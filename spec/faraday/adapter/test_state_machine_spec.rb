# frozen_string_literal: true

RSpec.describe Faraday::Adapter::Test do
  describe 'stateful stubs' do
    let(:stubs) do
      described_class::Stubs.new do |stub|
        stub.get('/unrelated') { [200, {}, 'stateless'] }

        stub.state_machine(initial: :drafting) do |fsm|
          fsm.state :drafting do |state|
            state.post('/drafts') do |env, session|
              session[:draft_id] = env[:body]
              [201, { 'X-Draft-Id' => session[:draft_id] }, 'draft']
            end

            state.transition(:post, '/submit', :ready,
                            guard: ->(env) { env.request_headers['X-Draft-Id'] == 'token' }) do |_env, session|
              [202, {}, "submitted:#{session[:draft_id]}"]
            end

            # Same path as in :done, different response per stage.
            state.get('/status') { [200, {}, 'not-started'] }
          end

          fsm.state :ready do |state|
            state.transition(:get, '/status', :done) do |_env, session|
              [200, {}, "processing:#{session[:draft_id]}"]
            end
          end

          fsm.state :done do |state|
            state.get('/status') { [200, {}, 'done'] }
            state.get(%r{\A/drafts/(?<id>\w+)\z}) do |env, session|
              [200, {}, "draft:#{session[:draft_id]}:#{env[:method]}"]
            end
          end
        end
      end
    end

    let(:connection) do
      Faraday.new { |builder| builder.adapter :test, stubs }
    end

    def create_and_submit
      connection.post('/drafts', '42')
      connection.post('/submit') { |env| env.headers['X-Draft-Id'] = 'token' }
    end

    it 'runs the draft -> submit -> read workflow in order, carrying session values' do
      draft = connection.post('/drafts', '42')
      expect(draft.status).to eq(201)
      expect(draft.headers['X-Draft-Id']).to eq('42')

      submitted = connection.post('/submit') { |env| env.headers['X-Draft-Id'] = 'token' }
      expect(submitted.body).to eq('submitted:42')

      expect(connection.get('/status').body).to eq('processing:42')
      expect(connection.get('/status').body).to eq('done')
      expect(connection.get('/drafts/42').body).to eq('draft:42:get')
    end

    it 'returns different responses for the same URL at different stages' do
      expect(connection.get('/status').body).to eq('not-started')
      create_and_submit
      expect(connection.get('/status').body).to eq('processing:42')
      expect(connection.get('/status').body).to eq('done')
    end

    it 'keeps regular stateless stubs working regardless of machine state' do
      expect(connection.get('/unrelated').body).to eq('stateless')
      create_and_submit
      expect(connection.get('/unrelated').body).to eq('stateless')
    end

    it 'exposes regex match data through the session' do
      create_and_submit
      connection.get('/status') # move to :done
      response = connection.get('/drafts/42')
      expect(response.body).to eq('draft:42:get')
    end

    it 'yields match_data for regex state paths like regular stubs' do
      local_stubs = described_class::Stubs.new do |stub|
        stub.state_machine(initial: :idle) do |fsm|
          fsm.state(:idle) do |state|
            state.get(%r{\A/items/(\d+)\z}) do |_env, session|
              [200, {}, "item:#{session[:match_data][1]}"]
            end
          end
        end
      end
      local_conn = Faraday.new { |builder| builder.adapter :test, local_stubs }
      expect(local_conn.get('/items/7').body).to eq('item:7')
    end

    context 'when the workflow order is violated' do
      it 'raises SequenceError for an unmet transition guard without consuming it' do
        connection.post('/drafts', '42')

        expect { connection.post('/submit') }.to(
          raise_error(described_class::Stubs::SequenceError, /condition was not met/)
        )

        response = connection.post('/submit') { |env| env.headers['X-Draft-Id'] = 'token' }
        expect(response.body).to eq('submitted:42')
      end

      it 'raises SequenceError when reaching a later-stage route too early' do
        expect { connection.get('/drafts/42') }.to raise_error(
          described_class::Stubs::SequenceError,
          a_string_including('/drafts/42', ':drafting', ':done')
        )
      end

      it 'raises NotFound for a route unknown to every stub' do
        expect { connection.get('/nope') }.to(
          raise_error(described_class::Stubs::NotFound)
        )
      end
    end

    context 'when concurrent requests compete for a one-time transition' do
      it 'lets exactly one request win and raises SequenceError for the rest' do
        connection.post('/drafts', '42')

        gate = Queue.new
        threads = Array.new(8) do
          Thread.new do
            gate.pop
            begin
              connection.post('/submit') { |env| env.headers['X-Draft-Id'] = 'token' }
              :ok
            rescue described_class::Stubs::SequenceError
              :sequence_error
            end
          end
        end

        8.times { gate << :go }
        expect(threads.map(&:value).tally).to eq(ok: 1, sequence_error: 7)

        expect { connection.post('/submit') { |env| env.headers['X-Draft-Id'] = 'token' } }.to(
          raise_error(described_class::Stubs::SequenceError, /already been taken/)
        )
      end
    end

    describe '#verify_stubbed_calls' do
      it 'reports unconsumed transitions' do
        expect { stubs.verify_stubbed_calls }.to raise_error(
          RuntimeError, a_string_including('/submit', 'transition to :ready')
        )
      end
    end

    describe 'machine definition validation' do
      it 'raises when the initial state is not declared' do
        expect do
          described_class::Stubs.new do |stub|
            stub.state_machine(initial: :missing) do |fsm|
              fsm.state(:present) { |state| state.get('/x') { [200, {}, ''] } }
            end
          end
        end.to raise_error(ArgumentError, /unknown initial state :missing/)
      end

      it 'raises when a transition targets an unknown state' do
        expect do
          described_class::Stubs.new do |stub|
            stub.state_machine(initial: :a) do |fsm|
              fsm.state(:a) { |state| state.transition(:get, '/x', :b) { [200, {}, ''] } }
            end
          end
        end.to raise_error(ArgumentError, /targets unknown state :b/)
      end
    end

    describe '#reset' do
      it 'returns the machine to its initial state and clears the session' do
        machine = stubs.instance_variable_get(:@state_machines).first
        create_and_submit
        expect(connection.get('/status').body).to eq('processing:42')

        machine.reset
        expect(connection.get('/status').body).to eq('not-started')
      end
    end
  end
end
