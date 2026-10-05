# frozen_string_literal: true

RSpec.describe Faraday::Response do
  subject { Faraday::Response.new(env) }

  let(:env) do
    Faraday::Env.from(status: 404, body: 'yikes', url: Faraday::Utils.URI('https://lostisland.github.io/faraday'),
                      response_headers: { 'Content-Type' => 'text/plain' })
  end

  it { expect(subject.finished?).to be_truthy }
  it { expect { subject.finish({}) }.to raise_error(RuntimeError) }
  it { expect(subject.success?).to be_falsey }
  it { expect(subject.status).to eq(404) }
  it { expect(subject.body).to eq('yikes') }
  it { expect(subject.url).to eq(URI('https://lostisland.github.io/faraday')) }
  it { expect(subject.headers['Content-Type']).to eq('text/plain') }
  it { expect(subject['content-type']).to eq('text/plain') }

  it 'accepts a response hash and an error collector as keyword arguments' do
    collector = []
    completed = described_class.new(
      status: 200,
      response_headers: { 'X' => 'y' },
      response_body: 'ok',
      error_collector: collector
    )

    expect(completed.status).to eq(200)
    expect(completed.body).to eq('ok')
    expect(completed.error_collector).to equal(collector)
  end

  describe '#apply_request' do
    before { subject.apply_request(body: 'a=b', method: :post) }

    it { expect(subject.body).to eq('yikes') }
    it { expect(subject.env[:method]).to eq(:post) }
  end

  describe '#to_hash' do
    let(:hash) { subject.to_hash }

    it { expect(hash).to be_a(Hash) }
    it { expect(hash[:status]).to eq(subject.status) }
    it { expect(hash[:response_headers]).to eq(subject.headers) }
    it { expect(hash[:body]).to eq(subject.body) }
    it { expect(hash[:url]).to eq(subject.env.url) }

    context 'when response is not finished' do
      subject { Faraday::Response.new.to_hash }

      it { is_expected.to eq({ status: nil, body: nil, response_headers: {}, url: nil }) }
    end
  end

  describe 'marshal serialization support' do
    subject { Faraday::Response.new }
    let(:loaded) { Marshal.load(Marshal.dump(subject)) }

    before do
      subject.on_complete {}
      subject.finish(env.merge(params: 'moo'))
    end

    it { expect(loaded.env[:params]).to be_nil }
    it { expect(loaded.env[:body]).to eq(env[:body]) }
    it { expect(loaded.env[:response_headers]).to eq(env[:response_headers]) }
    it { expect(loaded.env[:status]).to eq(env[:status]) }
    it { expect(loaded.env[:url]).to eq(env[:url]) }
  end

  describe '#on_complete' do
    subject { Faraday::Response.new }

    it 'parse body on finish' do
      subject.on_complete { |env| env[:body] = env[:body].upcase }
      subject.finish(env)

      expect(subject.body).to eq('YIKES')
    end

    it 'can access response body in on_complete callback' do
      subject.on_complete { |env| env[:body] = subject.body.upcase }
      subject.finish(env)

      expect(subject.body).to eq('YIKES')
    end

    it 'can access response body in on_complete callback' do
      callback_env = nil
      subject.on_complete { |env| callback_env = env }
      subject.finish({})

      expect(subject.env).to eq(callback_env)
    end
  end

  describe '#on_finish' do
    subject(:response) { described_class.new }

    let(:events) { [] }

    it 'distinguishes finalization from observer processing' do
      observed_finished = nil
      observed_processed = nil

      response.on_finish do
        observed_finished = response.finished?
        observed_processed = response.completion_observers_processed?
      end

      response.finish(env)

      expect(observed_finished).to be(true)
      expect(observed_processed).to be(false)
      expect(response).to be_completion_observers_processed
    end

    it 'runs pre-registered observers after on_complete callbacks in FIFO order' do
      response.on_complete do
        events << :complete
        response.on_finish { events << :registered_from_complete }
      end
      response.on_finish do
        events << :first
        response.on_finish { events << :registered_from_first }
      end
      response.on_finish { events << :second }

      response.finish(env)

      expect(events).to eq(%i[
        complete
        first
        second
        registered_from_complete
        registered_from_first
      ])
    end

    it 'continues processing observers when one raises' do
      first_error = RuntimeError.new('first')
      second_error = RuntimeError.new('second')

      response.on_finish { raise first_error }
      response.on_finish { events << :second }
      response.on_finish { raise second_error }

      returned_response = response.finish(env)

      expect(returned_response).to be(response)
      expect(events).to eq([:second])
      expect(response.error_collector.errors).to eq([first_error, second_error])
      expect(response.status).to eq(404)
      expect(response.body).to eq('yikes')
    end

    it 'passes the error and response to a configured callable collector' do
      collected = []
      collector = lambda { |error, completed_response|
        collected << [error, completed_response]
      }
      error = RuntimeError.new('boom')
      local_response = described_class.new(error_collector: collector)
      local_response.on_finish { raise error }

      local_response.finish(env)

      expect(collected).to eq([[error, local_response]])
      expect(local_response.status).to eq(404)
      expect(local_response.body).to eq('yikes')
    end

    it 'supports an array-like error collector' do
      errors = []
      local_response = described_class.new(error_collector: errors)
      error = RuntimeError.new('boom')
      local_response.on_finish { raise error }

      local_response.finish(env)

      expect(errors).to eq([error])
    end

    it 'supports a positional error collector for compatibility' do
      errors = []
      local_response = described_class.new(nil, errors)
      local_response.on_finish { raise RuntimeError.new('boom') }

      local_response.finish(env)

      expect(errors.map(&:message)).to eq(['boom'])
    end

    it 'keeps running observers when the error collector fails' do
      observer_error = RuntimeError.new('observer')
      collector = proc { raise 'collector failure' }
      local_response = described_class.new(error_collector: collector)
      local_response.on_finish { raise observer_error }
      local_response.on_finish { events << :second }

      expect { local_response.finish(env) }
        .to raise_error(RuntimeError, 'collector failure')
      expect(events).to eq([:second])
      expect(local_response.status).to eq(404)
      expect(local_response.body).to eq('yikes')
    end

    it 'runs observers registered after completion immediately' do
      response.finish(env)

      response.on_finish do |completed_env|
        events << [completed_env.status, response.completion_observers_processed?]
      end

      expect(events).to eq([[404, false]])
      expect(response).to be_completion_observers_processed
    end

    it 'finishes a response only once while still collecting late observer errors' do
      response.finish(env)
      error = RuntimeError.new('late')
      response.on_finish { raise error }

      expect { response.finish(env) }.to raise_error(RuntimeError, 'response already finished')
      expect(response.error_collector.errors).to eq([error])
    end

    it 'preserves the response when a late observer raises' do
      response.finish(env)
      response.on_finish { |completed_env| completed_env.body = 'changed'; raise 'boom' }

      expect(response.body).to eq('yikes')
    end

    it 'gives observers a frozen environment copy' do
      observed_env = nil
      response.on_finish { |completed_env| observed_env = completed_env }

      response.finish(env)

      expect(observed_env).not_to equal(response.env)
      expect(observed_env).to be_frozen
      expect(observed_env.response).to be_frozen
      expect(observed_env.response_headers).to be_frozen
      expect { observed_env.body = 'changed' }.to raise_error(FrozenError)
    end

    it 'freezes nested request data and custom members' do
      completed_env = env.dup
      completed_env.request = { timeout: 5, context: { id: 'request' } }
      completed_env.ssl = { verify: true, ca_file: 'ca.pem' }
      completed_env.request_headers = { 'X-Request' => 'sent' }
      completed_env.params = { page: '1' }
      completed_env[:custom] = { nested: { value: 'custom' } }
      observed_env = nil
      response.on_finish { |environment| observed_env = environment }

      response.finish(completed_env)

      expect(observed_env.request).to be_frozen
      expect(observed_env.request.context[:id]).to eq('request')
      expect(observed_env.request.context).to be_frozen
      expect(observed_env.ssl).to be_frozen
      expect(observed_env.request_headers).to be_frozen
      expect(observed_env.params).to be_frozen
      expect(observed_env[:custom][:nested]).to be_frozen
      expect(completed_env.request).not_to be_frozen
    end

    it 'processes queued observers during asynchronous completion' do
      mutex = Mutex.new
      condition = ConditionVariable.new
      state = :waiting
      response.on_finish do
        mutex.synchronize do
          state = :ready
          condition.broadcast
          condition.wait(mutex) while state == :ready
        end
        events << :first
      end

      thread = Thread.new { response.finish(env) }
      mutex.synchronize do
        condition.wait(mutex) until state == :ready
      end
      expect(response).to be_finished
      expect(response).not_to be_completion_observers_processed

      response.on_finish { events << :queued_late }
      mutex.synchronize do
        state = :continue
        condition.broadcast
      end
      expect(response.wait_for_completion_observers(1)).to be(response)
      thread.join

      expect(events).to eq(%i[first queued_late])
      expect(response).to be_completion_observers_processed
    end

    it 'does not snapshot an environment without observers' do
      environment = env
      response.finish(environment)

      expect(response.env).to equal(environment)
    end

    it 'returns nil when waiting times out before the response finishes' do
      expect(response.wait_for_completion_observers(0.01)).to be_nil
    end

    it 'uses the configured global error collector' do
      collected = []
      original = described_class.default_error_collector
      described_class.default_error_collector = collected
      local_response = described_class.new
      error = RuntimeError.new('global')
      local_response.on_finish { raise error }

      local_response.finish(env)

      expect(collected).to eq([error])
    ensure
      described_class.default_error_collector = original
    end

    it 'still raises legacy on_complete errors after observers are processed' do
      response.on_finish { events << :observer }
      response.on_complete { raise 'middleware failure' }

      expect { response.finish(env) }.to raise_error(RuntimeError, 'middleware failure')
      expect(events).to eq([:observer])
    end
  end
end
