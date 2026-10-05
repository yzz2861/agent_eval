# frozen_string_literal: true

RSpec.describe Faraday::Adapter::Test do
  let(:stubs) do
    described_class::Stubs.new do |stub|
      stub.get('http://domain.test/hello') do
        [200, { 'Content-Type' => 'text/html' }, 'domain: hello']
      end

      stub.get('http://wrong.test/hello') do
        [200, { 'Content-Type' => 'text/html' }, 'wrong: hello']
      end

      stub.get('http://wrong.test/bait') do
        [404, { 'Content-Type' => 'text/html' }]
      end

      stub.get('/hello') do
        [200, { 'Content-Type' => 'text/html' }, 'hello']
      end

      stub.get('/method-echo') do |env|
        [200, { 'Content-Type' => 'text/html' }, env[:method].to_s]
      end

      stub.get(%r{\A/resources/\d+(?:\?|\z)}) do
        [200, { 'Content-Type' => 'text/html' }, 'show']
      end

      stub.get(%r{\A/resources/(specified)\z}) do |_env, meta|
        [200, { 'Content-Type' => 'text/html' }, "show #{meta[:match_data][1]}"]
      end
    end
  end

  let(:connection) do
    Faraday.new do |builder|
      builder.adapter :test, stubs
    end
  end

  let(:response) { connection.get('/hello') }

  context 'with simple path sets status' do
    subject { response.status }

    it { is_expected.to eq 200 }
  end

  context 'with simple path sets headers' do
    subject { response.headers['Content-Type'] }

    it { is_expected.to eq 'text/html' }
  end

  context 'with simple path sets body' do
    subject { response.body }

    it { is_expected.to eq 'hello' }
  end

  context 'with host points to the right stub' do
    subject { connection.get('http://domain.test/hello').body }

    it { is_expected.to eq 'domain: hello' }
  end

  describe 'can be called several times' do
    subject { connection.get('/hello').body }

    it { is_expected.to eq 'hello' }
  end

  describe 'can handle regular expression path' do
    subject { connection.get('/resources/1').body }

    it { is_expected.to eq 'show' }
  end

  describe 'can handle single parameter block' do
    subject { connection.get('/method-echo').body }

    it { is_expected.to eq 'get' }
  end

  describe 'can handle regular expression path with captured result' do
    subject { connection.get('/resources/specified').body }

    it { is_expected.to eq 'show specified' }
  end

  context 'with get params' do
    subject { connection.get('/param?a=1').body }

    before do
      stubs.get('/param?a=1') { [200, {}, 'a'] }
    end

    it { is_expected.to eq 'a' }
  end

  describe 'ignoring unspecified get params' do
    before do
      stubs.get('/optional?a=1') { [200, {}, 'a'] }
    end

    context 'with multiple params' do
      subject { connection.get('/optional?a=1&b=1').body }

      it { is_expected.to eq 'a' }
    end

    context 'with single param' do
      subject { connection.get('/optional?a=1').body }

      it { is_expected.to eq 'a' }
    end

    context 'without params' do
      subject(:request) { connection.get('/optional') }

      it do
        expect { request }.to raise_error(
          Faraday::Adapter::Test::Stubs::NotFound
        )
      end
    end
  end

  context 'with http headers' do
    before do
      stubs.get('/yo', 'X-HELLO' => 'hello') { [200, {}, 'a'] }
      stubs.get('/yo') { [200, {}, 'b'] }
    end

    context 'with header' do
      subject do
        connection.get('/yo') { |env| env.headers['X-HELLO'] = 'hello' }.body
      end

      it { is_expected.to eq 'a' }
    end

    context 'without header' do
      subject do
        connection.get('/yo').body
      end

      it { is_expected.to eq 'b' }
    end
  end

  describe 'different outcomes for the same request' do
    def make_request
      connection.get('/foo')
    end

    subject(:request) { make_request.body }

    before do
      stubs.get('/foo') { [200, { 'Content-Type' => 'text/html' }, 'hello'] }
      stubs.get('/foo') { [200, { 'Content-Type' => 'text/html' }, 'world'] }
    end

    context 'the first request' do
      it { is_expected.to eq 'hello' }
    end

    context 'the second request' do
      before do
        make_request
      end

      it { is_expected.to eq 'world' }
    end
  end

  describe 'yielding env to stubs' do
    subject { connection.get('http://foo.com/foo?a=1').body }

    before do
      stubs.get '/foo' do |env|
        expect(env[:url].path).to eq '/foo'
        expect(env[:url].host).to eq 'foo.com'
        expect(env[:params]['a']).to eq '1'
        expect(env[:request_headers]['Accept']).to eq 'text/plain'
        [200, {}, 'a']
      end

      connection.headers['Accept'] = 'text/plain'
    end

    it { is_expected.to eq 'a' }
  end

  describe 'params parsing' do
    subject { connection.get('http://foo.com/foo?a[b]=1').body }

    context 'with default encoder' do
      before do
        stubs.get '/foo' do |env|
          expect(env[:params]['a']['b']).to eq '1'
          [200, {}, 'a']
        end
      end

      it { is_expected.to eq 'a' }
    end

    context 'with nested encoder' do
      before do
        stubs.get '/foo' do |env|
          expect(env[:params]['a']['b']).to eq '1'
          [200, {}, 'a']
        end

        connection.options.params_encoder = Faraday::NestedParamsEncoder
      end

      it { is_expected.to eq 'a' }
    end

    context 'with flat encoder' do
      before do
        stubs.get '/foo' do |env|
          expect(env[:params]['a[b]']).to eq '1'
          [200, {}, 'a']
        end

        connection.options.params_encoder = Faraday::FlatParamsEncoder
      end

      it { is_expected.to eq 'a' }
    end
  end

  describe 'raising an error if no stub was found' do
    describe 'for request' do
      subject(:request) { connection.get('/invalid') { [200, {}, []] } }

      it { expect { request }.to raise_error described_class::Stubs::NotFound }
    end

    describe 'for specified host' do
      subject(:request) { connection.get('http://domain.test/bait') }

      it { expect { request }.to raise_error described_class::Stubs::NotFound }
    end

    describe 'for request without specified header' do
      subject(:request) { connection.get('/yo') }

      before do
        stubs.get('/yo', 'X-HELLO' => 'hello') { [200, {}, 'a'] }
      end

      it { expect { request }.to raise_error described_class::Stubs::NotFound }
    end
  end

  describe 'for request with non default params encoder' do
    let(:connection) do
      Faraday.new(request: { params_encoder: Faraday::FlatParamsEncoder }) do |builder|
        builder.adapter :test, stubs
      end
    end
    let(:stubs) do
      described_class::Stubs.new do |stubs|
        stubs.get('/path?a=x&a=y&a=z') { [200, {}, 'a'] }
      end
    end

    context 'when all flat param values are correctly set' do
      subject(:request) { connection.get('/path?a=x&a=y&a=z') }

      it { expect(request.status).to eq 200 }
    end

    shared_examples 'raise NotFound when params do not satisfy the flat param values' do |params|
      subject(:request) { connection.get('/path', params) }

      context "with #{params.inspect}" do
        it { expect { request }.to raise_error described_class::Stubs::NotFound }
      end
    end

    it_behaves_like 'raise NotFound when params do not satisfy the flat param values', { a: %w[x] }
    it_behaves_like 'raise NotFound when params do not satisfy the flat param values', { a: %w[x y] }
    it_behaves_like 'raise NotFound when params do not satisfy the flat param values', { a: %w[x z y] } # NOTE: The order of the value is also compared.
    it_behaves_like 'raise NotFound when params do not satisfy the flat param values', { b: %w[x y z] }
  end

  describe 'strict_mode' do
    let(:stubs) do
      described_class::Stubs.new(strict_mode: true) do |stubs|
        stubs.get('/strict?a=12&b=xy', 'Authorization' => 'Bearer m_ck', 'X-C' => 'hello') { [200, {}, 'a'] }
        stubs.get('/with_user_agent?a=12&b=xy', authorization: 'Bearer m_ck', 'User-Agent' => 'My Agent') { [200, {}, 'a'] }
      end
    end

    context 'when params and headers are exactly set' do
      subject(:request) { connection.get('/strict', { a: '12', b: 'xy' }, { authorization: 'Bearer m_ck', x_c: 'hello' }) }

      it { expect(request.status).to eq 200 }
    end

    context 'when params and headers are exactly set with a custom user agent' do
      subject(:request) { connection.get('/with_user_agent', { a: '12', b: 'xy' }, { authorization: 'Bearer m_ck', 'User-Agent' => 'My Agent' }) }

      it { expect(request.status).to eq 200 }
    end

    shared_examples 'raise NotFound when params do not satisfy the strict check' do |params|
      subject(:request) { connection.get('/strict', params, { 'Authorization' => 'Bearer m_ck', 'X-C' => 'hello' }) }

      context "with #{params.inspect}" do
        it { expect { request }.to raise_error described_class::Stubs::NotFound }
      end
    end

    it_behaves_like 'raise NotFound when params do not satisfy the strict check', { a: '12' }
    it_behaves_like 'raise NotFound when params do not satisfy the strict check', { b: 'xy' }
    it_behaves_like 'raise NotFound when params do not satisfy the strict check', { a: '123', b: 'xy' }
    it_behaves_like 'raise NotFound when params do not satisfy the strict check', { a: '12', b: 'xyz' }
    it_behaves_like 'raise NotFound when params do not satisfy the strict check', { a: '12', b: 'xy', c: 'hello' }
    it_behaves_like 'raise NotFound when params do not satisfy the strict check', { additional: 'special', a: '12', b: 'xy', c: 'hello' }

    shared_examples 'raise NotFound when headers do not satisfy the strict check' do |path, headers|
      subject(:request) { connection.get(path, { a: 12, b: 'xy' }, headers) }

      context "with #{headers.inspect}" do
        it { expect { request }.to raise_error described_class::Stubs::NotFound }
      end
    end

    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/strict', { authorization: 'Bearer m_ck' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/strict', { 'X-C' => 'hello' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/strict', { authorization: 'Bearer m_ck', 'x-c': 'Hi' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/strict', { authorization: 'Basic m_ck', 'x-c': 'hello' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/strict', { authorization: 'Bearer m_ck', 'x-c': 'hello', x_special: 'special' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/with_user_agent', { authorization: 'Bearer m_ck' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/with_user_agent', { authorization: 'Bearer m_ck', user_agent: 'Unknown' }
    it_behaves_like 'raise NotFound when headers do not satisfy the strict check', '/with_user_agent', { authorization: 'Bearer m_ck', user_agent: 'My Agent', x_special: 'special' }

    context 'when strict_mode is disabled' do
      before do
        stubs.strict_mode = false
      end

      shared_examples 'does not raise NotFound even when params do not satisfy the strict check' do |params|
        subject(:request) { connection.get('/strict', params, { 'Authorization' => 'Bearer m_ck', 'X-C' => 'hello' }) }

        context "with #{params.inspect}" do
          it { expect(request.status).to eq 200 }
        end
      end

      it_behaves_like 'does not raise NotFound even when params do not satisfy the strict check', { a: '12', b: 'xy' }
      it_behaves_like 'does not raise NotFound even when params do not satisfy the strict check', { a: '12', b: 'xy', c: 'hello' }
      it_behaves_like 'does not raise NotFound even when params do not satisfy the strict check', { additional: 'special', a: '12', b: 'xy', c: 'hello' }

      shared_examples 'does not raise NotFound even when headers do not satisfy the strict check' do |path, headers|
        subject(:request) { connection.get(path, { a: 12, b: 'xy' }, headers) }

        context "with #{headers.inspect}" do
          it { expect(request.status).to eq 200 }
        end
      end

      it_behaves_like 'does not raise NotFound even when headers do not satisfy the strict check', '/strict', { authorization: 'Bearer m_ck', 'x-c': 'hello' }
      it_behaves_like 'does not raise NotFound even when headers do not satisfy the strict check', '/strict', { authorization: 'Bearer m_ck', 'x-c': 'hello', x_special: 'special' }
      it_behaves_like 'does not raise NotFound even when headers do not satisfy the strict check', '/strict', { authorization: 'Bearer m_ck', 'x-c': 'hello', user_agent: 'Special Agent' }
      it_behaves_like 'does not raise NotFound even when headers do not satisfy the strict check', '/with_user_agent', { authorization: 'Bearer m_ck', user_agent: 'My Agent' }
      it_behaves_like 'does not raise NotFound even when headers do not satisfy the strict check', '/with_user_agent', { authorization: 'Bearer m_ck', user_agent: 'My Agent', x_special: 'special' }
    end

    describe 'body_match?' do
      let(:stubs) do
        described_class::Stubs.new do |stubs|
          stubs.post('/no_check') { [200, {}, 'ok'] }
          stubs.post('/with_string', 'abc') { [200, {}, 'ok'] }
          stubs.post(
            '/with_proc',
            ->(request_body) { JSON.parse(request_body, symbolize_names: true) == { x: '!', a: [{ m: [{ a: true }], n: 123 }] } },
            { content_type: 'application/json' }
          ) do
            [200, {}, 'ok']
          end
        end
      end

      context 'when trying without any args for body' do
        subject(:without_body) { connection.post('/no_check') }

        it { expect(without_body.status).to eq 200 }
      end

      context 'when trying with string body stubs' do
        subject(:with_string) { connection.post('/with_string', 'abc') }

        it { expect(with_string.status).to eq 200 }
      end

      context 'when trying with proc body stubs' do
        subject(:with_proc) do
          connection.post('/with_proc', JSON.dump(a: [{ n: 123, m: [{ a: true }] }], x: '!'), { 'Content-Type' => 'application/json' })
        end

        it { expect(with_proc.status).to eq 200 }
      end
    end
  end

  describe 'request timeout' do
    subject(:request) do
      connection.get('/sleep') do |req|
        req.options.timeout = timeout
      end
    end

    before do
      stubs.get('/sleep') do
        sleep(0.01)
        [200, {}, '']
      end
    end

    context 'when request is within timeout' do
      let(:timeout) { 1 }

      it { expect(request.status).to eq 200 }
    end

    context 'when request is too slow' do
      let(:timeout) { 0.001 }

      it 'raises an exception' do
        expect { request }.to raise_error(Faraday::TimeoutError)
      end
    end
  end

  describe 'stateful stubs' do
    let(:stateful_stubs) { described_class::Stubs.new }
    let(:stateful_connection) do
      Faraday.new { |builder| builder.adapter(:test, stateful_stubs) }
    end

    it 'matches the same path differently according to the current state' do
      stateful_stubs.state(:draft) do |state|
        state.post('/workflow', transition: :submitted) do
          [201, {}, 'draft created']
        end

        state.get('/workflow') { [409, {}, 'draft is not submitted'] }
      end

      stateful_stubs.state(:submitted) do |state|
        state.post('/workflow', transition: :ready) do
          [202, {}, 'submitted']
        end

        state.get('/workflow') { [409, {}, 'result is not ready'] }
      end

      stateful_stubs.state(:ready) do |state|
        state.get('/workflow') { [200, {}, 'ready'] }
      end

      expect(stateful_connection.get('/workflow').status).to eq(409)
      expect(stateful_connection.post('/workflow').status).to eq(201)
      expect(stateful_stubs.current_state).to eq(:submitted)
      expect(stateful_connection.get('/workflow').status).to eq(409)
      expect(stateful_connection.post('/workflow').status).to eq(202)
      expect(stateful_stubs.current_state).to eq(:ready)
      expect(stateful_connection.get('/workflow').body).to eq('ready')
    end

    it 'passes values generated by a transition to later states' do
      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: :submitted) do |env, context|
          document_id = JSON.parse(env.body).fetch('id')
          context.set(:document_id, document_id)
          [201, {}, '']
        end
      end

      stateful_stubs.state(:submitted) do |state|
        state.post('/documents/submit', transition: :ready) do |_env, context|
          context.set(:result, "result-#{context.fetch(:document_id)}")
          [202, {}, '']
        end
      end

      stateful_stubs.state(:ready) do |state|
        state.get('/documents/result') do |_env, context|
          [200, {}, context.fetch(:result)]
        end
      end

      stateful_connection.post('/documents', JSON.dump(id: 42))
      stateful_connection.post('/documents/submit')

      expect(stateful_connection.get('/documents/result').body).to eq('result-42')
    end

    it 'lets a transition choose its target from the request' do
      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: true) do |env, context|
          payload = JSON.parse(env.body)
          context.transition_to(payload.fetch('ready') ? :ready : :submitted, reviewed: false)
          [202, {}, '']
        end
      end

      stateful_stubs.state(:submitted) do |state|
        state.get('/documents') { [200, {}, 'submitted'] }
      end

      stateful_stubs.state(:ready) do |state|
        state.get('/documents') { [200, {}, 'ready'] }
      end

      stateful_connection.post('/documents', JSON.dump(ready: true))

      expect(stateful_connection.get('/documents').body).to eq('ready')
      expect(stateful_stubs.current_state).to eq(:ready)
    end

    it 'raises a clear error when a request is made in the wrong state' do
      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: :submitted) { [201, {}, ''] }
      end

      stateful_stubs.state(:submitted) do |state|
        state.get('/documents/1/result') { [200, {}, 'ready'] }
      end

      expect { stateful_connection.get('/documents/1/result') }
        .to raise_error(
          described_class::Stubs::InvalidStateTransition,
          %r{GET .*documents/1/result.*current state :draft.*:submitted}
        )
    end

    it 'rolls back a one-time transition when its response block fails' do
      attempts = 0

      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: :submitted) do
          attempts += 1
          raise Faraday::ConnectionFailed, 'temporary failure' if attempts == 1

          [201, {}, '']
        end
      end

      stateful_stubs.state(:submitted) do |state|
        state.get('/documents') { [200, {}, 'submitted'] }
      end

      expect { stateful_connection.post('/documents') }
        .to raise_error(Faraday::ConnectionFailed, 'temporary failure')
      expect(stateful_stubs.current_state).to eq(:draft)
      expect(stateful_connection.post('/documents').status).to eq(201)
      expect(stateful_stubs.current_state).to eq(:submitted)
    end

    it 'releases a dynamic transition that never chooses a target' do
      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: true) do
          [201, {}, '']
        end
      end

      expect { stateful_connection.post('/documents') }
        .to raise_error(described_class::Stubs::InvalidStateTransition, /target state/)
      expect(stateful_stubs.current_state).to eq(:draft)
    end

    it 'allows only one in-flight request to consume a one-time transition' do
      entered_transition = Queue.new
      release_transition = Queue.new
      failures = Queue.new

      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: :submitted) do
          entered_transition << true
          release_transition.pop
          [201, {}, '']
        end
      end

      stateful_stubs.state(:submitted) do |state|
        state.get('/documents') { [200, {}, 'submitted'] }
      end

      winner = Thread.new do
        stateful_connection.post('/documents')
      rescue StandardError => error
        failures << error
      end

      entered_transition.pop

      loser = Thread.new do
        stateful_connection.post('/documents')
      rescue StandardError => error
        failures << error
      end

      error = failures.pop
      release_transition << true
      winner.join
      loser.join

      expect(error).to be_a(described_class::Stubs::TransitionInProgress)
      expect(error.message).to include('one-time transition', 'already in progress')
      expect(stateful_stubs.current_state).to eq(:submitted)
    end

    it 'reports an order error when a competing request arrives immediately after the transition' do
      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: :submitted) { [201, {}, ''] }
      end

      stateful_stubs.state(:submitted) do |state|
        state.get('/documents') { [200, {}, 'submitted'] }
      end

      start = Queue.new
      results = 8.times.map do
        Thread.new do
          start.pop
          begin
            stateful_connection.post('/documents').status
          rescue described_class::Stubs::InvalidStateTransition
            :blocked
          end
        end
      end

      8.times { start << 1 }
      statuses = results.map(&:value).tally

      expect(statuses).to eq(201 => 1, :blocked => 7)
      expect(stateful_stubs.current_state).to eq(:submitted)
    end

    it 'keeps regular stateless stubs independent of the current state' do
      stateful_stubs.state(:draft) do |state|
        state.post('/documents', transition: :submitted) { [201, {}, ''] }
      end

      stateful_stubs.state(:submitted) do |state|
        state.get('/documents') { [200, {}, 'ready'] }
      end

      stateful_stubs.get('/health') { [200, {}, 'ok'] }

      expect(stateful_connection.get('/health').body).to eq('ok')
      expect(stateful_connection.get('/health').body).to eq('ok')
      expect(stateful_stubs.current_state).to eq(:draft)
    end
  end

  describe '#clear' do
    it 'removes pending stubs' do
      stubs.clear
      expect { connection.get('/hello') }.to raise_error(described_class::Stubs::NotFound)
    end

    it 'removes already consumed stubs' do
      expect(connection.get('/hello').body).to eq('hello')
      stubs.clear
      expect { connection.get('/hello') }.to raise_error(described_class::Stubs::NotFound)
    end

    it 'leaves the stubs empty' do
      stubs.clear
      expect(stubs).to be_empty
    end
  end
end
