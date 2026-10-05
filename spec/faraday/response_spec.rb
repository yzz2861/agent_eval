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

    it 'is not observers_processed before finish' do
      expect(subject.observers_processed?).to be_falsey
    end

    it 'is observers_processed after finish' do
      subject.finish(env)
      expect(subject.observers_processed?).to be_truthy
    end

    it 'runs observers in registration order' do
      order = []
      subject.on_complete { order << :first }
      subject.on_complete { order << :second }
      subject.finish(env)

      expect(order).to eq(%i[first second])
    end

    it 'runs observers registered from within an observer, in registration order' do
      order = []
      subject.on_complete do
        order << :first
        subject.on_complete { order << :third }
      end
      subject.on_complete { order << :second }
      subject.finish(env)

      expect(order).to eq(%i[first second third])
      expect(subject.observers_processed?).to be_truthy
    end

    it 'runs late-registered observers immediately after observers are processed' do
      order = []
      subject.on_complete { order << :early }
      subject.finish(env)
      subject.on_complete { order << :late }

      expect(order).to eq(%i[early late])
    end

    it 'keeps running remaining observers when one raises' do
      order = []
      subject.on_complete { order << :first }
      subject.on_complete { raise 'boom' }
      subject.on_complete { order << :third }

      expect { subject.finish(env) }.to raise_error('boom')
      expect(order).to eq(%i[first third])
      expect(subject.observers_processed?).to be_truthy
    end

    it 'records observer errors without changing status and body' do
      error = RuntimeError.new('boom')
      subject.on_complete { raise error }

      expect { subject.finish(env) }.to raise_error(error)
      expect(subject.completion_errors).to eq([error])
      expect(subject.status).to eq(404)
      expect(subject.body).to eq('yikes')
    end

    it 're-raises errors from late-registered observers by default' do
      subject.finish(env)

      expect { subject.on_complete { raise 'boom' } }.to raise_error('boom')
      expect(subject.completion_errors.size).to eq(1)
    end

    context 'with a custom completion_error_handler' do
      around do |example|
        original = Faraday::Response.completion_error_handler
        example.run
        Faraday::Response.completion_error_handler = original
      end

      it 'forwards observer errors to the configured handler' do
        collected = []
        Faraday::Response.completion_error_handler = ->(error, response) { collected << [error, response] }

        error = RuntimeError.new('boom')
        subject.on_complete { raise error }

        expect { subject.finish(env) }.not_to raise_error
        expect(collected).to eq([[error, subject]])
        expect(subject.completion_errors).to eq([error])
        expect(subject.status).to eq(404)
        expect(subject.body).to eq('yikes')
      end

      it 'hands errors from late-registered observers to the handler' do
        collected = []
        Faraday::Response.completion_error_handler = ->(error, response) { collected << [error, response] }

        subject.finish(env)
        expect { subject.on_complete { raise 'boom' } }.not_to raise_error
        expect(collected.size).to eq(1)
        expect(collected.first[1]).to eq(subject)
      end
    end
  end
end
