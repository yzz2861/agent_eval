# frozen_string_literal: true

RSpec.describe Faraday::RequestOptions do
  subject(:options) { Faraday::RequestOptions.new }

  it 'allows to set the request proxy' do
    expect(options.proxy).to be_nil

    expect { options[:proxy] = { booya: 1 } }.to raise_error(NoMethodError)

    options[:proxy] = { user: 'user' }
    expect(options.proxy).to be_a_kind_of(Faraday::ProxyOptions)
    expect(options.proxy.user).to eq('user')

    options.proxy = nil
    expect(options.proxy).to be_nil
    expect(options.inspect).to eq('#<Faraday::RequestOptions (empty)>')
  end

  it 'defaults required_capabilities to an empty list' do
    expect(options.required_capabilities).to eq([])
  end

  it 'accumulates required capabilities without duplicates' do
    options.require_capabilities :streaming_responses
    options.require_capabilities Faraday::Adapter::TLS_CIPHERS, :streaming_responses

    expect(options.required_capabilities)
      .to eq([:streaming_responses, Faraday::Adapter::TLS_CIPHERS])
  end

  it 'coerces capabilities provided through the options hash to symbols' do
    built = Faraday::RequestOptions.from(required_capabilities: %w[parallel])
    expect(built.required_capabilities).to eq([:parallel])
  end
end
