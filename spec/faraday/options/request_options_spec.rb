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

  describe '#stream_response?' do
    it 'accepts Proc and other callable on_data handlers' do
      expect(options.stream_response?).to be(false)

      options.on_data = proc {}
      expect(options.stream_response?).to be(true)

      options.on_data = Faraday::EventStream::Decoder.new {}
      expect(options.stream_response?).to be(true)
    end
  end
end
