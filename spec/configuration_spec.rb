# frozen_string_literal: true

require_relative "spec_helper"

describe Rack::Attack::Configuration do
  subject { Rack::Attack::Configuration.new }

  describe 'attributes' do
    it 'exposes the safelists attribute' do
      _(subject.safelists).must_equal({})
    end

    it 'exposes the blocklists attribute' do
      _(subject.blocklists).must_equal({})
    end

    it 'exposes the throttles attribute' do
      _(subject.throttles).must_equal({})
    end

    it 'exposes the tracks attribute' do
      _(subject.tracks).must_equal({})
    end

    it 'exposes the anonymous_blocklists attribute' do
      _(subject.anonymous_blocklists).must_equal([])
    end

    it 'exposes the anonymous_safelists attribute' do
      _(subject.anonymous_safelists).must_equal([])
    end

    it 'exposes a default store-unavailable responder' do
      response = subject.store_unavailable_responder.call(nil)

      _(response[0]).must_equal 503
    end

    it 'allows customizing the store-unavailable responder' do
      responder = ->(_req) { [503, {}, ['down']] }
      subject.store_unavailable_responder = responder

      _(subject.store_unavailable_responder).must_equal responder
    end
  end
end
