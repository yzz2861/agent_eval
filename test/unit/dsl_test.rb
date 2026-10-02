# frozen_string_literal: true

require 'rubygems'
require 'minitest/autorun'
require 'rack/cors'

describe Rack::Cors, 'DSL' do
  it 'should support explicit config object dsl mode' do
    cors = Rack::Cors.new(proc {}) do |cfg|
      cfg.allow do |allow|
        allow.origins 'localhost:3000', '127.0.0.1:3000' do |source, env|
          source == 'http://10.10.10.10:3000' &&
            env['USER_AGENT'] == 'test-agent'
        end
        allow.resource '/get-only', methods: :get
        allow.resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    _(resources.length).must_equal 1
    _(resources.first.allow_origin?('http://localhost:3000')).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'test-agent' })).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3001', { 'USER_AGENT' => 'test-agent' })).wont_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'other-agent' })).wont_equal true
  end

  it 'should support implicit config object dsl mode' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'localhost:3000', '127.0.0.1:3000' do |source, env|
          source == 'http://10.10.10.10:3000' &&
            env['USER_AGENT'] == 'test-agent'
        end
        resource '/get-only', methods: :get
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    _(resources.length).must_equal 1
    _(resources.first.allow_origin?('http://localhost:3000')).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'test-agent' })).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3001', { 'USER_AGENT' => 'test-agent' })).wont_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'other-agent' })).wont_equal true
  end

  it 'should support "file://" origin' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'file://'
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    _(resources.first.allow_origin?('file://')).must_equal true
  end

  it 'should default credentials option to false' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'example.net'
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources
    _(resources.first.resources.first.credentials).must_equal false
  end

  it 'should return a structured origin result for block decisions' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins '*' do |source, _env|
          { credentials: true, max_age: 3600 } if source == 'https://admin.example.com'
        end
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    trusted = resources.first.match_origin('https://admin.example.com')
    _(trusted).wont_be_nil
    _(trusted.credentials).must_equal true
    _(trusted.max_age).must_equal 3600
    _(trusted.public_resource?).must_equal false

    other = resources.first.match_origin('https://other.example.com')
    _(other).wont_be_nil
    _(other.credentials).must_be_nil
    _(other.public_resource?).must_equal true

    _(resources.first.allow_origin?('https://admin.example.com')).must_equal true
    _(resources.first.allow_origin?('https://other.example.com')).must_equal true
  end

  it 'should keep specificity deterministic with strings and regexp' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins '*', 'https://exact.example.com', /\.specific\.com\z/
        resource '/'
      end
    end
    resources = cors.send :all_resources

    _(resources.first.match_origin('https://exact.example.com').public_resource?).must_equal false
    _(resources.first.match_origin('https://app.specific.com').public_resource?).must_equal false
    _(resources.first.match_origin('https://random.example.org').public_resource?).must_equal true
  end

  it 'should raise when credentials are enabled for a wildcard mixed with specific origins' do
    _(proc do
      Rack::Cors.new(proc {}) do
        allow do
          origins '*', 'https://admin.example.com'
          resource '/', credentials: true
        end
      end
    end).must_raise Rack::Cors::Resource::CorsMisconfigurationError
  end
end
