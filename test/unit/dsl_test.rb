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

  it 'should support structured origin rules with per-origin credentials and max_age' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins '*',
                { 'admin.example.com' => { credentials: true, max_age: 600 } }
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    trusted = resources.first.match_origin('http://admin.example.com')
    _(trusted.wildcard?).must_equal false
    _(trusted.credentials).must_equal true
    _(trusted.max_age).must_equal 600

    other = resources.first.match_origin('http://anything.else')
    _(other.wildcard?).must_equal true
    _(other.credentials).must_be_nil
    _(other.max_age).must_be_nil

    _(resources.first.allow_origin?('http://admin.example.com')).must_equal true
    _(resources.first.allow_origin?('http://anything.else')).must_equal true
  end

  it 'should let specific rules win over a wildcard declared first' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins '*',
                %r{^https://(.*)\.example\.com$},
                { 'https://admin.example.com' => { credentials: true } }
        resource '/'
      end
    end
    resources = cors.send :all_resources

    exact = resources.first.match_origin('https://admin.example.com')
    _(exact.wildcard?).must_equal false
    _(exact.credentials).must_equal true

    regexp = resources.first.match_origin('https://app.example.com')
    _(regexp.wildcard?).must_equal false
    _(regexp.credentials).must_be_nil
  end

  it 'should prefer exact rules over procs regardless of declaration order' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins '*',
                ->(_source, _env) { { max_age: 10 } },
                { 'admin.example.com' => { credentials: true } }
        resource '/'
      end
    end
    resources = cors.send :all_resources

    match = resources.first.match_origin('http://admin.example.com')
    _(match.credentials).must_equal true
    _(match.max_age).must_be_nil

    fallback = resources.first.match_origin('http://other.example.com')
    _(fallback.max_age).must_equal 10
  end

  it 'should support procs returning structured match results' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins lambda { |source, _env|
          source.end_with?('.trusted.example.com') && { credentials: true, max_age: 300 }
        }
        resource '/'
      end
    end
    resources = cors.send :all_resources

    match = resources.first.match_origin('http://app.trusted.example.com')
    _(match.credentials).must_equal true
    _(match.max_age).must_equal 300
    _(resources.first.allow_origin?('http://app.trusted.example.com')).must_equal true

    _(resources.first.match_origin('http://untrusted.example.com')).must_be_nil
    _(resources.first.allow_origin?('http://untrusted.example.com')).wont_equal true
  end

  it 'should keep boolean procs working as before' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins ->(source, _env) { source == 'http://ok.example.com' }
        resource '/'
      end
    end
    resources = cors.send :all_resources

    match = resources.first.match_origin('http://ok.example.com')
    _(match.wildcard?).must_equal false
    _(match.credentials).must_be_nil
    _(resources.first.match_origin('http://nope.example.com')).must_be_nil
  end

  it 'should raise when credentials are enabled for a wildcard origin' do
    _(proc do
      Rack::Cors.new(proc {}) do
        allow do
          origins '*' => { credentials: true }
          resource '/'
        end
      end
    end).must_raise Rack::Cors::Resource::CorsMisconfigurationError
  end

  it 'should reject unknown origin options' do
    _(proc do
      Rack::Cors.new(proc {}) do
        allow do
          origins 'example.com' => { credentails: true }
          resource '/'
        end
      end
    end).must_raise ArgumentError
  end
end
