# frozen_string_literal: true

require 'rack/builder'
require 'minitest/autorun'
require 'rack/test'
require 'rack/cors'
require 'logger'
require 'stringio'

describe Rack::Cors, 'intersection combine mode' do
  include Rack::Test::Methods

  attr_accessor :cors_result, :app

  Capture = Class.new do
    def initialize(app, options = {})
      @app = app
      @holder = options[:holder]
    end

    def call(env)
      response = @app.call(env)
      @holder.cors_result = env[Rack::Cors::RACK_CORS]
      response
    end
  end

  def build_app(combine: :intersect, &block)
    test = self
    Rack::Builder.new do
      use Capture, holder: test
      use Rack::Cors, debug: true, logger: Logger.new(StringIO.new), combine: combine, &block
      run ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }
    end
  end

  def api_app(combine: :intersect, order: :broad_first, admin_origins: '*')
    broad = proc do
      origins '*'
      resource '/api/*', headers: :any, methods: %i[get post put], expose: 'X-Base', max_age: 600
    end
    narrow = proc do
      origins admin_origins
      resource '/api/admin/*', headers: 'x-admin', methods: :get, expose: 'X-Admin', max_age: 300
    end
    rules = order == :broad_first ? [broad, narrow] : [narrow, broad]

    build_app(combine: combine) do
      rules.each { |rule| allow(&rule) }
    end
  end

  def cors_request(path, method: :get, origin: 'http://example.com')
    header 'Origin', origin
    public_send(method, path)
  end

  def preflight(path, method: 'GET', headers: nil, origin: 'http://example.com')
    header 'Origin', origin
    header 'Access-Control-Request-Method', method
    header 'Access-Control-Request-Headers', headers if headers
    options path
  end

  it 'narrows the method set for paths covered by several resources' do
    self.app = api_app
    cors_request '/api/admin/users'
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'GET'
  end

  it 'keeps the broad method set outside the narrower resource' do
    self.app = api_app
    cors_request '/api/things'
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'GET, POST, PUT'
  end

  it 'rejects a preflight method outside the intersection' do
    self.app = api_app
    preflight '/api/admin/users', method: 'POST'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_DENY_METHOD
  end

  it 'narrows the allowed headers' do
    self.app = api_app
    preflight '/api/admin/users', method: 'GET', headers: 'X-Other'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_DENY_HEADER
  end

  it 'accepts headers in the intersection' do
    self.app = api_app
    preflight '/api/admin/users', method: 'GET', headers: 'X-Admin'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
    _(last_response.headers['Access-Control-Allow-Headers']).must_equal 'X-Admin'
  end

  it 'always permits CORS simple headers despite an empty explicit header intersection' do
    self.app = api_app
    preflight '/api/admin/users', method: 'GET', headers: 'Content-Type'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
  end

  it 'unifies exposed headers' do
    self.app = api_app
    cors_request '/api/admin/users'
    _(last_response.headers['Access-Control-Expose-Headers']).must_equal 'X-Admin, X-Base'
  end

  it 'takes the minimum configured max-age' do
    self.app = api_app
    cors_request '/api/admin/users'
    _(last_response.headers['Access-Control-Max-Age']).must_equal '300'
  end

  it 'defaults max-age to 7200 when nothing is configured' do
    self.app = build_app do
      allow do
        origins '*'
        resource '/api/*'
      end
      allow do
        origins '*'
        resource '/api/admin/*'
      end
    end
    cors_request '/api/admin/x'
    _(last_response.headers['Access-Control-Max-Age']).must_equal '7200'
  end

  it 'requires credentials on every matched rule' do
    self.app = build_app do
      allow do
        origins 'http://example.com'
        resource '/api/*', methods: :get, credentials: true
      end
      allow do
        origins 'http://example.com'
        resource '/api/admin/*', methods: :get, credentials: false
      end
    end
    cors_request '/api/admin/x'
    _(last_response.headers['Access-Control-Allow-Credentials']).must_be_nil
  end

  it 'grants credentials when all matched rules do' do
    self.app = build_app do
      allow do
        origins 'http://example.com'
        resource '/api/*', methods: :get, credentials: true
      end
      allow do
        origins 'http://example.com'
        resource '/api/admin/*', methods: :get, credentials: true
      end
    end
    cors_request '/api/admin/x'
    _(last_response.headers['Access-Control-Allow-Credentials']).must_equal 'true'
  end

  it 'intersects origin permissions and echoes the specific origin' do
    self.app = build_app do
      allow do
        origins '*'
        resource '/api/*', methods: :get
      end
      allow do
        origins 'http://example.com'
        resource '/api/admin/*', methods: :get
      end
    end
    cors_request '/api/admin/x', origin: 'http://example.com'
    _(last_response.headers['Access-Control-Allow-Origin']).must_equal 'http://example.com'
  end

  it 'denies an origin allowed by only one covering block' do
    self.app = build_app do
      allow do
        origins 'http://example.com'
        resource '/api/*', methods: :get
      end
      allow do
        origins 'http://other.example'
        resource '/api/admin/*', methods: :get
      end
    end
    cors_request '/api/admin/x', origin: 'http://example.com'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_NO_ORIGIN
  end

  it 'evaluates origin Procs at request time' do
    self.app = build_app do
      allow do
        origins('http://a.example')
        resource '/x', methods: :get
      end
      allow do
        origins { |source, _env| source == 'http://b.example' }
        resource '/x', methods: :get
      end
    end
    cors_request '/x', origin: 'http://a.example'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_NO_ORIGIN

    cors_request '/x', origin: 'http://b.example'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_NO_ORIGIN
  end

  it 'reports no-path when no rule covers the path' do
    self.app = api_app
    cors_request '/elsewhere'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_NO_PATH
  end

  it 'is independent of the order resources are declared' do
    self.app = api_app(order: :broad_first)
    cors_request '/api/admin/users'
    first = last_response.headers.to_h.slice('Access-Control-Allow-Methods',
                                             'Access-Control-Expose-Headers',
                                             'Access-Control-Max-Age')

    self.app = api_app(order: :narrow_first)
    cors_request '/api/admin/users'
    second = last_response.headers.to_h.slice('Access-Control-Allow-Methods',
                                              'Access-Control-Expose-Headers',
                                              'Access-Control-Max-Age')

    _(second).must_equal first
  end

  it 'only combines rules whose :if block passes for the request' do
    self.app = build_app do
      allow do
        origins '*'
        resource '/api/*', methods: :get
      end
      allow do
        origins '*'
        resource '/api/*', methods: :get, if: proc { |env| env['HTTP_X_FEATURE'] == 'on' }
      end
    end

    cors_request '/api/x'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil

    header 'X-Feature', 'on'
    cors_request '/api/x'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
  end

  it 'does not change first-match behavior by default' do
    self.app = api_app(combine: :first_match)
    cors_request '/api/admin/users'
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'GET, POST, PUT'
    _(last_response.headers['Access-Control-Max-Age']).must_equal '600'
  end

  it 'rejects an unknown combine mode at initialization' do
    _(proc do
      Rack::Cors.new(proc {}, combine: :bogus) {}
    end).must_raise ArgumentError
  end

  it 'raises at initialization when static method sets are disjoint' do
    _(proc do
      Rack::Cors.new(proc {}, combine: :intersect) do
        allow do
          origins 'http://example.com'
          resource '/x', methods: :get
        end
        allow do
          origins 'http://example.com'
          resource '/x', methods: :post
        end
      end
    end).must_raise Rack::Cors::Resource::CorsMisconfigurationError
  end

  it 'raises at initialization when literal origin sets are disjoint' do
    _(proc do
      Rack::Cors.new(proc {}, combine: :intersect) do
        allow do
          origins 'http://a.example'
          resource '/y', methods: :get
        end
        allow do
          origins 'http://b.example'
          resource '/y', methods: :get
        end
      end
    end).must_raise Rack::Cors::Resource::CorsMisconfigurationError
  end

  it 'does not raise at initialization for regex/proc origins or :if rules' do
    Rack::Cors.new(proc {}, combine: :intersect) do
      allow do
        origins %r{Ahttp://example.comz}
        resource '/z', methods: :get
      end
      allow do
        origins 'http://other.example'
        resource '/z', methods: :get
      end
      allow do
        origins '*'
        resource '/conditional', methods: :get, if: proc { |env| env['HTTP_X_OK'] == '1' }
      end
      allow do
        origins '*'
        resource '/conditional', methods: :post, if: proc { |env| env['HTTP_X_OK'] == '1' }
      end
    end
  end

  it 'treats unconfigured methods as GET and :any as the full method set' do
    self.app = build_app do
      allow do
        origins '*'
        resource '/api/*', methods: :any
      end
      allow do
        origins '*'
        resource '/api/admin/*'
      end
    end
    preflight '/api/admin/x', method: 'POST'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_DENY_METHOD

    preflight '/api/admin/x', method: 'GET'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'GET'
  end

  it 'keeps :any headers when every covering rule uses :any' do
    self.app = build_app do
      allow do
        origins '*'
        resource '/api/*', headers: :any
      end
      allow do
        origins '*'
        resource '/api/admin/*', headers: :any
      end
    end
    preflight '/api/admin/x', method: 'GET', headers: 'X-Custom-Thing'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
  end

  it 'keeps the full method set when every covering rule uses methods :any' do
    self.app = build_app do
      allow do
        origins '*'
        resource '/api/*', methods: :any
      end
      allow do
        origins '*'
        resource '/api/admin/*', methods: :any
      end
    end
    preflight '/api/admin/x', method: 'DELETE'
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT'
  end
end
