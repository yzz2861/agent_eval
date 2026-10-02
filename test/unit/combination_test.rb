# frozen_string_literal: true

require 'rack/builder'
require 'minitest/autorun'
require 'rack/test'
require 'rack/cors'

class CaptureResult
  def initialize(app, options = {})
    @app = app
    @result_holder = options[:holder]
  end

  def call(env)
    response = @app.call(env)
    @result_holder.cors_result = env[Rack::Cors::RACK_CORS]
    response
  end
end

describe Rack::Cors, 'combine: :intersection' do
  include Rack::Test::Methods

  attr_accessor :cors_result

  def load_app(name, options = {})
    test = self
    Rack::Builder.new do
      use CaptureResult, holder: test
      eval File.read(File.dirname(__FILE__) + "/#{name}.ru") # rubocop:disable Security/Eval
      map('/') do
        run(lambda { |_env| [200, { 'content-type' => 'text/html' }, ['success']] })
      end
    end
  end

  let(:app) { load_app('combination') }
  let(:reversed_app) { load_app('combination_reversed') }

  def preflight(origin, path, opts = {})
    header 'Origin', origin
    header 'Access-Control-Request-Method', opts[:method] ? opts[:method].to_s.upcase : 'GET'
    header 'Access-Control-Request-Headers', opts[:headers] if opts[:headers]
    options path
  end

  it 'keeps the broad rule for paths outside the narrower resource' do
    header 'Origin', 'https://trusted.example.com'
    get '/api/users'
    _(last_response.headers['Access-Control-Allow-Origin']).must_equal 'https://trusted.example.com'
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'DELETE, GET, POST, PUT'
    _(last_response.headers['Access-Control-Expose-Headers']).must_equal 'x-a, x-b'
    _(last_response.headers['Access-Control-Max-Age']).must_equal '600'
    _(last_response.headers['Access-Control-Allow-Credentials']).must_equal 'true'
  end

  it 'intersects methods for paths matched by both resources' do
    preflight('https://trusted.example.com', '/api/admin/users', method: :post)
    _(last_response.headers['Access-Control-Allow-Methods']).must_equal 'GET, POST'
  end

  it 'denies a method allowed only by the broad resource' do
    preflight('https://trusted.example.com', '/api/admin/users', method: :delete)
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result).must_be :preflight
    _(cors_result).wont_be :hit
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_DENY_METHOD
  end

  it 'intersects headers' do
    preflight('https://trusted.example.com', '/api/admin/users',
              method: :post, headers: 'X-Admin, X-Token')
    _(last_response.headers['Access-Control-Allow-Headers']).must_equal 'X-Admin, X-Token'
  end

  it 'denies a request header outside the narrower list' do
    preflight('https://trusted.example.com', '/api/admin/users',
              method: :post, headers: 'X-Evil')
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_DENY_HEADER
  end

  it 'still allows CORS simple headers with an empty header intersection' do
    preflight('https://trusted.example.com', '/api/admin/users',
              method: :get, headers: 'Accept')
    _(last_response.headers['Access-Control-Allow-Origin']).wont_be_nil
  end

  it 'uses the tightest max_age' do
    preflight('https://trusted.example.com', '/api/admin/users', method: :get)
    _(last_response.headers['Access-Control-Max-Age']).must_equal '300'
  end

  it 'combines expose as an intersection' do
    header 'Origin', 'https://trusted.example.com'
    get '/api/admin/users'
    _(last_response.headers['Access-Control-Expose-Headers']).must_equal ''
  end

  it 'unions vary headers' do
    header 'Origin', 'https://trusted.example.com'
    get '/api/admin/users'
    _(last_response.headers['Vary']).must_equal 'Host, X-Tenant'
  end

  it 'is independent of declaration order' do
    response = Rack::MockRequest.new(reversed_app).options(
      '/api/admin/users',
      'HTTP_ORIGIN' => 'https://trusted.example.com',
      'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST',
      'HTTP_ACCESS_CONTROL_REQUEST_HEADERS' => 'X-Admin, X-Token'
    )
    _(response.headers['Access-Control-Allow-Methods']).must_equal 'GET, POST'
    _(response.headers['Access-Control-Allow-Headers']).must_equal 'X-Admin, X-Token'
    _(response.headers['Access-Control-Max-Age']).must_equal '300'
  end

  it 'intersects origin permissions at request time' do
    preflight('https://untrusted.example.net', '/api/users', method: :get)
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_NO_ORIGIN
  end

  it 'does not grant CORS for an unmatched path' do
    header 'Origin', 'https://trusted.example.com'
    get '/elsewhere'
    _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    _(cors_result.miss_reason).must_equal Rack::Cors::Result::MISS_NO_PATH
  end

  it 'adds Vary headers based on every path-matching resource, even without an Origin' do
    get '/api/admin/users'
    _(last_response.headers['Vary']).must_equal 'Host, X-Tenant'
  end

  describe ':if guarded resources' do
    it 'intersects only resources whose :if preflight guard matches the request' do
      app = Rack::Builder.new do
        use Rack::Cors, combine: :intersection do
          allow do
            origins 'https://trusted.example.com'
            resource '/api/*', methods: %i[get post]
            resource '/api/*', methods: %i[get], if: proc { |env| env['HTTP_X_OK'] == '1' }
          end
        end
        run ->(_env) { [200, {}, ['ok']] }
      end

      response = Rack::MockRequest.new(app).request(
        'OPTIONS',
        '/api/users',
        input: '',
        'HTTP_ORIGIN' => 'https://trusted.example.com',
        'HTTP_X_OK' => '1',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST'
      )
      _(response.headers['Access-Control-Allow-Origin']).must_be_nil
    end

    it 'reports deny-method for request-time empty method intersections' do
      app = Rack::Builder.new do
        use Rack::Cors, combine: :intersection do
          allow do
            origins 'https://trusted.example.com'
            resource '/api/*', methods: %i[get post], if: proc { |env| env['HTTP_X_OK'] == '1' }
          end
          allow do
            origins 'https://trusted.example.com'
            resource '/api/*', methods: :get, if: proc { |env| env['HTTP_X_OK'] == '1' }
          end
        end
        run ->(_env) { [200, {}, ['ok']] }
      end

      response = Rack::MockRequest.new(app).request(
        'OPTIONS', '/api/users',
        input: '',
        'HTTP_ORIGIN' => 'https://trusted.example.com',
        'HTTP_X_OK' => '1',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST'
      )
      _(response.headers['Access-Control-Allow-Origin']).must_be_nil
    end

    it 'ignores non-matching guards during preflight' do
      app = Rack::Builder.new do
        use Rack::Cors, combine: :intersection do
          allow do
            origins 'https://trusted.example.com'
            resource '/api/*', methods: %i[get post]
            resource '/api/*', methods: %i[get], if: proc { |env| env['HTTP_X_OK'] == '1' }
          end
        end
        run ->(_env) { [200, {}, ['ok']] }
      end

      response = Rack::MockRequest.new(app).request(
        'OPTIONS', '/api/users',
        input: '',
        'HTTP_ORIGIN' => 'https://trusted.example.com',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'POST'
      )
      _(response.headers['Access-Control-Allow-Origin']).must_equal 'https://trusted.example.com'
      _(response.headers['Access-Control-Allow-Methods']).must_equal 'GET, POST'
    end
  end

  describe 'initialization time validation' do
    def cors(&block)
      Rack::Cors.new(->(_env) { [200, {}, []] }, combine: :intersection, &block)
    end

    it 'raises for overlapping resources with disjoint methods' do
      error = assert_raises Rack::Cors::Resource::CorsMisconfigurationError do
        cors do
          allow do
            origins 'https://a.example.com'
            resource '/api/*', methods: :get
          end
          allow do
            origins 'https://a.example.com'
            resource '/api/admin/*', methods: :post
          end
        end
      end
      _(error.message).must_include 'share no allowed methods'
    end

    it 'raises for provably disjoint origins' do
      error = assert_raises Rack::Cors::Resource::CorsMisconfigurationError do
        cors do
          allow do
            origins 'https://a.example.com'
            resource '/api/*', methods: :get
          end
          allow do
            origins 'https://b.example.com'
            resource '/api/*', methods: :get
          end
        end
      end
      _(error.message).must_include 'disjoint origins'
    end

    it 'raises for a block that declares resources but no origins' do
      assert_raises Rack::Cors::Resource::CorsMisconfigurationError do
        cors do
          allow do
            origins ''
            resource '/api/*', methods: :get
          end
        end
      end
    end

    it 'raises for an explicitly empty methods list' do
      assert_raises Rack::Cors::Resource::CorsMisconfigurationError do
        cors do
          allow do
            origins 'https://a.example.com'
            resource '/api/*', methods: []
          end
        end
      end
    end

    it 'does not flag disjoint methods on non-overlapping paths' do
      cors do
        allow do
          origins 'https://a.example.com'
          resource '/public/*', methods: :get
        end
        allow do
          origins 'https://a.example.com'
          resource '/admin/*', methods: :post
        end
      end
    end

    it 'does not flag regexp origins at initialization time' do
      cors do
        allow do
          origins %r{\Ahttps://a\.example\.com\z}
          resource '/api/*', methods: :get
        end
        allow do
          origins %r{\Ahttps://b\.example\.org\z}
          resource '/api/*', methods: :get
        end
      end
    end
  end

  describe 'public resources' do
    def public_app
      Rack::Builder.new do
        use Rack::Cors, combine: :intersection do
          allow do
            origins '*'
            resource '/api/*', methods: :get
          end
          allow do
            origins 'https://trusted.example.com'
            resource '/api/admin/*', methods: :get
          end
        end
        run ->(_env) { [200, {}, ['ok']] }
      end
    end

    it 'reflects the origin when not every matched resource is public' do
      header 'Origin', 'https://trusted.example.com'
      get '/api/admin/users'
      _(last_response.headers['Access-Control-Allow-Origin']).must_equal 'https://trusted.example.com'
    end

    it 'denies origins missing from the narrower resource' do
      header 'Origin', 'https://anyone.example.net'
      get '/api/admin/users'
      _(last_response.headers['Access-Control-Allow-Origin']).must_be_nil
    end
  end

  describe ':first_match default' do
    it 'keeps historical first-match behavior' do
      cors = Rack::Cors.new(->(_env) { [200, {}, []] }) do
        allow do
          origins 'https://trusted.example.com'
          resource '/api/*', methods: %i[get post]
        end
        allow do
          origins 'https://trusted.example.com'
          resource '/api/admin/*', methods: :get
        end
      end

      env = Rack::MockRequest.env_for('/api/admin/users', method: 'POST',
                                       'HTTP_ORIGIN' => 'https://trusted.example.com')
      resource, = cors.send(:match_resource, '/api/admin/users', env)
      _(resource.methods.sort).must_equal %w[get post]
    end

    it 'rejects unknown combine modes at initialization' do
      assert_raises ArgumentError do
        Rack::Cors.new(->(_env) { [200, {}, []] }, combine: :union) {}
      end
    end
  end
end
