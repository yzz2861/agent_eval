require_relative "../spec_helper"

# Load the plugin so its store class is available to the specs.
Class.new(Roda){plugin :one_time_csrf}

describe "one_time_csrf plugin" do
  include CookieJar

  # Synchronization barrier to force interleaving of concurrent requests.
  class OneTimeCsrfBarrier
    def initialize(count)
      @count = count
      @arrived = 0
      @mutex = Mutex.new
      @cond = ConditionVariable.new
    end

    def arrive
      @mutex.synchronize do
        @arrived += 1
        if @arrived >= @count
          @cond.broadcast
        else
          @cond.wait(@mutex)
        end
      end
    end
  end

  # Fake clock returning a manually advanced time.
  class OneTimeCsrfClock
    def initialize
      @now = 1000.0
    end

    def call
      @now
    end

    def advance(seconds)
      @now += seconds
    end
  end

  def one_time_csrf_app(opts={}, &block)
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin(:one_time_csrf, opts)
      route do |r|
        r.post 'delete-account' do
          check_one_time_csrf!
          'deleted'
        end
        r.post 'other' do
          check_one_time_csrf!
          'other'
        end
        r.post 'form' do
          check_csrf!
          'form'
        end
        r.get 'token', String do |s|
          one_time_csrf_token("/#{s}")
        end
        r.get 'token', String, String do |m, s|
          one_time_csrf_token("/#{s}", m)
        end
        r.get 'formtoken' do
          csrf_token('/form')
        end
        instance_exec(r, &block) if block
      end
    end
  end

  def post_with_token(path, token, field: '_one_time_csrf', method: 'POST')
    body(path, 'REQUEST_METHOD'=>method, 'CONTENT_TYPE'=>'application/x-www-form-urlencoded',
      'rack.input'=>rack_input("#{field}=#{Rack::Utils.escape(token)}"))
  end

  it "allows a sensitive operation exactly once per token" do
    one_time_csrf_app
    token = body('/token/delete-account')
    post_with_token('/delete-account', token).must_equal 'deleted'
    proc{post_with_token('/delete-account', token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    token = body('/token/delete-account')
    post_with_token('/delete-account', token).must_equal 'deleted'
  end

  it "still allows regular forms to use existing route_csrf tokens" do
    one_time_csrf_app
    token = body('/formtoken')
    body('/form', 'REQUEST_METHOD'=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'form'
    body('/form', 'REQUEST_METHOD'=>'POST', 'rack.input'=>rack_input("_csrf=#{Rack::Utils.escape(token)}")).must_equal 'form'
    proc{post_with_token('/delete-account', token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "rejects tokens used for a different path without consuming them" do
    one_time_csrf_app
    token = body('/token/delete-account')
    proc{post_with_token('/other', token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    post_with_token('/delete-account', token).must_equal 'deleted'
  end

  it "rejects tokens used for a different request method without consuming them" do
    one_time_csrf_app do |r|
      r.is 'multi' do
        check_one_time_csrf!
        'multi'
      end
    end
    token = body('/token/POST/multi')
    proc{post_with_token('/multi', token, :method=>'PUT')}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    post_with_token('/multi', token).must_equal 'multi'

    token = body('/token/PUT/multi')
    proc{post_with_token('/multi', token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
    post_with_token('/multi', token, :method=>'PUT').must_equal 'multi'
  end

  it "rejects tokens used in a different session without consuming them" do
    one_time_csrf_app
    token = body('/token/delete-account')
    cookie = @cookie

    @cookie = nil
    proc{post_with_token('/delete-account', token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    @cookie = cookie
    post_with_token('/delete-account', token).must_equal 'deleted'
  end

  it "rejects expired tokens" do
    clock = OneTimeCsrfClock.new
    store = Roda::RodaPlugins::OneTimeCsrf::MemoryStore.new(:clock=>clock)
    one_time_csrf_app(:store=>store, :ttl=>60)

    token = body('/token/delete-account')
    clock.advance(59)
    post_with_token('/delete-account', token).must_equal 'deleted'

    token = body('/token/delete-account')
    clock.advance(61)
    store.read(token).must_be_nil
    proc{post_with_token('/delete-account', token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "allows only one of two concurrent requests to consume the same token" do
    barrier = OneTimeCsrfBarrier.new(2)
    store = Class.new(Roda::RodaPlugins::OneTimeCsrf::MemoryStore) do
      define_method(:read) do |token|
        data = super(token)
        # Ensure both requests have validated the token before either
        # attempts to consume it.
        barrier.arrive if data
        data
      end
    end.new
    one_time_csrf_app(:store=>store)
    token = body('/token/delete-account')
    cookie = @cookie

    results = 2.times.map do
      Thread.new do
        begin
          @app.call(req_env('PATH_INFO'=>'/delete-account', 'REQUEST_METHOD'=>'POST',
            'rack.input'=>rack_input("_one_time_csrf=#{Rack::Utils.escape(token)}"),
            'HTTP_COOKIE'=>cookie))[0]
        rescue Roda::RodaPlugins::RouteCsrf::InvalidToken
          403
        end
      end
    end.map(&:value)
    results.sort.must_equal [200, 403]
  end

  it "rejects the sensitive operation when the token store is unavailable" do
    store = Object.new
    def store.read(*) raise "store unavailable" end
    def store.write(*) raise "store unavailable" end
    def store.consume(*) raise "store unavailable" end
    one_time_csrf_app(:store=>store)
    proc{post_with_token('/delete-account', 'token')}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports check_one_time_csrf! with a block" do
    one_time_csrf_app do |r|
      r.post 'blocked' do
        check_one_time_csrf!{'nope'}
        'yep'
      end
    end
    token = body('/token/blocked')
    post_with_token('/blocked', token).must_equal 'yep'
    body('/blocked', 'REQUEST_METHOD'=>'POST', 'rack.input'=>rack_input).must_equal 'nope'
  end

  it "supports valid_one_time_csrf?" do
    one_time_csrf_app do |r|
      r.post 'valid' do
        valid_one_time_csrf?.to_s
      end
    end
    token = body('/token/valid')
    post_with_token('/valid', token).must_equal 'true'
    post_with_token('/valid', token).must_equal 'false'
  end

  it "supports one_time_csrf_tag and one_time_csrf_field" do
    one_time_csrf_app{one_time_csrf_tag('/delete-account')}
    body =~ /\A<input type="hidden" name="_one_time_csrf" value="([^"]+)" \/>\z/
    post_with_token('/delete-account', $1).must_equal 'deleted'

    one_time_csrf_app{one_time_csrf_field}
    body.must_equal '_one_time_csrf'

    one_time_csrf_app(:field=>'foo'){one_time_csrf_tag('/delete-account')}
    body =~ /\A<input type="hidden" name="foo" value="([^"]+)" \/>\z/
    post_with_token('/delete-account', $1, :field=>'foo').must_equal 'deleted'
  end

  it "supports the :token option to check_one_time_csrf!" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin(:one_time_csrf)
      route do |r|
        r.get 'token', String do |s|
          one_time_csrf_token("/#{s}")
        end
        r.post 'delete-account' do
          check_one_time_csrf!(:token=>env['TOKEN'])
          'deleted'
        end
      end
    end
    token = body('/token/delete-account')
    body('/delete-account', 'REQUEST_METHOD'=>'POST', 'TOKEN'=>token).must_equal 'deleted'
    proc{body('/delete-account', 'REQUEST_METHOD'=>'POST', 'TOKEN'=>token)}.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end
end
