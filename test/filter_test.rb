require_relative 'test_helper'

class BeforeFilterTest < Minitest::Test
  it "executes filters in the order defined" do
    count = 0
    mock_app do
      get('/') { 'Hello World' }
      before do
        assert_equal 0, count
        count = 1
      end
      before do
        assert_equal 1, count
        count = 2
      end
    end

    get '/'
    assert ok?
    assert_equal 2, count
    assert_equal 'Hello World', body
  end

  it "can modify the request" do
    mock_app do
      get('/foo') { 'foo' }
      get('/bar') { 'bar' }
      before { request.path_info = '/bar' }
    end

    get '/foo'
    assert ok?
    assert_equal 'bar', body
  end

  it "can modify instance variables available to routes" do
    mock_app do
      before { @foo = 'bar' }
      get('/foo') { @foo }
    end

    get '/foo'
    assert ok?
    assert_equal 'bar', body
  end

  it "allows redirects" do
    mock_app do
      before { redirect '/bar' }
      get('/foo') do
        fail 'before block should have halted processing'
        'ORLY?!'
      end
    end

    get '/foo'
    assert redirect?
    assert_equal 'http://example.org/bar', response['Location']
    assert_equal '', body
  end

  it "does not modify the response with its return value" do
    mock_app do
      before { 'Hello World!' }
      get('/foo') do
        assert_equal [], response.body
        'cool'
      end
    end

    get '/foo'
    assert ok?
    assert_equal 'cool', body
  end

  it "does modify the response with halt" do
    mock_app do
      before { halt 302, 'Hi' }
      get '/foo' do
        "should not happen"
      end
    end

    get '/foo'
    assert_equal 302, response.status
    assert_equal 'Hi', body
  end

  it "gives you access to params" do
    mock_app do
      before { @foo = params['foo'] }
      get('/foo') { @foo }
    end

    get '/foo?foo=cool'
    assert ok?
    assert_equal 'cool', body
  end

  it "properly unescapes parameters" do
    mock_app do
      before { @foo = params['foo'] }
      get('/foo') { @foo }
    end

    get '/foo?foo=bar%3Abaz%2Fbend'
    assert ok?
    assert_equal 'bar:baz/bend', body
  end

  it "runs filters defined in superclasses" do
    base = Class.new(Sinatra::Base)
    base.before { @foo = 'hello from superclass' }

    mock_app(base) { get('/foo') { @foo } }

    get '/foo'
    assert_equal 'hello from superclass', body
  end

  it 'does not run before filter when serving static files' do
    ran_filter = false
    mock_app do
      before { ran_filter = true }
      set :static, true
      set :public_folder, __dir__
    end
    get "/#{File.basename(__FILE__)}"
    assert ok?
    assert_equal File.read(__FILE__), body
    assert !ran_filter
  end

  it 'takes an optional route pattern' do
    ran_filter = false
    mock_app do
      before("/b*") { ran_filter = true }
      get('/foo') { }
      get('/bar') { }
    end
    get '/foo'
    assert !ran_filter
    get '/bar'
    assert ran_filter
  end

  it 'generates block arguments from route pattern' do
    subpath = nil
    mock_app do
      before("/foo/:sub") { |s| subpath = s }
      get('/foo/*') { }
    end
    get '/foo/bar'
    assert_equal subpath, 'bar'
  end

  it 'can catch exceptions in before filters and handle them properly' do
    doodle = ''
    mock_app do
      before do
        doodle += 'This begins'
        raise StandardError, "before"
      end
      get "/" do
        doodle = 'and runs'
      end
      error 500 do
        "Error handled #{env['sinatra.error'].message}"
      end
    end

    doodle = ''
    get '/'
    assert_equal 'Error handled before', body
    assert_equal 'This begins', doodle
  end
end

class AfterFilterTest < Minitest::Test
  it "executes before and after filters in correct order" do
    invoked = 0
    mock_app do
      before   { invoked = 2 }
      get('/') { invoked += 2; 'hello' }
      after    { invoked *= 2 }
    end

    get '/'
    assert ok?

    assert_equal 8, invoked
  end

  it "executes filters in the order defined" do
    count = 0
    mock_app do
      get('/') { 'Hello World' }
      after do
        assert_equal 0, count
        count = 1
      end
      after do
        assert_equal 1, count
        count = 2
      end
    end

    get '/'
    assert ok?
    assert_equal 2, count
    assert_equal 'Hello World', body
  end

  it "allows redirects" do
    mock_app do
      get('/foo') { 'ORLY' }
      after { redirect '/bar' }
    end

    get '/foo'
    assert redirect?
    assert_equal 'http://example.org/bar', response['Location']
    assert_equal '', body
  end

  it "does not modify the response with its return value" do
    mock_app do
      get('/foo') { 'cool' }
      after { 'Hello World!' }
    end

    get '/foo'
    assert ok?
    assert_equal 'cool', body
  end

  it "does modify the response with halt" do
    mock_app do
      get '/foo' do
        "should not be returned"
      end
      after { halt 302, 'Hi' }
    end

    get '/foo'
    assert_equal 302, response.status
    assert_equal 'Hi', body
  end

  it "runs filters defined in superclasses" do
    count = 2
    base = Class.new(Sinatra::Base)
    base.after { count *= 2 }
    mock_app(base) do
      get('/foo') do
        count += 2
        "ok"
      end
    end

    get '/foo'
    assert_equal 8, count
  end

  it "respects content type set in superclass filter" do
    base = Class.new(Sinatra::Base)
    base.before { content_type :json }
    mock_app(base) do
      get('/foo'){ {foo: :bar}.to_json }
    end

    get '/foo'
    assert_equal 'application/json', response.headers['Content-Type']
  end

  it 'does not run after filter when serving static files' do
    ran_filter = false
    mock_app do
      after { ran_filter = true }
      set :static, true
      set :public_folder, __dir__
    end
    get "/#{File.basename(__FILE__)}"
    assert ok?
    assert_equal File.read(__FILE__), body
    assert !ran_filter
  end

  it 'takes an optional route pattern' do
    ran_filter = false
    mock_app do
      after("/b*") { ran_filter = true }
      get('/foo') { }
      get('/bar') { }
    end
    get '/foo'
    assert !ran_filter
    get '/bar'
    assert ran_filter
  end

  it 'changes to path_info from a pattern matching before filter are respected when routing' do
    mock_app do
      before('/foo') { request.path_info = '/bar' }
      get('/bar') { 'blah' }
    end
    get '/foo'
    assert ok?
    assert_equal 'blah', body
  end

  it 'generates block arguments from route pattern' do
    subpath = nil
    mock_app do
      after("/foo/:sub") { |s| subpath = s }
      get('/foo/*') { }
    end
    get '/foo/bar'
    assert_equal subpath, 'bar'
  end

  it 'is possible to access url params from the route param' do
    ran = false
    mock_app do
      get('/foo/*') { }
      before('/foo/:sub') do
        assert_equal params[:sub], 'bar'
        ran = true
      end
    end
    get '/foo/bar'
    assert ran
  end

  it 'is possible to apply host_name conditions to before filters with no path' do
    ran = false
    mock_app do
      before(:host_name => 'example.com') { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_HOST' => 'example.org' })
    assert !ran
    get('/', {}, { 'HTTP_HOST' => 'example.com' })
    assert ran
  end

  it 'is possible to apply host_name conditions to before filters with a path' do
    ran = false
    mock_app do
      before('/foo', :host_name => 'example.com') { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_HOST' => 'example.com' })
    assert !ran
    get('/foo', {}, { 'HTTP_HOST' => 'example.org' })
    assert !ran
    get('/foo', {}, { 'HTTP_HOST' => 'example.com' })
    assert ran
  end

  it 'is possible to apply host_name conditions to after filters with no path' do
    ran = false
    mock_app do
      after(:host_name => 'example.com') { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_HOST' => 'example.org' })
    assert !ran
    get('/', {}, { 'HTTP_HOST' => 'example.com' })
    assert ran
  end

  it 'is possible to apply host_name conditions to after filters with a path' do
    ran = false
    mock_app do
      after('/foo', :host_name => 'example.com') { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_HOST' => 'example.com' })
    assert !ran
    get('/foo', {}, { 'HTTP_HOST' => 'example.org' })
    assert !ran
    get('/foo', {}, { 'HTTP_HOST' => 'example.com' })
    assert ran
  end

  it 'is possible to apply user_agent conditions to before filters with no path' do
    ran = false
    mock_app do
      before(:user_agent => /foo/) { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_USER_AGENT' => 'bar' })
    assert !ran
    get('/', {}, { 'HTTP_USER_AGENT' => 'foo' })
    assert ran
  end

  it 'is possible to apply user_agent conditions to before filters with a path' do
    ran = false
    mock_app do
      before('/foo', :user_agent => /foo/) { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_USER_AGENT' => 'foo' })
    assert !ran
    get('/foo', {}, { 'HTTP_USER_AGENT' => 'bar' })
    assert !ran
    get('/foo', {}, { 'HTTP_USER_AGENT' => 'foo' })
    assert ran
  end

  it 'can add params' do
    mock_app do
      before { params['foo'] = 'bar' }
      get('/') { params['foo'] }
    end

    get '/'
    assert_body 'bar'
  end

  it 'can add params on a single path' do
    mock_app do
      before('/hi'){ params['foo'] = 'bar' }
      get('/hi') { params['foo'] }
    end

    get '/hi'
    assert_body 'bar'
  end

  # ref: issue #1567
  it 'can add params on named parameters path' do
    mock_app do
      before('/:id/hi'){ params['foo'] = 'bar' }
      get('/:id/hi') { params['foo'] }
    end

    get '/:id/hi'
    assert_body 'bar'
  end

  it 'can remove params' do
    mock_app do
      before { params.delete('foo') }
      get('/') { params['foo'].to_s }
    end

    get '/?foo=bar'
    assert_body ''
  end

  it 'is possible to apply user_agent conditions to after filters with no path' do
    ran = false
    mock_app do
      after(:user_agent => /foo/) { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_USER_AGENT' => 'bar' })
    assert !ran
    get('/', {}, { 'HTTP_USER_AGENT' => 'foo' })
    assert ran
  end

  it 'is possible to apply user_agent conditions to after filters with a path' do
    ran = false
    mock_app do
      after('/foo', :user_agent => /foo/) { ran = true }
      get('/') { 'welcome' }
    end
    get('/', {}, { 'HTTP_USER_AGENT' => 'foo' })
    assert !ran
    get('/foo', {}, { 'HTTP_USER_AGENT' => 'bar' })
    assert !ran
    get('/foo', {}, { 'HTTP_USER_AGENT' => 'foo' })
    assert ran
  end

  it 'only triggers provides condition if conforms with current Content-Type' do
    mock_app do
      before(:provides => :txt)  { @type = 'txt' }
      before(:provides => :html) { @type = 'html' }
      get('/') { @type }
    end

    get('/', {}, { 'HTTP_ACCEPT' => '*/*' })
    assert_body 'txt'
  end

  it 'can catch exceptions in after filters and handle them properly' do
    doodle = ''
    mock_app do
      after do
        doodle += ' and after'
        raise StandardError, "after"
      end
      get "/foo" do
        doodle = 'Been now'
        raise StandardError, "now"
      end
      get "/" do
        doodle = 'Been now'
      end
      error 500 do
        "Error handled #{env['sinatra.error'].message}"
      end
    end

    get '/foo'
    assert_equal 'Error handled now', body
    assert_equal 'Been now and after', doodle

    doodle = ''
    get '/'
    assert_equal 'Error handled after', body
    assert_equal 'Been now and after', doodle
  end
end

class AroundFilterTest < Minitest::Test
  it 'nests filters in superclass and definition order around the endpoint' do
    events = []
    base = Class.new(Sinatra::Base) do
      around do |continuation|
        events << :outer_enter
        continuation.call
        events << :outer_exit
      end
    end

    mock_app(base) do
      before { events << :before }
      around do |continuation|
        events << :inner_enter
        continuation.call
        events << :inner_exit
      end
      around do |continuation|
        events << :middle_enter
        continuation.call
        events << :middle_exit
      end
      get('/') { events << :endpoint; 'ok' }
      after { events << :after }
    end

    get '/'

    assert_equal 'ok', body
    expected_events = [
      :before, :outer_enter, :inner_enter, :middle_enter,
      :endpoint, :middle_exit, :inner_exit, :outer_exit, :after
    ]
    assert_equal expected_events, events
  end

  it 'passes path captures before the continuation' do
    captured = nil
    mock_app do
      around('/users/:id') do |id, continuation|
        captured = id
        continuation.call
      end
      get('/users/:id') { params.fetch('id', 'missing') }
    end

    get '/users/42'

    assert_equal '42', body
    assert_equal '42', captured
  end

  it 'keeps around path captures out of endpoint params' do
    mock_app do
      around('/users/:id') { |_id, continuation| continuation.call }
      get('/users/*') { params.fetch('id', 'missing') }
    end

    get '/users/42'

    assert_equal 'missing', body
  end

  it 'does not run around filters when serving static files' do
    ran_filter = false
    mock_app do
      around { |continuation| ran_filter = true; continuation.call }
      set :static, true
      set :public_folder, __dir__
    end

    get '/filter_test.rb'

    assert ok?
    assert_equal File.read(__FILE__), body
    assert !ran_filter
  end

  it 'runs cleanup when the endpoint uses halt' do
    events = []
    mock_app do
      around do |continuation|
        events << :enter
        continuation.call
        assert_equal 201, response.status
        events << :exit
      end
      get('/') do
        events << :endpoint
        halt 201, 'created'
      end
    end

    get '/'

    assert_equal 201, response.status
    assert_equal 'created', body
    assert_equal [:enter, :endpoint, :exit], events
  end

  it 'keeps nested cleanup ordered when routes pass' do
    events = []
    mock_app do
      around do |continuation|
        events << :enter
        continuation.call
        events << :exit
      end
      get('/') do
        events << :first
        pass
      end
      get('/') do
        events << :second
        'matched'
      end
    end

    get '/'

    assert_equal 'matched', body
    assert_equal [:enter, :first, :second, :exit], events
  end

  it 'runs cleanup and error handlers when the endpoint raises' do
    events = []
    mock_app do
      around do |continuation|
        events << :enter
        begin
          continuation.call
        ensure
          events << :exit
        end
      end
      get('/') { events << :endpoint; raise 'boom' }
      error(500) { 'handled' }
    end

    get '/'

    assert_equal 'handled', body
    assert_equal [:enter, :endpoint, :exit], events
  end

  it 'supports active short circuits while still running cleanup' do
    events = []
    mock_app do
      around do |continuation|
        events << :enter
        begin
          halt 403, 'blocked'
        ensure
          events << :exit
        end
      end
      get('/') { events << :endpoint; 'ok' }
    end

    get '/'

    assert_equal 403, response.status
    assert_equal 'blocked', body
    assert_equal [:enter, :exit], events
  end

  it 'only runs the endpoint once when the continuation is called twice' do
    events = []
    mock_app do
      around do |continuation|
        events << :enter
        begin
          continuation.call
          continuation.call
        ensure
          events << :exit
        end
      end
      get('/') { events << :endpoint; 'ok' }
      error(500) { 'handled' }
    end

    get '/'

    assert_equal 'handled', body
    assert_equal [:enter, :endpoint, :exit], events
  end
end
