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
  it "wraps the route handler between before and after filters" do
    events = []
    mock_app do
      before  { events << :before }
      around do |app|
        events << :enter
        app.call
        events << :exit
      end
      get('/') { events << :endpoint; 'hello' }
      after   { events << :after }
    end

    get '/'
    assert ok?
    assert_equal 'hello', body
    assert_equal [:before, :enter, :endpoint, :exit, :after], events
  end

  it "nests multiple around filters in the order defined" do
    events = []
    mock_app do
      around do |app|
        events << :outer_enter
        app.call
        events << :outer_exit
      end
      around do |app|
        events << :inner_enter
        app.call
        events << :inner_exit
      end
      get('/') { events << :endpoint; 'hello' }
    end

    get '/'
    assert ok?
    assert_equal [:outer_enter, :inner_enter, :endpoint, :inner_exit, :outer_exit], events
  end

  it "nests superclass filters outside subclass filters" do
    events = []
    parent = Class.new(Sinatra::Base) do
      around do |app|
        events << :parent_enter
        app.call
        events << :parent_exit
      end
    end
    mock_app(parent) do
      around do |app|
        events << :child_enter
        app.call
        events << :child_exit
      end
      get('/') { events << :endpoint; 'hello' }
    end

    get '/'
    assert ok?
    assert_equal [:parent_enter, :child_enter, :endpoint, :child_exit, :parent_exit], events
  end

  it "only wraps routes matching the filter path" do
    events = []
    mock_app do
      around('/wrapped') do |app|
        events << :enter
        app.call
        events << :exit
      end
      get('/wrapped')   { events << :endpoint; 'wrapped' }
      get('/unwrapped') { events << :endpoint; 'unwrapped' }
    end

    get '/wrapped'
    assert_equal 'wrapped', body
    assert_equal [:enter, :endpoint, :exit], events

    events.clear
    get '/unwrapped'
    assert_equal 'unwrapped', body
    assert_equal [:endpoint], events
  end

  it "runs cleanup when the endpoint halts and still applies the halted response" do
    events = []
    mock_app do
      around do |app|
        events << :enter
        begin
          app.call
        ensure
          events << :exit
        end
      end
      get('/') { halt 418, 'teapot' }
    end

    get '/'
    assert_equal 418, response.status
    assert_equal 'teapot', body
    assert_equal [:enter, :exit], events
  end

  it "runs code after the continuation when the endpoint halts" do
    events = []
    mock_app do
      around do |app|
        events << :enter
        app.call
        events << :exit
      end
      get('/') { halt 200, 'halted' }
    end

    get '/'
    assert ok?
    assert_equal 'halted', body
    assert_equal [:enter, :exit], events
  end

  it "keeps the chain intact when the endpoint passes to the next route" do
    events = []
    mock_app do
      around do |app|
        events << :enter
        app.call
        events << :exit
      end
      get('/') { pass }
      get('/') { events << :endpoint; 'second' }
    end

    get '/'
    assert ok?
    assert_equal 'second', body
    assert_equal [:enter, :endpoint, :exit], events
  end

  it "runs cleanup when the endpoint raises" do
    events = []
    mock_app do
      around do |app|
        events << :enter
        begin
          app.call
        ensure
          events << :exit
        end
      end
      get('/') { raise 'boom' }
      error(500) { 'handled' }
    end

    get '/'
    assert_equal 500, response.status
    assert_equal 'handled', body
    assert_equal [:enter, :exit], events
  end

  it "allows a filter to short-circuit without calling the continuation" do
    events = []
    mock_app do
      around do |app|
        events << :outer_enter
        app.call
        events << :outer_exit
      end
      around do |_app|
        events << :inner
        body 'short-circuited'
      end
      get('/') { events << :endpoint; 'nope' }
    end

    get '/'
    assert ok?
    assert_equal 'short-circuited', body
    assert_equal [:outer_enter, :inner, :outer_exit], events
  end

  it "allows a filter to halt the request without calling the continuation" do
    events = []
    mock_app do
      around do |app|
        events << :enter
        halt 401, 'unauthorized' unless params[:token]
        app.call
        events << :exit
      end
      get('/') { events << :endpoint; 'secret' }
    end

    get '/'
    assert_equal 401, response.status
    assert_equal 'unauthorized', body
    assert_equal [:enter], events

    events.clear
    get '/', token: '1'
    assert ok?
    assert_equal 'secret', body
    assert_equal [:enter, :endpoint, :exit], events
  end

  it "runs outer filter cleanup when an inner filter halts" do
    events = []
    mock_app do
      around do |app|
        events << :outer_enter
        app.call
        events << :outer_exit
      end
      around { |_app| halt 403, 'forbidden' }
      get('/') { events << :endpoint; 'nope' }
    end

    get '/'
    assert_equal 403, response.status
    assert_equal 'forbidden', body
    assert_equal [:outer_enter, :outer_exit], events
  end

  it "raises when the continuation is called more than once" do
    mock_app do
      around do |app|
        app.call
        app.call
      end
      get('/') { 'hello' }
      error(500) { env['sinatra.error'].message }
    end

    get '/'
    assert_equal 500, response.status
    assert_match 'more than once', body
  end

  it "shares the request context with the route handler" do
    mock_app do
      around do |app|
        @resource = 'open'
        app.call
        @resource = 'closed'
      end
      get('/') { @resource }
    end

    get '/'
    assert ok?
    assert_equal 'open', body
  end
end
