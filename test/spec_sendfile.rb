# frozen_string_literal: true

require_relative 'helper'
require 'fileutils'
require 'tmpdir'

separate_testing do
  require_relative '../lib/rack/sendfile'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
end

describe Rack::Sendfile do
  def sendfile_body(filename = "rack_sendfile")
    FileUtils.touch File.join(Dir.tmpdir,  filename)
    res = ['Hello World']
    res.define_singleton_method(:to_path) { File.join(Dir.tmpdir,  filename) }
    res
  end

  def simple_app(body = sendfile_body)
    lambda { |env| [200, { 'content-type' => 'text/plain' }, body] }
  end

  def sendfile_app(body, mappings = [], variation = nil)
    Rack::Lint.new Rack::Sendfile.new(simple_app(body), variation, mappings)
  end

  def request(headers = {}, body = sendfile_body, mappings = [], variation = nil)
    yield Rack::MockRequest.new(sendfile_app(body, mappings, variation)).get('/', headers)
  end

  def open_file(path)
    Class.new(File) do
      unless method_defined?(:to_path)
        alias :to_path :path
      end
    end.open(path, 'wb+')
  end

  it "does nothing when no x-sendfile-type header present" do
    request do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-sendfile'
    end
  end

  it "does nothing and logs to rack.errors when incorrect x-sendfile-type header present" do
    io = StringIO.new
    # Configure with wrong variation type
    request({ 'rack.errors' => io }, sendfile_body, [], 'X-Banana') do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-sendfile'

      io.rewind
      io.read.must_equal "Unknown x-sendfile variation: \"X-Banana\"\n"
    end
  end

  it "sets x-sendfile response header and discards body" do
    request({}, sendfile_body, [], 'X-Sendfile') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-sendfile'].must_equal File.join(Dir.tmpdir,  "rack_sendfile")
    end
  end

  it "closes body when x-sendfile used" do
    body = sendfile_body
    closed = false
    body.define_singleton_method(:close){closed = true}
    request({}, body, [], 'X-Sendfile') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-sendfile'].must_equal File.join(Dir.tmpdir,  "rack_sendfile")
    end
    closed.must_equal true
  end

  it "sets x-lighttpd-send-file response header and discards body" do
    request({}, sendfile_body, [], 'X-Lighttpd-Send-File') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-lighttpd-send-file'].must_equal File.join(Dir.tmpdir,  "rack_sendfile")
    end
  end

  it "sets x-accel-redirect response header and discards body" do
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/foo/bar/"
    }
    request(headers, sendfile_body, [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/foo/bar/rack_sendfile'
    end
  end

  it "does not do a regexp substitution on the internal path" do
    tmpdir = Dir.tmpdir.dup
    tmpdir[1..2] = ".*"
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{tmpdir}/=/foo/bar/"
    }
    body = sendfile_body
    expected = Rack::Utils.escape_path(File.expand_path(body.to_path)).gsub('?', '%3F')
    request(headers, body, [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal expected
    end
  end

  it "sets x-accel-redirect response header to percent-encoded path" do
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/foo/bar%/"
    }
    request(headers, sendfile_body('file_with_%_?_symbol'), [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/foo/bar%25/file_with_%25_%3F_symbol'
    end
  end

  it 'writes to rack.error when no x-accel-mapping is specified' do
    request({}, sendfile_body, [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-accel-redirect'
      response.errors.must_include 'x-accel-mapping'
    end
  end

  it 'does nothing when body does not respond to #to_path' do
    request({}, ['Not a file...'], [], 'X-Sendfile') do |response|
      response.body.must_equal 'Not a file...'
      response.headers.wont_include 'x-sendfile'
    end
  end

  it "sets x-accel-redirect response header and discards body when initialized with multiple mappings" do
    begin
      dir1 = Dir.mktmpdir
      dir2 = Dir.mktmpdir

      first_body = open_file(File.join(dir1, 'rack_sendfile'))
      first_body.puts 'hello world'

      second_body = open_file(File.join(dir2, 'rack_sendfile'))
      second_body.puts 'goodbye world'

      mappings = [
        ["#{dir1}/", '/foo/bar/'],
        ["#{dir2}/", '/wibble/']
      ]

      request({}, first_body, mappings, 'X-Accel-Redirect') do |response|
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['content-length'].must_equal '0'
        response.headers['x-accel-redirect'].must_equal '/foo/bar/rack_sendfile'
      end

      request({}, second_body, mappings, 'X-Accel-Redirect') do |response|
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['content-length'].must_equal '0'
        response.headers['x-accel-redirect'].must_equal '/wibble/rack_sendfile'
      end
    ensure
      FileUtils.remove_entry_secure dir1
      FileUtils.remove_entry_secure dir2
    end
  end

  it "sets x-accel-redirect response header and discards body when initialized with multiple mappings via header" do
    begin
      dir1 = Dir.mktmpdir
      dir2 = Dir.mktmpdir
      dir3 = Dir.mktmpdir

      first_body = open_file(File.join(dir1, 'rack_sendfile'))
      first_body.puts 'hello world'

      second_body = open_file(File.join(dir2, 'rack_sendfile'))
      second_body.puts 'goodbye world'

      third_body = open_file(File.join(dir3, 'rack_sendfile'))
      third_body.puts 'hello again world'

      # Now we need to explicitly enable x-accel-redirect in the constructor
      app = Rack::Lint.new Rack::Sendfile.new(simple_app(first_body), "X-Accel-Redirect", [])
      
      headers = {
        'HTTP_X_ACCEL_MAPPING' => "#{dir1}/=/foo/bar/, #{dir2}/=/wibble/"
      }

      response = Rack::MockRequest.new(app).get('/', headers)
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/foo/bar/rack_sendfile'

      app = Rack::Lint.new Rack::Sendfile.new(simple_app(second_body), "X-Accel-Redirect", [])
      response = Rack::MockRequest.new(app).get('/', headers)
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/wibble/rack_sendfile'

      app = Rack::Lint.new Rack::Sendfile.new(simple_app(third_body), "X-Accel-Redirect", [])
      response = Rack::MockRequest.new(app).get('/', headers)
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal "#{dir3}/rack_sendfile"
    ensure
      FileUtils.remove_entry_secure dir1
      FileUtils.remove_entry_secure dir2
      FileUtils.remove_entry_secure dir3
    end
  end

  # Security tests for CVE mitigation
  describe "security: information disclosure prevention" do
    it "ignores HTTP_X_SENDFILE_TYPE header to prevent attacker-controlled sendfile activation" do
      # Attacker tries to enable x-sendfile via header
      request 'HTTP_X_SENDFILE_TYPE' => 'x-sendfile' do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-sendfile'
      end
    end

    it "ignores HTTP_X_SENDFILE_TYPE header attempting to enable x-accel-redirect" do
      # Attacker tries to enable x-accel-redirect via header with mapping
      headers = {
        'HTTP_X_SENDFILE_TYPE' => 'x-accel-redirect',
        'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/attacker/path/"
      }
      request headers do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "ignores HTTP_X_ACCEL_MAPPING when x-accel-redirect is not explicitly enabled" do
      # Even if attacker sends mapping header, it should be ignored without explicit config
      headers = {
        'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/attacker/path/"
      }
      request headers do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "ignores HTTP_X_ACCEL_MAPPING when application-level mappings are configured" do
      # When app provides mappings, header should be ignored for security
      begin
        dir = Dir.mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'test'
        
        app_mappings = [["#{dir}/", '/app/mapping/']]
        app = Rack::Lint.new Rack::Sendfile.new(simple_app(body), "X-Accel-Redirect", app_mappings)
        
        headers = {
          'HTTP_X_ACCEL_MAPPING' => "#{dir}/=/attacker/path/"
        }
        
        response = Rack::MockRequest.new(app).get('/', headers)
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['x-accel-redirect'].must_equal '/app/mapping/rack_sendfile'
        response.headers['x-accel-redirect'].wont_equal '/attacker/path/rack_sendfile'
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "allows HTTP_X_ACCEL_MAPPING only when x-accel-redirect explicitly enabled with no app mappings" do
      # This is the safe use case: explicit config + no app mappings = allow header
      begin
        dir = Dir.mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'test'
        
        app = Rack::Lint.new Rack::Sendfile.new(simple_app(body), "X-Accel-Redirect", [])
        
        headers = {
          'HTTP_X_ACCEL_MAPPING' => "#{dir}/=/safe/nginx/mapping/"
        }
        
        response = Rack::MockRequest.new(app).get('/', headers)
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['x-accel-redirect'].must_equal '/safe/nginx/mapping/rack_sendfile'
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "does not allow x-lighttpd-send-file activation via header" do
      # Verify other sendfile types also can't be enabled via headers
      request 'HTTP_X_SENDFILE_TYPE' => 'x-lighttpd-send-file' do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-lighttpd-send-file'
      end
    end

    it "requires explicit middleware configuration for any sendfile variation" do
      # Test that sendfile.type env var still works (internal, not from HTTP headers)
      body = sendfile_body
      app = lambda { |env| [200, { 'content-type' => 'text/plain' }, body] }
      middleware = Rack::Lint.new Rack::Sendfile.new(app)
      
      env = Rack::MockRequest.env_for('/', { 'sendfile.type' => 'x-sendfile' })
      status, headers = middleware.call(env)
      
      status.must_equal 200
      headers['x-sendfile'].must_equal File.join(Dir.tmpdir, "rack_sendfile")
      headers['content-length'].must_equal '0'
    end
  end

  describe "strict mapping mode" do
    # realpath(3) must be able to resolve these paths, so keep them inside
    # the repository instead of the system temp dir.
    def strict_mktmpdir
      root = File.expand_path('../tmp', __dir__)
      FileUtils.mkdir_p root
      Dir.mktmpdir('sendfile', root)
    end

    def strict_app(body, mappings, variation = 'X-Accel-Redirect', on_miss: :fallback)
      Rack::Lint.new Rack::Sendfile.new(simple_app(body), variation, mappings, strict: true, on_miss: on_miss)
    end

    def strict_request(body, mappings, headers = {}, variation = 'X-Accel-Redirect', on_miss: :fallback)
      yield Rack::MockRequest.new(strict_app(body, mappings, variation, on_miss: on_miss)).get('/', headers)
    end

    it "maps files under a declared root to the internal URI prefix" do
      begin
        dir = strict_mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'hello world'

        strict_request(body, [[dir, '/files/']]) do |response|
          response.must_be :ok?
          response.body.must_be :empty?
          response.headers['content-length'].must_equal '0'
          response.headers['x-accel-redirect'].must_equal '/files/rack_sendfile'
        end
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "resolves symlinks in the declared root itself" do
      begin
        real_dir = strict_mktmpdir
        link_dir = File.join(strict_mktmpdir, 'link')
        File.symlink real_dir, link_dir
        body = open_file(File.join(real_dir, 'rack_sendfile'))
        body.puts 'hello world'

        strict_request(body, [[link_dir, '/files/']]) do |response|
          response.must_be :ok?
          response.headers['x-accel-redirect'].must_equal '/files/rack_sendfile'
        end
      ensure
        FileUtils.remove_entry_secure real_dir
        FileUtils.remove_entry_secure File.dirname(link_dir)
      end
    end

    it "refuses symlinks that escape the declared root" do
      begin
        root = strict_mktmpdir
        outside = strict_mktmpdir
        secret = File.join(outside, 'secret')
        FileUtils.touch secret
        File.symlink secret, File.join(root, 'leaked')

        body = open_file(File.join(root, 'leaked'))
        closed = false
        body.define_singleton_method(:close) { closed = true }

        strict_request(body, [[root, '/files/']], on_miss: :reject) do |response|
          response.status.must_equal 403
          response.headers.wont_include 'x-accel-redirect'
        end
        closed.must_equal true
      ensure
        FileUtils.remove_entry_secure root
        FileUtils.remove_entry_secure outside
      end
    end

    it "does not match sibling directories sharing a name prefix" do
      begin
        parent = strict_mktmpdir
        root = File.join(parent, 'files')
        evil = File.join(parent, 'files-evil')
        FileUtils.mkdir root
        FileUtils.mkdir evil
        body = open_file(File.join(evil, 'rack_sendfile'))
        body.puts 'sneaky'
        body.rewind

        strict_request(body, [[root, '/files/']]) do |response|
          response.must_be :ok?
          response.body.must_equal "sneaky\n"
          response.headers.wont_include 'x-accel-redirect'
        end
      ensure
        FileUtils.remove_entry_secure parent
      end
    end

    it "percent-encodes non-ASCII, spaces and percent signs exactly once" do
      begin
        dir = strict_mktmpdir
        # Literal '%20' in the name must become '%2520', proving the path is
        # never decoded before being encoded.
        name = "报告 final%20.txt"
        body = open_file(File.join(dir, name))
        body.puts 'hello world'

        strict_request(body, [[dir, '/files/']]) do |response|
          response.must_be :ok?
          response.headers['x-accel-redirect'].must_equal '/files/%E6%8A%A5%E5%91%8A%20final%2520.txt'
        end
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "never emits a header containing control characters" do
      begin
        dir = strict_mktmpdir
        body = open_file(File.join(dir, "rack\nsendfile"))
        body.puts 'hello world'

        strict_request(body, [[dir, '/files/']], on_miss: :reject) do |response|
          response.status.must_equal 403
          response.headers.each_value { |v| v.wont_match(/[\r\n]/) }
        end
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "ignores the x-accel-mapping request header" do
      begin
        dir = strict_mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'hello world'

        headers = { 'HTTP_X_ACCEL_MAPPING' => "#{dir}/=/attacker/".b }
        strict_request(body, [[dir, '/files/']], headers) do |response|
          response.must_be :ok?
          response.headers['x-accel-redirect'].must_equal '/files/rack_sendfile'
        end
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "falls back to serving the body on miss when on_miss is :fallback" do
      begin
        root = strict_mktmpdir
        outside = strict_mktmpdir
        body = open_file(File.join(outside, 'rack_sendfile'))
        body.puts 'hello world'
        body.rewind

        io = StringIO.new
        strict_request(body, [[root, '/files/']], { 'rack.errors' => io }) do |response|
          response.must_be :ok?
          response.body.must_equal "hello world\n"
          response.headers.wont_include 'x-accel-redirect'
        end
        io.rewind
        io.read.must_include 'not under any declared root'
      ensure
        FileUtils.remove_entry_secure root
        FileUtils.remove_entry_secure outside
      end
    end

    it "rejects with 403 and closes the body on miss when on_miss is :reject" do
      begin
        root = strict_mktmpdir
        outside = strict_mktmpdir
        body = open_file(File.join(outside, 'rack_sendfile'))
        body.puts 'hello world'
        closed = false
        body.define_singleton_method(:close) { closed = true }

        strict_request(body, [[root, '/files/']], on_miss: :reject) do |response|
          response.status.must_equal 403
          response.body.must_equal "Forbidden\n"
          response.headers.wont_include 'x-accel-redirect'
        end
        closed.must_equal true
      ensure
        FileUtils.remove_entry_secure root
        FileUtils.remove_entry_secure outside
      end
    end

    it "raises ArgumentError for an unknown on_miss action" do
      lambda do
        Rack::Sendfile.new(simple_app, 'X-Accel-Redirect', [], strict: true, on_miss: :explode)
      end.must_raise ArgumentError
    end

    it "restricts x-sendfile to declared roots in strict mode" do
      begin
        root = strict_mktmpdir
        outside = strict_mktmpdir

        allowed = open_file(File.join(root, 'rack_sendfile'))
        allowed.puts 'hello world'
        strict_request(allowed, [[root, '/files/']], {}, 'X-Sendfile') do |response|
          response.must_be :ok?
          response.headers['x-sendfile'].must_equal File.realpath(File.join(root, 'rack_sendfile')).b
        end

        denied = open_file(File.join(outside, 'rack_sendfile'))
        denied.puts 'hello world'
        strict_request(denied, [[root, '/files/']], {}, 'X-Sendfile', on_miss: :reject) do |response|
          response.status.must_equal 403
          response.headers.wont_include 'x-sendfile'
        end
      ensure
        FileUtils.remove_entry_secure root
        FileUtils.remove_entry_secure outside
      end
    end

    it "closes the original body once the mapped response is closed" do
      begin
        dir = strict_mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'hello world'
        closed = false
        body.define_singleton_method(:close) { closed = true }

        strict_request(body, [[dir, '/files/']]) do |response|
          response.must_be :ok?
          response.headers['x-accel-redirect'].must_equal '/files/rack_sendfile'
        end
        closed.must_equal true
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "handles bodies whose path encoding differs from the configured root" do
      begin
        dir = strict_mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'hello world'
        body.define_singleton_method(:to_path) { File.join(dir, 'rack_sendfile').b }

        strict_request(body, [[dir, '/files/']]) do |response|
          response.must_be :ok?
          response.headers['x-accel-redirect'].must_equal '/files/rack_sendfile'
        end
      ensure
        FileUtils.remove_entry_secure dir
      end
    end
  end
end
