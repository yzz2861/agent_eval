# frozen_string_literal: true

require_relative 'helper'
require 'fileutils'
require 'tmpdir'

separate_testing do
  require_relative '../lib/rack/sendfile'
  require_relative '../lib/rack/files'
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

  describe "strict x-accel mappings" do
    def strict_app(app, mappings, on_unmatched)
      Rack::Lint.new(
        raw_strict_app(app, mappings, on_unmatched)
      )
    end

    def raw_strict_app(app, mappings, on_unmatched)
      Rack::Sendfile.new(
        app,
        'X-Accel-Redirect',
        mappings,
        strict_mappings: true,
        on_unmatched: on_unmatched
      )
    end

    def path_body(path, content = 'Hello World')
      body = [content]
      body.define_singleton_method(:to_path) { path }
      body
    end

    def strict_tmpdir(&block)
      Dir.mktmpdir('sendfile', File.expand_path('tmp', __dir__), &block)
    end

    it "maps an ordinary Rack::Files download and rejects links outside the root" do
      strict_tmpdir do |root|
        File.write(File.join(root, 'ordinary.txt'), 'safe download')

        outside = strict_tmpdir
        secret = File.join(outside, 'secret.txt')
        File.write(secret, 'secret download')
        File.symlink(secret, File.join(root, 'outside-link.txt'))

        app = strict_app(Rack::Files.new(root), [[root, '/downloads/']], :reject)
        request_headers = { 'HTTP_X_ACCEL_MAPPING' => "#{outside}=/attacker/".b }
        begin
          response = Rack::MockRequest.new(app).get('/ordinary.txt', request_headers)
          response.must_be :ok?
          response.body.must_be :empty?
          response.headers['content-length'].must_equal '0'
          response.headers['x-accel-redirect'].must_equal '/downloads/ordinary.txt'

          response = Rack::MockRequest.new(app).get('/outside-link.txt', request_headers)
          response.status.must_equal 403
          response.body.must_be :empty?
          response.headers.wont_include 'x-accel-redirect'
        ensure
          FileUtils.remove_entry_secure outside
        end
      end
    end

    it "uses the real path of a symlink inside an allowed directory" do
      strict_tmpdir do |root|
        FileUtils.mkdir_p(File.join(root, 'nested'))
        target = File.join(root, 'nested', 'target.txt')
        File.write(target, 'inside target')
        link = File.join(root, 'link.txt')
        File.symlink(target, link)

        app = strict_app(simple_app(path_body(link)), [[root, '/downloads/']], :reject)
        response = Rack::MockRequest.new(app).get('/')

        response.must_be :ok?
        response.headers['x-accel-redirect'].must_equal '/downloads/nested/target.txt'
      end
    end

    it "uses the real directory when a configured root is itself a symlink" do
      strict_tmpdir do |base|
        real_root = File.join(base, 'real-root')
        linked_root = File.join(base, 'linked-root')
        FileUtils.mkdir_p(real_root)
        File.symlink(real_root, linked_root)
        file = File.join(real_root, 'file.txt')
        File.write(file, 'content')

        app = strict_app(simple_app(path_body(file)), [[linked_root, '/downloads/']], :reject)
        response = Rack::MockRequest.new(app).get('/')

        response.headers['x-accel-redirect'].must_equal '/downloads/file.txt'
      end
    end

    it "supports the filesystem root prefix without adding an extra slash" do
      strict_tmpdir do |root|
        file = File.join(root, 'file.txt')
        File.write(file, 'content')
        app = strict_app(simple_app(path_body(file)), [['/', '/']], :reject)
        response = Rack::MockRequest.new(app).get('/')

        response.headers['x-accel-redirect'].must_equal(
          '/' + Rack::Utils.escape_path(file.delete_prefix('/')).gsub('?', '%3F')
        )
      end
    end

    it "does not allow request mappings to expand the configured roots" do
      strict_tmpdir do |root|
        strict_tmpdir do |outside|
          file = File.join(outside, 'secret.txt')
          File.write(file, 'secret')
          app = strict_app(simple_app(path_body(file)), [[root, '/downloads/']], :reject)

          response = Rack::MockRequest.new(app).get(
            '/',
            'HTTP_X_ACCEL_MAPPING' => "#{outside}=/attacker/".b
          )

          response.status.must_equal 403
          response.headers.wont_include 'x-accel-redirect'
        end
      end
    end

    it "respects directory boundaries and nested roots" do
      strict_tmpdir do |base|
        root = File.join(base, 'files')
        nested = File.join(root, 'nested')
        sibling = File.join(base, 'files-secret')
        FileUtils.mkdir_p(nested)
        FileUtils.mkdir_p(sibling)

        mappings = [[root, '/files/'], [nested, '/nested/']]
        root_file = File.join(root, 'root.txt')
        nested_file = File.join(nested, 'child.txt')
        sibling_file = File.join(sibling, 'child.txt')
        File.write(root_file, 'root')
        File.write(nested_file, 'nested')
        File.write(sibling_file, 'sibling')

        response = Rack::MockRequest.new(strict_app(simple_app(path_body(root_file)), mappings, :reject)).get('/')
        response.headers['x-accel-redirect'].must_equal '/files/root.txt'

        response = Rack::MockRequest.new(strict_app(simple_app(path_body(nested_file)), mappings, :reject)).get('/')
        response.headers['x-accel-redirect'].must_equal '/nested/child.txt'

        response = Rack::MockRequest.new(strict_app(simple_app(path_body(sibling_file)), mappings, :reject)).get('/')
        response.status.must_equal 403
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "encodes file names once and leaves a valid encoded URI prefix unchanged" do
      strict_tmpdir do |root|
        names = {
          '中文 文件%.txt' => '/downloads/%E4%B8%AD%E6%96%87%20%E6%96%87%E4%BB%B6%25.txt',
          "line\nbreak.txt" => '/downloads/line%0Abreak.txt',
          '%2e%2e' => '/downloads/%252e%252e'
        }

        names.each do |name, expected|
          path = File.join(root, name)
          File.write(path, 'content')
          app = strict_app(simple_app(path_body(path)), [[root, '/downloads/']], :reject)
          response = Rack::MockRequest.new(app).get('/')

          response.headers['x-accel-redirect'].must_equal expected
          response.headers['x-accel-redirect'].wont_match(/[\r\n]/)
        end

        path = File.join(root, 'percent.txt')
        File.write(path, 'content')
        app = strict_app(simple_app(path_body(path)), [[root, '/down%20loads/']], :reject)
        response = Rack::MockRequest.new(app).get('/')

        response.headers['x-accel-redirect'].must_equal '/down%20loads/percent.txt'
      end
    end

    it "falls back without closing the body when no root matches" do
      strict_tmpdir do |root|
        strict_tmpdir do |outside|
          path = File.join(outside, 'secret.txt')
          File.write(path, 'secret')
          body = path_body(path)
          closed = false
          body.define_singleton_method(:close) { closed = true }

          app = raw_strict_app(simple_app(body), [[root, '/downloads/']], :fallback)
          status, headers, returned_body = app.call(Rack::MockRequest.env_for('/'))

          status.must_equal 200
          returned_body.must_equal body
          headers.wont_include 'x-accel-redirect'
          headers.wont_include 'content-length'
          closed.must_equal false
          body.close
        end
      end
    end

    it "closes the original body after delegating or rejecting" do
      strict_tmpdir do |root|
        strict_tmpdir do |outside|
          inside = File.join(root, 'inside.txt')
          secret = File.join(outside, 'secret.txt')
          File.write(inside, 'inside')
          File.write(secret, 'secret')

          body = path_body(inside)
          closed = false
          body.define_singleton_method(:close) { closed = true }
          app = strict_app(simple_app(body), [[root, '/downloads/']], :reject)
          Rack::MockRequest.new(app).get('/')
          closed.must_equal true

          body = path_body(secret)
          closed = false
          body.define_singleton_method(:close) { closed = true }
          app = strict_app(simple_app(body), [[root, '/downloads/']], :reject)
          Rack::MockRequest.new(app).get('/')
          closed.must_equal true
        end
      end
    end

    it "rejects files whose path cannot be represented as a real file" do
      strict_tmpdir do |root|
        body = path_body("#{root}/bad\0name.txt")
        app = strict_app(simple_app(body), [[root, '/downloads/']], :reject)
        response = Rack::MockRequest.new(app).get('/')

        response.status.must_equal 403
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "rejects bodies whose to_path does not return a path" do
      strict_tmpdir do |root|
        body = []
        body.define_singleton_method(:to_path) { nil }
        app = strict_app(simple_app(body), [[root, '/downloads/']], :reject)
        response = Rack::MockRequest.new(app).get('/')

        response.status.must_equal 403
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "requires explicit safe configuration" do
      strict_tmpdir do |root|
        proc do
          Rack::Sendfile.new(simple_app, 'X-Accel-Redirect', [[root, '/downloads/']], strict_mappings: true)
        end.must_raise ArgumentError

        proc do
          Rack::Sendfile.new(simple_app, 'X-Accel-Redirect', [], strict_mappings: true, on_unmatched: :reject)
        end.must_raise ArgumentError

        proc do
          Rack::Sendfile.new(
            simple_app,
            'X-Sendfile',
            [[root, '/downloads/']],
            strict_mappings: true,
            on_unmatched: :reject
          )
        end.must_raise ArgumentError

        proc do
          Rack::Sendfile.new(
            simple_app,
            'X-Accel-Redirect',
            [[root, "/down\nloads/"]],
            strict_mappings: true,
            on_unmatched: :reject
          )
        end.must_raise ArgumentError

        proc do
          Rack::Sendfile.new(
            simple_app,
            'X-Accel-Redirect',
            [[root, '/downloads/../files/']],
            strict_mappings: true,
            on_unmatched: :reject
          )
        end.must_raise ArgumentError

        proc do
          Rack::Sendfile.new(
            simple_app,
            'X-Accel-Redirect',
            [[root, '/down%2floads/']],
            strict_mappings: true,
            on_unmatched: :reject
          )
        end.must_raise ArgumentError
      end
    end

    it "uses x-accel-redirect when strict mappings are enabled without a variation" do
      strict_tmpdir do |root|
        file = File.join(root, 'file.txt')
        File.write(file, 'content')
        middleware = Rack::Sendfile.new(
          simple_app(path_body(file)),
          nil,
          [[root, '/downloads/']],
          strict_mappings: true,
          on_unmatched: :reject
        )
        response = Rack::MockRequest.new(Rack::Lint.new(middleware)).get('/')

        response.headers['x-accel-redirect'].must_equal '/downloads/file.txt'
      end
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
end
