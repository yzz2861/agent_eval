# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/files'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
end

describe Rack::Files do
  DOCROOT = File.expand_path(File.dirname(__FILE__)) unless defined? DOCROOT

  def files(*args)
    Rack::Lint.new Rack::Files.new(*args)
  end

  it "can be used without root" do
    # https://github.com/rack/rack/issues/1464

    app = Rack::Files.new(nil)

    request = Rack::Request.new(
      Rack::MockRequest.env_for("/cgi/test")
    )

    file_path = File.expand_path("cgi/test", __dir__)
    assert_equal 200, app.serving(request, file_path)[0]
  end

  it 'serves files with + in the file name' do
    Dir.mktmpdir do |dir|
      File.write File.join(dir, "you+me.txt"), "hello world"
      app = files(dir)
      env = Rack::MockRequest.env_for("/you+me.txt")
      status, _, body = app.call env

      assert_equal 200, status

      str = ''.dup
      body.each { |x| str << x }
      assert_match "hello world", str
    end
  end

  it "serves the correct file content for a GET request" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/test")

    res.must_be :ok?
    assert_match(res, /ruby/)
  end

  it "does not serve directories" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/assets")
    res.status.must_equal 404
  end

  it "sets the last-modified header" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/test")

    path = File.join(DOCROOT, "/cgi/test")

    res.must_be :ok?
    res["last-modified"].must_equal File.mtime(path).httpdate
  end

  it "returns 304 if file isn't modified since last serve" do
    path = File.join(DOCROOT, "/cgi/test")
    res = Rack::MockRequest.new(files(DOCROOT)).
      get("/cgi/test", 'HTTP_IF_MODIFIED_SINCE' => File.mtime(path).httpdate)

    res.status.must_equal 304
    res.body.must_be :empty?
  end

  it "returns the file if it has been modified since last serve" do
    path = File.join(DOCROOT, "/cgi/test")
    res = Rack::MockRequest.new(files(DOCROOT)).
      get("/cgi/test", 'HTTP_IF_MODIFIED_SINCE' => (File.mtime(path) - 100).httpdate)

    res.must_be :ok?
  end

  it "serves files with URL encoded filenames" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/%74%65%73%74") # "/cgi/test"

    res.must_be :ok?
    # res.must_match(/ruby/)    # nope
    # (/ruby/).must_match res   # This is weird, but an oddity of minitest
    # assert_match(/ruby/, res) # nope
    assert_match(res, /ruby/)
  end

  it "serves uri with URL encoded null byte (%00) in filenames" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/test%00")
    res.must_be :bad_request?
  end

  it "allows safe directory traversal" do
    req = Rack::MockRequest.new(files(DOCROOT))

    res = req.get('/cgi/../cgi/test')
    res.must_be :successful?

    res = req.get('.')
    res.must_be :not_found?

    res = req.get("test/..")
    res.must_be :not_found?
  end

  it "does not allow unsafe directory traversal" do
    req = Rack::MockRequest.new(files(DOCROOT))

    res = req.get("/../README.rdoc")
    res.must_be :client_error?

    res = req.get("../test/spec_file.rb")
    res.must_be :client_error?

    res = req.get("../README.rdoc")
    res.must_be :client_error?

    res.must_be :not_found?
  end

  it "allows files with .. in their name" do
    req = Rack::MockRequest.new(files(DOCROOT))
    res = req.get("/cgi/..test")
    res.must_be :not_found?

    res = req.get("/cgi/test..")
    res.must_be :not_found?

    res = req.get("/cgi../test..")
    res.must_be :not_found?
  end

  it "does not allow unsafe directory traversal with encoded periods" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/%2E%2E/README")

    res.must_be :client_error?
    res.must_be :not_found?
  end

  it "allows safe directory traversal with encoded periods" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/%2E%2E/cgi/test")

    res.must_be :successful?
  end

  it "returns 404 if it can't find the file" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi/blubb")

    res.must_be :not_found?
  end

  it "uses bytesize not size for Content-Length in error responses with multibyte UTF-8" do
    app = Rack::Files.new(DOCROOT)

    # Create env directly with UTF-8 encoded PATH_INFO (not ASCII-8BIT like MockRequest forces):
    env = {
      "REQUEST_METHOD" => "GET",
      "PATH_INFO" => "/cgi/caf%C3%A9", # URL-encoded "café"
      "SCRIPT_NAME" => "",
      "QUERY_STRING" => "",
      "SERVER_NAME" => "example.org",
      "SERVER_PORT" => "80",
      "rack.url_scheme" => "http",
      "rack.input" => StringIO.new,
      "rack.errors" => StringIO.new
    }

    # Verify PATH_INFO is UTF-8:
    assert_equal Encoding::UTF_8, env["PATH_INFO"].encoding

    status, headers, body = app.call(env)

    # Should be 404 not found:
    assert_equal 404, status

    # Extract body content:
    body_str = String.new
    body.each { |part| body_str << part }

    # The body "File not found: /cgi/café\n" has 26 chars but 27 bytes:
    assert_equal 26, body_str.size      # character count
    assert_equal 27, body_str.bytesize  # byte count

    # Content-Length must be 27 (bytes), not 26 (characters):
    # (This will FAIL if using .size instead of .bytesize)
    headers["content-length"].must_equal "27"
  end

  it "detects SystemCallErrors" do
    res = Rack::MockRequest.new(files(DOCROOT)).get("/cgi")

    res.must_be :not_found?
  end

  it "returns bodies that respond to #to_path" do
    env = Rack::MockRequest.env_for("/cgi/test")
    status, _, body = Rack::Files.new(DOCROOT).call(env)

    path = File.join(DOCROOT, "/cgi/test")

    status.must_equal 200
    body.must_respond_to :to_path
    body.to_path.must_equal path
  end

  it "returns bodies that do not respond to #to_path if a byte range is requested" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=22-33"
    status, _, body = Rack::Files.new(DOCROOT).call(env)

    status.must_equal 206
    body.wont_respond_to :to_path
  end

  it "returns correct byte range in body" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=22-33"
    res = Rack::MockResponse.new(*files(DOCROOT).call(env))

    res.status.must_equal 206
    res["content-length"].must_equal "12"
    res["content-range"].must_equal "bytes 22-33/209"
    res.body.must_equal "IS FILE! ***"
  end

  it "handles cases where the file is truncated during request" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=0-3300"
    files = Class.new(Rack::Files) do
      def filesize(_); 10000 end
    end.new(DOCROOT)

    res = Rack::MockResponse.new(*files.call(env))
    res.status.must_equal 206
    res.length.must_equal 209
    res.finish

    res["content-length"].must_equal "209"
    res["content-range"].must_equal "bytes 0-3300/10000"
  end

  it "returns correct multiple byte ranges in body" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=22-33, 60-80"
    res = Rack::MockResponse.new(*files(DOCROOT).call(env))

    res.status.must_equal 206
    res["content-length"].must_equal "191"
    res["content-type"].must_equal "multipart/byteranges; boundary=AaB03x"
    expected_body = <<-EOF
\r
--AaB03x\r
content-type: text/plain\r
content-range: bytes 22-33/209\r
\r
IS FILE! ***\r
--AaB03x\r
content-type: text/plain\r
content-range: bytes 60-80/209\r
\r
, tests will break!!!\r
--AaB03x--\r
    EOF

    res.body.must_equal expected_body
  end

  it "returns 416 error and correct Content-Range for unsatisfiable byte range" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=1234-5678"
    res = Rack::MockResponse.new(*files(DOCROOT).call(env))

    res.status.must_equal 416
    res["content-range"].must_equal "bytes */209"
  end

  it "ignores range when file size is 0 bytes" do
    env = Rack::MockRequest.env_for("/cgi/assets/images/favicon.ico")
    env["HTTP_RANGE"] = "bytes=0-1234"
    res = Rack::MockResponse.new(*files(DOCROOT).call(env))

    res.status.must_equal 200
    res["content-range"].must_be_nil
  end

  it "supports custom http headers" do
    env = Rack::MockRequest.env_for("/cgi/test")
    status, heads, _ = files(DOCROOT, 'cache-control' => 'public, max-age=38',
     'access-control-allow-origin' => '*').call(env)

    status.must_equal 200
    heads['cache-control'].must_equal 'public, max-age=38'
    heads['access-control-allow-origin'].must_equal '*'
  end

  it "allows customizing the way http header's are set" do
    env = Rack::MockRequest.env_for("/cgi/test")
    custom_files = Class.new(Rack::Files) do
      def assign_headers(headers, request)
        request.must_be_instance_of Rack::Request
        headers.merge!(@headers.invert)
      end
    end

    status, heads, _ = Rack::Lint.new(custom_files.new(DOCROOT, 'left' => 'right')).call(env)

    status.must_equal 200
    heads['right'].must_equal 'left'
  end

  it "does not add custom HTTP headers when none are supplied" do
    env = Rack::MockRequest.env_for("/cgi/test")
    status, heads, _ = files(DOCROOT).call(env)

    status.must_equal 200
    heads['cache-control'].must_be_nil
    heads['access-control-allow-origin'].must_be_nil
  end

  it "only supports GET, HEAD, and OPTIONS requests" do
    req = Rack::MockRequest.new(files(DOCROOT))

    forbidden = %w[post put patch delete]
    forbidden.each do |method|
      res = req.send(method, "/cgi/test")
      res.must_be :client_error?
      res.must_be :method_not_allowed?
      res.headers['allow'].split(/, */).sort.must_equal %w(GET HEAD OPTIONS)
    end

    allowed = %w[get head options]
    allowed.each do |method|
      res = req.send(method, "/cgi/test")
      res.must_be :successful?
    end
  end

  it "sets Allow correctly for OPTIONS requests" do
    req = Rack::MockRequest.new(files(DOCROOT))
    res = req.options('/cgi/test')
    res.must_be :successful?
    res.headers['allow'].wont_equal nil
    res.headers['allow'].split(/, */).sort.must_equal %w(GET HEAD OPTIONS)
  end

  it "sets content-length correctly for HEAD requests" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::Files.new(DOCROOT)))
    res = req.head "/cgi/test"
    res.must_be :successful?
    res['content-length'].must_equal "209"
  end

  it "defaults to a MIME type of text/plain" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::Files.new(DOCROOT)))
    res = req.get "/cgi/test"
    res.must_be :successful?
    res['content-type'].must_equal "text/plain"
  end

  it "allows the default MIME type to be set" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::Files.new(DOCROOT, nil, 'application/octet-stream')))
    res = req.get "/cgi/test"
    res.must_be :successful?
    res['content-type'].must_equal "application/octet-stream"
  end

  it "does not set the content-type header if the MIME type is not specified" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::Files.new(DOCROOT, nil, nil)))
    res = req.get "/cgi/test"
    res.must_be :successful?
    res['content-type'].must_be_nil
  end

  it "returns 404 and empty body for a HEAD request when the file is not found" do
    res = Rack::MockRequest.new(files(DOCROOT)).head("/cgi/missing")
    res.must_be :not_found?
    res.body.must_be :empty?
  end

  if defined?(Ractor)
    it "can be made ractor shareable" do
      files = Rack::Files.new(DOCROOT)

      Ractor.make_shareable(files)

      assert Ractor.shareable?(files)
    end
  end

  describe "version-pinned file serving" do
    def atomically_replace(path, contents)
      tmp = "#{path}.#{Process.pid}.#{Thread.current.object_id}.tmp"
      File.write(tmp, contents)
      File.rename(tmp, path)
    end

    def open_file_paths
      # Snapshot of currently open File descriptors, used to assert that a
      # request does not leave any newly opened file handle behind.
      GC.start
      ObjectSpace.each_object(File).filter_map do |file|
        file.path unless file.closed?
      rescue StandardError
        nil
      end
    end

    it "returns a pinned flag from the constructor" do
      files = Rack::Files.new(DOCROOT, {}, 'text/plain', true)
      assert files.pinned

      files = Rack::Files.new(DOCROOT)
      refute files.pinned
    end

    it "streams the original file contents when the path is atomically replaced after the response is built" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        app = Rack::Lint.new(Rack::Files.new(dir, {}, 'text/plain', true))

        status, headers, body = app.call(Rack::MockRequest.env_for("/asset.txt"))

        # Replace the file (temp file + rename) before the body is iterated:
        atomically_replace(path, "brand new, much longer contents")

        sent = +""
        body.each { |chunk| sent << chunk }
        body.close

        assert_equal 200, status
        assert_equal "old contents", sent
        # Headers describe the original version, not the replacement:
        assert_equal "12", headers[Rack::CONTENT_LENGTH]
        refute body.respond_to?(:to_path)
      end
    end

    it "does not expose #to_path so Sendfile cannot re-open the replaced path" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir, {}, 'text/plain', true)

        _, _, body = files.call(Rack::MockRequest.env_for("/asset.txt"))
        refute body.respond_to?(:to_path)
        body.close
      end
    end

    it "sends a single byte range of the pinned version after replacement" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        app = Rack::Lint.new(Rack::Files.new(dir, {}, 'text/plain', true))

        env = Rack::MockRequest.env_for("/asset.txt", "HTTP_RANGE" => "bytes=4-11")
        status, headers, body = app.call(env)
        atomically_replace(path, "xxxxxxxxxxxxxxxxxxxxxxxx")

        sent = +""
        body.each { |chunk| sent << chunk }
        body.close

        assert_equal 206, status
        assert_equal "contents", sent
        assert_equal "bytes 4-11/12", headers["content-range"]
        assert_equal "8", headers[Rack::CONTENT_LENGTH]
      end
    end

    it "sends multipart ranges of the pinned version after replacement" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        app = Rack::Lint.new(Rack::Files.new(dir, {}, 'text/plain', true))

        env = Rack::MockRequest.env_for("/asset.txt", "HTTP_RANGE" => "bytes=0-2,4-7")
        status, headers, body = app.call(env)
        atomically_replace(path, "xxxxxxxxxxxxxxxxxxxxxxxx")

        sent = +""
        body.each { |chunk| sent << chunk }
        body.close

        assert_equal 206, status
        assert_includes sent, "old"
        assert_includes sent, "cont"
        assert_equal "multipart/byteranges; boundary=#{Rack::Files::MULTIPART_BOUNDARY}",
          headers[Rack::CONTENT_TYPE]
      end
    end

    it "uses pinned file info for HEAD requests" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        app = Rack::Lint.new(Rack::Files.new(dir, {}, 'text/plain', true))

        before = open_file_paths
        status, headers, body = app.call(
          Rack::MockRequest.env_for("/asset.txt", "REQUEST_METHOD" => "HEAD")
        )
        atomically_replace(path, "brand new, much longer contents")

        assert_equal 200, status
        assert_equal "12", headers[Rack::CONTENT_LENGTH]
        body.close
        assert_equal before, open_file_paths
      end
    end

    it "closes the pinned file for 304 responses without leaking a descriptor" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        app = Rack::Lint.new(Rack::Files.new(dir, {}, 'text/plain', true))

        before = open_file_paths
        env = Rack::MockRequest.env_for("/asset.txt",
          "HTTP_IF_MODIFIED_SINCE" => File.mtime(path).httpdate)
        status, _headers, body = app.call(env)

        assert_equal 304, status
        body.close
        assert_equal before, open_file_paths
      end
    end

    it "closes the pinned file when iteration stops early" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir, {}, 'text/plain', true)

        _status, _headers, body = files.call(Rack::MockRequest.env_for("/asset.txt"))

        body.each do |_chunk|
          break
        end

        assert body.closed?
        assert_raises(IOError) { body.each {} }
      end
    end

    it "closes the pinned file when iteration raises" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir, {}, 'text/plain', true)

        _status, _headers, body = files.call(Rack::MockRequest.env_for("/asset.txt"))

        raised = assert_raises(RuntimeError) do
          body.each do |_chunk|
            raise "boom"
          end
        end
        assert_equal "boom", raised.message
        assert body.closed?
      end
    end

    it "sends available bytes and closes the file when the file is truncated" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir, {}, 'text/plain', true)

        env = Rack::MockRequest.env_for("/asset.txt", "HTTP_RANGE" => "bytes=0-100")
        status, headers, body = files.call(env)
        File.truncate(path, 3)

        sent = +""
        body.each { |chunk| sent << chunk }

        assert_equal 206, status
        assert_equal "old", sent
        assert body.closed?
        assert_equal "bytes 0-11/12", headers["content-range"]
      end
    end

    it "streams the pinned version returned by #serving_pinned_file after replacement" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir)

        file = File.open(path, "rb")
        request = Rack::Request.new(Rack::MockRequest.env_for("/asset.txt"))
        status, headers, body = files.serving_pinned_file(request, file)
        atomically_replace(path, "brand new, much longer contents")

        sent = +""
        body.each { |chunk| sent << chunk }

        assert_equal 200, status
        assert_equal "old contents", sent
        assert_equal "12", headers[Rack::CONTENT_LENGTH]
        assert body.closed?
      end
    end

    it "closes the provided file from #serving_pinned_file for a 304 response" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir)

        file = File.open(path, "rb")
        env = Rack::MockRequest.env_for("/asset.txt",
          "HTTP_IF_MODIFIED_SINCE" => File.mtime(path).httpdate)
        request = Rack::Request.new(env)
        status, _headers, body = files.serving_pinned_file(request, file)

        assert_equal 304, status
        assert_equal [], body
        assert file.closed?
      end
    end

    it "returns 404 and releases the descriptor for a missing pinned file" do
      Dir.mktmpdir do |dir|
        app = Rack::Lint.new(Rack::Files.new(dir, {}, 'text/plain', true))
        before = open_file_paths
        status, _headers, body = app.call(Rack::MockRequest.env_for("/missing"))

        assert_equal 404, status
        body.close
        assert_equal before, open_file_paths
      end
    end

    it "closes the provided file for a 416 unsatisfiable range response" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "asset.txt")
        File.write(path, "old contents")
        files = Rack::Files.new(dir, {}, 'text/plain', true)

        file = File.open(path, "rb")
        request = Rack::Request.new(
          Rack::MockRequest.env_for("/asset.txt", "HTTP_RANGE" => "bytes=100-200")
        )
        status, headers, _body = files.serving_pinned_file(request, file)

        assert_equal 416, status
        assert_equal "bytes */12", headers["content-range"]
        assert file.closed?
      end
    end
  end
end
