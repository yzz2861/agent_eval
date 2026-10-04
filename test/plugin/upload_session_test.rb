require "test_helper"
require "shrine/plugins/upload_session"
require "shrine/storage/file_system"
require "rack/test"
require "json"
require "tmpdir"
require "digest"
require "stringio"

describe Shrine::Plugins::UploadSession do
  def app
    Rack::Test::Session.new(Rack::Lint.new(@shrine.upload_session_endpoint(:cache)))
  end

  before do
    @tmpdir = Dir.mktmpdir
    tmpdir = @tmpdir
    @uploader = uploader do
      plugin :upload_session
      storages[:cache] = Shrine::Storage::FileSystem.new(tmpdir)
    end
    @shrine = @uploader.class
  end

  after do
    FileUtils.rm_rf(@tmpdir)
  end

  def create_session(size: 11, body: nil)
    body ||= { "size" => size, "filename" => "hello.txt" }.to_json
    app.post("/", body, { "CONTENT_TYPE" => "application/json" })
  end

  def session_id
    @session_id ||= JSON.parse(create_session.body)["id"]
  end

  def put_chunk(content, offset:)
    app.put("/#{session_id}", content, {
      "HTTP_UPLOAD_OFFSET"       => offset.to_s,
      "HTTP_UPLOAD_LENGTH"       => content.bytesize.to_s,
      "CONTENT_TYPE"             => "application/octet-stream",
    })
  end

  describe "POST /" do
    it "creates a session and returns its id and empty ranges" do
      response = create_session(size: 10)

      assert_equal 201, response.status
      assert_equal "application/json; charset=utf-8", response.headers["Content-Type"]

      result = JSON.parse(response.body)

      assert_match(/\Aus-[0-9a-f]{32}\z/, result["id"])
      assert_equal 10, result["total_size"]
      assert_equal [], result["ranges"]
      assert_equal 0, result["received"]
      refute result["finalized"]
      assert result["expires_at"]
    end

    it "requires a total size" do
      response = app.post("/", "{}", { "CONTENT_TYPE" => "application/json" })

      assert_equal 400, response.status
    end

    it "rejects invalid JSON" do
      response = app.post("/", "{", { "CONTENT_TYPE" => "application/json" })

      assert_equal 400, response.status
    end

    it "rejects unsupported methods" do
      assert_equal 405, app.get("/").status
    end
  end

  describe "PUT /:id" do
    it "records out of order chunks and reports merged ranges" do
      response = put_chunk("world", offset: 6)

      assert_equal 200, response.status
      assert_equal [[6, 11]], JSON.parse(response.body)["ranges"]

      response = put_chunk("hello ", offset: 0)

      assert_equal [[0, 11]], JSON.parse(response.body)["ranges"]
      assert_equal 11, JSON.parse(response.body)["received"]
    end

    it "accepts a resubmitted identical chunk" do
      put_chunk("hello", offset: 0)
      response = put_chunk("hello", offset: 0)

      assert_equal 200, response.status
    end

    it "rejects different content for the same range" do
      put_chunk("hello", offset: 0)
      response = put_chunk("HELLO", offset: 0)

      assert_equal 409, response.status
    end

    it "rejects partially overlapping chunks" do
      put_chunk("hello", offset: 0)
      response = put_chunk("XX", offset: 3)

      assert_equal 409, response.status
    end

    it "rejects chunks beyond the declared size" do
      response = app.put("/#{session_id}", "x" * 12, {
        "HTTP_UPLOAD_OFFSET" => "0",
      })

      assert_equal 416, response.status
    end

    it "requires an offset" do
      response = app.put("/#{session_id}", "x", {})

      assert_equal 400, response.status
    end

    it "supports a Content-Range header" do
      response = app.put("/#{session_id}", "hello ", {
        "HTTP_CONTENT_RANGE" => "bytes 0-5/11",
      })

      assert_equal 200, response.status
      assert_equal [[0, 6]], JSON.parse(response.body)["ranges"]
    end

    it "returns 404 for unknown sessions" do
      response = app.put("/missing", "x", { "HTTP_UPLOAD_OFFSET" => "0" })

      assert_equal 404, response.status
    end
  end

  describe "GET /:id" do
    it "returns the session status" do
      put_chunk("abc", offset: 2)
      response = app.get("/#{session_id}")

      assert_equal 200, response.status
      assert_equal [[2, 5]], JSON.parse(response.body)["ranges"]
    end

    it "returns 404 for unknown sessions" do
      assert_equal 404, app.get("/missing").status
    end
  end

  describe "POST /:id/finalize" do
    def finalize(body = "{}")
      app.post("/#{session_id}/finalize", body, { "CONTENT_TYPE" => "application/json" })
    end

    before do
      put_chunk("world", offset: 6)
    end

    it "rejects finalizing an incomplete session" do
      assert_equal 409, finalize.status
    end

    it "publishes an UploadedFile once" do
      put_chunk("hello ", offset: 0)

      response  = finalize
      response2 = finalize

      assert_equal 200, response.status
      assert_equal 200, response2.status
      assert_equal response.body, response2.body

      result = JSON.parse(response.body)

      assert_equal "cache", result["storage"]
      assert_equal 11, result["metadata"]["size"]
      assert_equal "hello.txt", result["metadata"]["filename"]

      uploaded_file = @shrine.uploaded_file(response.body)

      assert uploaded_file.exists?
      assert_equal "hello world", uploaded_file.read
    end

    it "verifies the declared checksum" do
      put_chunk("hello ", offset: 0)
      bad = app.post("/#{session_id}/finalize", {
        "checksum" => "0" * 64,
        "checksum_algorithm" => "sha256",
      }.to_json, { "CONTENT_TYPE" => "application/json" })

      assert_equal 409, bad.status

      response = app.post("/#{session_id}/finalize", {
        "checksum" => Digest::SHA256.hexdigest("hello world"),
        "checksum_algorithm" => "sha256",
      }.to_json, { "CONTENT_TYPE" => "application/json" })

      assert_equal 200, response.status
    end

    it "returns 404 for unknown sessions" do
      response = app.post("/missing/finalize", "{}", { "CONTENT_TYPE" => "application/json" })

      assert_equal 404, response.status
    end
  end

  describe "DELETE /:id" do
    it "aborts the session and removes its chunks" do
      put_chunk("abc", offset: 0)

      response = app.delete("/#{session_id}")

      assert_equal 204, response.status
      assert_equal 404, app.get("/#{session_id}").status
    end

    it "refuses to abort a finalized session" do
      id = JSON.parse(create_session(size: 0).body)["id"]
      app.post("/#{id}/finalize", "{}", { "CONTENT_TYPE" => "application/json" })

      response = app.delete("/#{id}")

      assert_equal 409, response.status
    end
  end

  it "returns 404 for unknown routes" do
    assert_equal 404, app.get("/a/b/c").status
  end

  it "returns 501 when the storage doesn't support sessions" do
    uploader_class = Class.new(Shrine)
    uploader_class.plugin :upload_session
    uploader_class.storages[:memory] = Shrine::Storage::Memory.new

    endpoint = uploader_class.upload_session_endpoint(:memory)
    session = Rack::Test::Session.new(endpoint)
    response = session.post("/", { "size" => 1 }.to_json, { "CONTENT_TYPE" => "application/json" })

    assert_equal 501, response.status
  end

  it "exposes a Ruby API on the uploader" do
    uploader = @shrine.new(:cache)
    session = uploader.create_upload_session(total_size: 5)

    assert_kind_of Shrine::UploadSession, session

    uploader.put_upload_chunk(session.id, StringIO.new("hello"), offset: 0)

    uploaded_file = uploader.finalize_upload_session(session.id)

    assert_kind_of @shrine::UploadedFile, uploaded_file
    assert_equal "hello", uploaded_file.read
  end
end
