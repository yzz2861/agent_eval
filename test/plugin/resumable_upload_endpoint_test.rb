require "test_helper"
require "shrine/plugins/resumable_uploads"
require "rack/test"
require "json"
require "digest"
require "base64"

describe Shrine::Plugins::ResumableUploads do
  JSON_HEADERS = { "CONTENT_TYPE" => "application/json" }.freeze
  OCTET_HEADERS = { "CONTENT_TYPE" => "application/octet-stream" }.freeze

  def app
    Rack::Test::Session.new(Rack::Lint.new(@shrine.resumable_upload_endpoint(:cache)))
  end

  def create_session(total_size:, **params)
    response = app.post("/", params.merge(total_size: total_size).to_json, JSON_HEADERS)
    [response.status, JSON.parse(response.body), response.headers]
  end

  def put_chunk(id, bytes, start_offset, total_size)
    headers = {
      "CONTENT_TYPE"   => "application/octet-stream",
      "HTTP_CONTENT_RANGE" => "bytes #{start_offset}-#{start_offset + bytes.bytesize - 1}/#{total_size}",
    }
    app.patch("/#{id}", bytes, headers)
  end

  def finalize(id)
    app.post("/#{id}/finalize", "{}", JSON_HEADERS)
  end

  before do
    @uploader = uploader { plugin :resumable_uploads }
    @shrine = @uploader.class
  end

  describe "POST /" do
    it "creates a session and returns its id and length" do
      status, body, headers = create_session(total_size: 100, filename: "a.txt")

      assert_equal 201, status
      assert_equal "application/json; charset=utf-8", headers["Content-Type"]
      assert_equal "100", headers["Upload-Length"]
      refute_nil body["id"]
      assert_equal 100, body["total_size"]
      assert_equal "a.txt", body["filename"]
      assert_equal [], body["ranges"]
    end

    it "requires total_size" do
      response = app.post("/", {}.to_json, JSON_HEADERS)
      assert_equal 400, response.status
      assert_equal "total_size is required", response.body
    end

    it "rejects a non-integer total_size" do
      response = app.post("/", { total_size: "abc" }.to_json, JSON_HEADERS)
      assert_equal 400, response.status
      assert_equal "total_size must be an integer", response.body
    end

    it "rejects a negative total_size" do
      response = app.post("/", { total_size: -1 }.to_json, JSON_HEADERS)
      assert_equal 400, response.status
    end

    it "rejects an invalid checksum format" do
      response = app.post("/", { total_size: 1, checksum: "bad" }.to_json, JSON_HEADERS)
      assert_equal 400, response.status
    end

    it "accepts tus-style Upload-Length headers" do
      response = app.post("/", "", { "HTTP_UPLOAD_LENGTH" => "42" })

      assert_equal 201, response.status
      assert_equal 42, JSON.parse(response.body)["total_size"]
    end

    it "accepts a tus-style base64 Upload-Checksum header" do
      encoded = Base64.strict_encode64(Digest::SHA256.hexdigest("abc"))
      response = app.post("/", "", {
        "HTTP_UPLOAD_LENGTH"   => "3",
        "HTTP_UPLOAD_CHECKSUM" => "sha256 #{encoded}",
      })

      assert_equal 201, response.status
      assert_equal "sha256=#{Digest::SHA256.hexdigest("abc")}",
                   JSON.parse(response.body)["checksum"]
    end
  end

  describe "PATCH /:id" do
    before do
      _status, body, _headers = create_session(total_size: 11)
      @id = body["id"]
    end

    it "stores a chunk and reports the confirmed range" do
      response = put_chunk(@id, "world", 6, 11)

      assert_equal 200, response.status
      assert_equal "11", response.headers["Upload-Offset"]
      assert_equal "6 11", response.headers["Upload-Received-Ranges"]
      assert_equal [[6, 11]], JSON.parse(response.body)["ranges"]
    end

    it "accepts chunks out of order" do
      put_chunk(@id, "world", 6, 11)
      response = put_chunk(@id, "hello ", 0, 11)

      assert_equal 200, response.status
      assert_equal "0 11", response.headers["Upload-Received-Ranges"]
    end

    it "accepts Upload-Offset instead of Content-Range" do
      response = app.patch("/#{@id}", "hello ", {
        "CONTENT_TYPE"      => "application/octet-stream",
        "HTTP_UPLOAD_OFFSET" => "0",
      })

      assert_equal 200, response.status
      assert_equal "6", response.headers["Upload-Offset"]
    end

    it "accepts resubmitting the same range with the same content" do
      put_chunk(@id, "hello ", 0, 11)
      response = put_chunk(@id, "hello ", 0, 11)

      assert_equal 200, response.status
    end

    it "rejects different content for the same range" do
      put_chunk(@id, "hello ", 0, 11)
      response = put_chunk(@id, "HELLO ", 0, 11)

      assert_equal 409, response.status
    end

    it "rejects partial overlap" do
      put_chunk(@id, "aaaaa", 0, 11)
      response = put_chunk(@id, "aabbb", 3, 11)

      assert_equal 409, response.status
    end

    it "rejects out-of-bounds ranges with 416" do
      response = app.patch("/#{@id}", "xxx", {
        "CONTENT_TYPE"   => "application/octet-stream",
        "HTTP_CONTENT_RANGE" => "bytes 10-12/11",
      })

      assert_equal 416, response.status
    end

    it "requires a range header" do
      response = app.patch("/#{@id}", "abc", OCTET_HEADERS)

      assert_equal 400, response.status
      assert_equal "Upload-Offset or Content-Range header is required", response.body
    end

    it "rejects mismatched Content-Range and body length" do
      response = app.patch("/#{@id}", "abc", {
        "CONTENT_TYPE"   => "application/octet-stream",
        "HTTP_CONTENT_RANGE" => "bytes 0-4/11",
      })

      assert_equal 400, response.status
    end

    it "returns 404 for an unknown session" do
      response = put_chunk("missing", "a", 0, 1)
      assert_equal 404, response.status
    end
  end

  describe "GET/HEAD /:id" do
    it "reports received ranges" do
      _status, body, _headers = create_session(total_size: 5)
      id = body["id"]
      put_chunk(id, "ab", 0, 5)

      response = app.get("/#{id}")
      assert_equal 200, response.status
      assert_equal "5", response.headers["Upload-Length"]
      assert_equal "2", response.headers["Upload-Offset"]
      assert_equal "0 2", response.headers["Upload-Received-Ranges"]
      assert_equal [[0, 2]], JSON.parse(response.body)["ranges"]

      response = app.head("/#{id}")
      assert_equal 200, response.status
      assert_equal "2", response.headers["Upload-Offset"]
      assert_equal "0", response.headers["Content-Length"]
    end
  end

  describe "POST /:id/finalize" do
    it "publishes completed uploads and returns UploadedFile JSON" do
      content = "final content"
      _status, body, _headers = create_session(
        total_size: content.bytesize,
        checksum: "sha256=#{Digest::SHA256.hexdigest(content)}",
        filename: "f.txt",
      )
      id = body["id"]
      assert_equal 200, put_chunk(id, content, 0, content.bytesize).status

      response = finalize(id)
      assert_equal 200, response.status

      uploaded_file = @shrine.uploaded_file(response.body)
      assert_equal content, uploaded_file.read
      assert_equal content.bytesize, uploaded_file.metadata["size"]
    end

    it "returns 409 for incomplete uploads" do
      _status, body, _headers = create_session(total_size: 5)
      response = finalize(body["id"])
      assert_equal 409, response.status
    end

    it "returns 460 on checksum mismatch" do
      _status, body, _headers = create_session(
        total_size: 3,
        checksum: "sha256=#{Digest::SHA256.hexdigest("xxx")}",
      )
      id = body["id"]
      put_chunk(id, "abc", 0, 3)

      response = finalize(id)
      assert_equal 460, response.status
    end

    it "publishes exactly once across two finalize calls" do
      _status, body, _headers = create_session(total_size: 3)
      id = body["id"]
      put_chunk(id, "abc", 0, 3)

      first  = finalize(id)
      second = finalize(id)

      assert_equal 200, first.status
      assert_equal 200, second.status
      assert_equal first.body, second.body
      assert_equal 1, @shrine.storages[:cache].store.count
    end

    it "returns 404 for an unknown session" do
      response = finalize("missing")
      assert_equal 404, response.status
    end

    it "accepts metadata overrides at finalize" do
      _status, body, _headers = create_session(total_size: 3)
      id = body["id"]
      put_chunk(id, "abc", 0, 3)

      response = app.post(
        "/#{id}/finalize",
        { metadata: { "tag" => "custom" } }.to_json,
        JSON_HEADERS,
      )

      assert_equal 200, response.status
      uploaded_file = @shrine.uploaded_file(response.body)
      assert_equal "custom", uploaded_file.metadata["tag"]
    end
  end

  describe "DELETE /:id" do
    it "aborts an unfinished session" do
      _status, body, _headers = create_session(total_size: 5)
      id = body["id"]

      response = app.delete("/#{id}")
      assert_equal 204, response.status

      assert_equal 404, app.get("/#{id}").status
    end

    it "does not abort a finalized session" do
      _status, body, _headers = create_session(total_size: 3)
      id = body["id"]
      put_chunk(id, "abc", 0, 3)
      finalize(id)

      response = app.delete("/#{id}")
      assert_equal 409, response.status
    end
  end

  it "returns 404 for unknown paths" do
    assert_equal 404, app.get("/something/else").status
  end

  it "rejects ids that attempt path traversal" do
    assert_equal 404, app.get("/%2e%2e%2f%2e%2e%2fetc").status
  end

  it "returns 405 for unsupported verbs on the root" do
    assert_equal 405, app.get("/").status
  end
end
