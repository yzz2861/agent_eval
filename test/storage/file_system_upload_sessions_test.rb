require "test_helper"

require "shrine/storage/file_system"

require "fileutils"
require "tmpdir"
require "stringio"
require "digest"

describe "FileSystem upload sessions" do
  def storage(directory = root, **options)
    Shrine::Storage::FileSystem.new(directory, **options)
  end

  def root
    File.join(Dir.tmpdir, "shrine-upload-sessions")
  end

  before do
    FileUtils.rm_rf(root)
    @store   = Shrine::UploadSessions::Memory.new
    @storage = storage(upload_session_store: @store, upload_session_ttl: 60)
  end

  after do
    FileUtils.rm_rf(root)
  end

  def chunk(content, offset:, length: nil)
    @storage.put_upload_chunk(@session_id, StringIO.new(content), offset: offset, length: length)
  end

  it "is enabled by default and can be disabled" do
    assert storage.supports_upload_sessions?
    refute storage(upload_sessions: false).supports_upload_sessions?
  end

  it "raises when sessions are used while disabled" do
    disabled = storage(upload_sessions: false)

    assert_raises(Shrine::UploadSessionError) do
      disabled.create_upload_session(total_size: 1)
    end
  end

  describe "creating sessions" do
    it "returns a session with a generated id" do
      session = @storage.create_upload_session(total_size: 10)

      assert_match(/\Aus-[0-9a-f]{32}\z/, session.id)
      assert_equal 10, session.total_size
      assert_equal [], session.ranges
      refute session.finalized?
      assert session.expires_at
    end

    it "accepts an explicit id" do
      session = @storage.create_upload_session(total_size: 1, id: "custom-id_1")
      assert_equal "custom-id_1", session.id
    end

    it "rejects a negative size" do
      assert_raises(ArgumentError) { @storage.create_upload_session(total_size: -1) }
    end

    it "rejects ids with path traversal characters" do
      assert_raises(ArgumentError) do
        @storage.create_upload_session(total_size: 1, id: "../escape")
      end
    end

    it "rejects unknown checksum algorithms" do
      assert_raises(ArgumentError) do
        @storage.create_upload_session(total_size: 1, checksum_algorithm: :crc32)
      end
    end

    it "rejects duplicate explicit ids" do
      @storage.create_upload_session(total_size: 1, id: "dup")

      assert_raises(Shrine::UploadSessionError) do
        @storage.create_upload_session(total_size: 1, id: "dup")
      end
    end
  end

  describe "uploading chunks" do
    before do
      @session_id = @storage.create_upload_session(total_size: 11).id
    end

    it "accepts out of order chunks and merges adjacent ranges" do
      chunk("world", offset: 6)
      session = chunk("hello ", offset: 0)

      assert_equal [[0, 11]], session.ranges
      assert_equal 11, File.size(File.join(root, ".upload-sessions", "#{@session_id}.part"))
    end

    it "keeps non-adjacent ranges separate" do
      session = chunk("abc", offset: 2)

      assert_equal [[2, 5]], session.ranges

      session = chunk("x", offset: 0)

      assert_equal [[0, 1], [2, 5]], session.ranges
    end

    it "accepts the same range with the same content (idempotent retry)" do
      chunk("hello", offset: 0)
      session = chunk("hello", offset: 0)

      assert_equal [[0, 5]], session.ranges
    end

    it "rejects the same range with different content" do
      chunk("hello", offset: 0)

      assert_raises(Shrine::UploadChunkConflict) do
        chunk("HELLO", offset: 0)
      end
    end

    it "rejects partially overlapping ranges" do
      chunk("hello", offset: 0) # [0, 5]

      assert_raises(Shrine::UploadChunkConflict) do
        chunk("XX", offset: 3)    # [3, 5]
      end

      assert_raises(Shrine::UploadChunkConflict) do
        chunk("longer", offset: 3) # [3, 9]
      end
    end

    it "rejects chunks exceeding the declared size" do
      assert_raises(Shrine::UploadChunkOutOfRange) do
        chunk("x" * 12, offset: 0)
      end
    end

    it "rejects empty chunks" do
      assert_raises(ArgumentError) { chunk("", offset: 0) }
    end

    it "rejects negative offsets" do
      assert_raises(ArgumentError) { chunk("x", offset: -1) }
    end

    it "reads only the declared length" do
      io = StringIO.new("abc" + "rest")
      session = @storage.put_upload_chunk(@session_id, io, offset: 0, length: 3)

      assert_equal [[0, 3]], session.ranges
    end

    it "raises for unknown sessions" do
      assert_raises(Shrine::UploadSessionNotFound) do
        @storage.put_upload_chunk("missing", StringIO.new("x"), offset: 0)
      end
    end

    it "raises for expired sessions" do
      session = @storage.create_upload_session(total_size: 1, ttl: 0)

      assert_raises(Shrine::UploadSessionNotFound) do
        @storage.put_upload_chunk(session.id, StringIO.new("x"), offset: 0)
      end
    end
  end

  describe "finalizing" do
    before do
      @content = "hello world"
      @checksum = Digest::SHA256.hexdigest(@content)
      @session_id = @storage.create_upload_session(
        total_size:         @content.bytesize,
        checksum_algorithm: "sha256",
      ).id
    end

    it "refuses to finalize an incomplete session" do
      chunk("world", offset: 6)

      assert_raises(Shrine::UploadSessionIncomplete) do
        @storage.finalize_upload_session(@session_id, checksum: @checksum)
      end
    end

    it "publishes the content and records the uploaded id" do
      chunk("world", offset: 6)
      chunk("hello ", offset: 0)

      session = @storage.finalize_upload_session(@session_id, checksum: @checksum)

      assert session.finalized?
      assert_equal @content, @storage.open(session.uploaded_id).read
      assert_equal @content.bytesize, session.metadata["size"]
      refute File.exist?(File.join(root, ".upload-sessions", "#{@session_id}.part"))
    end

    it "publishes at an explicit id" do
      chunk(@content, offset: 0)
      session = @storage.finalize_upload_session(@session_id, id: "final/file.txt", checksum: @checksum)

      assert_equal "final/file.txt", session.uploaded_id
      assert @storage.exists?("final/file.txt")
    end

    it "rejects a checksum mismatch" do
      chunk(@content, offset: 0)

      assert_raises(Shrine::UploadSessionIncomplete) do
        @storage.finalize_upload_session(@session_id, checksum: "0" * 64)
      end

      refute @storage.get_upload_session(@session_id).finalized?
    end

    it "supports empty files" do
      session_id = @storage.create_upload_session(total_size: 0).id
      session = @storage.finalize_upload_session(session_id)

      assert session.finalized?
      assert_equal "", @storage.open(session.uploaded_id).read
    end

    it "verifies the checksum of an empty file without staged chunks" do
      session_id = @storage.create_upload_session(
        total_size:         0,
        checksum_algorithm: "sha256",
      ).id

      session = @storage.finalize_upload_session(
        session_id,
        checksum:           Digest::SHA256.hexdigest(""),
        checksum_algorithm: "sha256",
      )

      assert session.finalized?
      assert_equal "", @storage.open(session.uploaded_id).read
    end

    it "publishes only once when finalized twice" do
      chunk(@content, offset: 0)

      first  = @storage.finalize_upload_session(@session_id, checksum: @checksum)
      second = @storage.finalize_upload_session(@session_id, checksum: "different")

      assert_equal first.uploaded_id, second.uploaded_id
      assert @storage.exists?(first.uploaded_id)
      refute @storage.exists?("#{first.uploaded_id}-again")
    end

    it "refuses chunks after finalization" do
      chunk(@content, offset: 0)
      @storage.finalize_upload_session(@session_id, checksum: @checksum)

      assert_raises(Shrine::UploadChunkConflict) do
        chunk("x", offset: 0, length: 1)
      end
    end
  end

  describe "aborting" do
    it "removes the session and its staged chunks" do
      @session_id = @storage.create_upload_session(total_size: 5).id
      chunk("abc", offset: 0)

      @storage.abort_upload_session(@session_id)

      refute File.exist?(File.join(root, ".upload-sessions", "#{@session_id}.part"))
      assert_raises(Shrine::UploadSessionNotFound) do
        @storage.get_upload_session(@session_id)
      end
    end

    it "refuses to abort a finalized session" do
      session_id = @storage.create_upload_session(total_size: 0).id
      @storage.finalize_upload_session(session_id)

      assert_raises(Shrine::UploadSessionClosed) do
        @storage.abort_upload_session(session_id)
      end
    end
  end

  describe "pruning" do
    it "removes expired unfinished sessions and their chunks" do
      expired = @storage.create_upload_session(total_size: 5, ttl: 60)
      @session_id = expired.id
      chunk("abc", offset: 0)

      now = Time.now + 61
      removed = @storage.prune_upload_sessions!(now)

      assert_equal [expired.id], removed.map(&:id)
      refute File.exist?(File.join(root, ".upload-sessions", "#{expired.id}.part"))
    end

    it "keeps fresh sessions" do
      fresh = @storage.create_upload_session(total_size: 5, ttl: 60)

      assert_equal [], @storage.prune_upload_sessions!(Time.now)
      assert @storage.get_upload_session(fresh.id)
    end

    it "does not remove published files when cleaning up records" do
      session_id = @storage.create_upload_session(total_size: 0, ttl: 60).id
      session = @storage.finalize_upload_session(session_id)

      @storage.prune_upload_sessions!(Time.now + 61)

      assert @storage.exists?(session.uploaded_id)
    end
  end
end
