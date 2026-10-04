require "test_helper"
require "shrine/plugins/resumable_uploads"
require "digest"
require "fileutils"

describe Shrine::Plugins::ResumableUploads do
  before do
    @uploader = uploader { plugin :resumable_uploads }
    @shrine   = @uploader.class
    @service  = @shrine.resumable_upload(:cache)
    @tmpdir   = File.join("tmp", "resumable-uploads-test")
    FileUtils.rm_rf(@tmpdir)
    FileUtils.mkdir_p(@tmpdir)
  end

  describe "session creation" do
    it "creates a session and returns a session id" do
      session = @service.create_session(total_size: 123)

      refute_nil session.id
      assert_match(/\A[a-f0-9]+\z/, session.id)
      assert_equal 123, session.total_size
      assert_equal [], session.ranges
      refute session.complete?
      refute session.finalized?
      refute_nil session.expires_at
    end

    it "rejects a negative total size" do
      assert_raises(Shrine::ResumableUpload::Error) { @service.create_session(total_size: -1) }
    end

    it "accepts an empty file as immediately complete but not finalized" do
      session = @service.create_session(total_size: 0)

      assert session.complete?
      refute session.finalized?
    end

    it "rejects an invalid checksum format" do
      assert_raises(Shrine::ResumableUpload::Error) do
        @service.create_session(total_size: 10, checksum: "not-a-checksum")
      end
    end

    it "rejects an unsupported checksum algorithm" do
      assert_raises(Shrine::ResumableUpload::Error) do
        @service.create_session(total_size: 10, checksum: "crc32=abc")
      end
    end

    it "uses the custom id generator" do
      service = @shrine.resumable_upload(:cache, id_generator: -> { "fixed-id" })
      assert_equal "fixed-id", service.create_session(total_size: 1).id
    end
  end

  describe "chunk submission" do
    before do
      @session = @service.create_session(total_size: 11)
      @id = @session.id
    end

    it "accepts chunks sent out of order and tracks confirmed ranges" do
      @service.put_chunk(@id, "world", start_offset: 6)
      assert_equal [[6, 11]], @service.get_session(@id).merged_ranges

      @service.put_chunk(@id, "hello ", start_offset: 0)
      session = @service.get_session(@id)

      assert_equal [[0, 11]], session.merged_ranges
      assert_equal 11, session.received_size
      assert session.complete?
    end

    it "allows resubmitting the same range with identical content" do
      @service.put_chunk(@id, "hello ", start_offset: 0)
      @service.put_chunk(@id, "hello ", start_offset: 0)

      assert_equal [[0, 6]], @service.get_session(@id).merged_ranges
    end

    it "allows resubmitting a sub-range with identical content" do
      @service.put_chunk(@id, "hello ", start_offset: 0)
      @service.put_chunk(@id, "ell", start_offset: 1)

      assert_equal [[0, 6]], @service.get_session(@id).merged_ranges
    end

    it "rejects a resubmitted range with different content" do
      @service.put_chunk(@id, "hello ", start_offset: 0)

      error = assert_raises(Shrine::ResumableUpload::Conflict) do
        @service.put_chunk(@id, "HELLO ", start_offset: 0)
      end
      assert_equal 409, error.status
      assert_equal [[0, 6]], @service.get_session(@id).merged_ranges
    end

    it "rejects partial overlap with different content at the boundary" do
      @service.put_chunk(@id, "aaaaa", start_offset: 0)

      assert_raises(Shrine::ResumableUpload::Conflict) do
        @service.put_chunk(@id, "aabbb", start_offset: 3)
      end
      assert_equal [[0, 5]], @service.get_session(@id).merged_ranges
    end

    it "rejects a prefix-extending chunk that overlaps a confirmed range" do
      @service.put_chunk(@id, "bbb", start_offset: 3)

      assert_raises(Shrine::ResumableUpload::Conflict) do
        @service.put_chunk(@id, "aabbb", start_offset: 1)
      end
    end

    it "rejects chunks outside the declared length" do
      error = assert_raises(Shrine::ResumableUpload::RangeInvalid) do
        @service.put_chunk(@id, "x" * 3, start_offset: 10)
      end
      assert_equal 416, error.status
    end

    it "rejects chunks starting at a negative offset" do
      assert_raises(Shrine::ResumableUpload::RangeInvalid) do
        @service.put_chunk(@id, "x", start_offset: -1)
      end
    end

    it "accepts a zero-length chunk without changing ranges" do
      session = @service.put_chunk(@id, "", start_offset: 0)
      assert_equal [], session.ranges
    end

    it "raises for an unknown session" do
      assert_raises(Shrine::ResumableUpload::SessionNotFound) do
        @service.put_chunk("missing", "x", start_offset: 0)
      end
    end

    it "treats expired sessions as missing" do
      expired = @service.create_session(total_size: 1, expires_in: -1)

      assert_raises(Shrine::ResumableUpload::SessionNotFound) do
        @service.put_chunk(expired.id, "x", start_offset: 0)
      end
    end

    it "rejects chunks for a finalized session" do
      session = complete_session(@service, "abc")
      @service.finalize(session.id)

      assert_raises(Shrine::ResumableUpload::AlreadyFinalized) do
        @service.put_chunk(session.id, "a", start_offset: 0)
      end
    end

    it "handles concurrent out-of-order chunk submissions" do
      content = "a" * 100
      session = @service.create_session(total_size: content.bytesize)

      threads = (0...10).map do |index|
        Thread.new do
          start = index * 10
          @service.put_chunk(session.id, content.byteslice(start, 10), start_offset: start)
        end
      end
      threads.each(&:join)

      reloaded = @service.get_session(session.id)
      assert reloaded.complete?
      assert_equal [[0, 100]], reloaded.merged_ranges

      uploaded_file = @service.finalize(session.id)
      assert_equal content, uploaded_file.read
    end

    it "serializes concurrent finalize calls into a single publication" do
      content = "race"
      session = complete_session(@service, content)
      files = Array.new(8)
      barrier = Thread::Queue.new

      threads = Array.new(8) do |index|
        Thread.new do
          barrier.pop
          files[index] = @service.finalize(session.id)
        end
      end
      8.times { barrier << :go }
      threads.each(&:join)

      assert_equal 1, @shrine.storages[:cache].store.count
      assert files.compact.all? { |file| file.id == files.first.id }
    end
  end

  describe "finalization" do
    it "publishes the assembled content and returns an UploadedFile" do
      content = "the complete file"
      session = complete_session(@service, content, filename: "x.txt", content_type: "text/plain")

      uploaded_file = @service.finalize(session.id)

      assert_instance_of @shrine::UploadedFile, uploaded_file
      assert_equal content, uploaded_file.read
      assert_equal content.bytesize, uploaded_file.metadata["size"]
      assert_equal "x.txt", uploaded_file.original_filename
      assert_equal "text/plain", uploaded_file.mime_type
      assert @service.get_session(session.id).finalized?
    end

    it "refuses to finalize an incomplete session" do
      session = @service.create_session(total_size: 5)
      @service.put_chunk(session.id, "ab", start_offset: 0)

      error = assert_raises(Shrine::ResumableUpload::Incomplete) do
        @service.finalize(session.id)
      end
      assert_equal 409, error.status
      assert_equal 0, @shrine.storages[:cache].store.count
    end

    it "verifies the declared checksum before publishing" do
      content = "checksum me"
      session = complete_session(@service, content, checksum: "sha256=#{Digest::SHA256.hexdigest("different")}")

      error = assert_raises(Shrine::ResumableUpload::ChecksumMismatch) do
        @service.finalize(session.id)
      end
      assert_equal 460, error.status
      assert_equal 0, @shrine.storages[:cache].store.count
      refute @service.get_session(session.id).finalized?
    end

    it "accepts a matching checksum" do
      content = "checksum me"
      session = complete_session(@service, content, checksum: "sha256=#{Digest::SHA256.hexdigest(content)}")

      uploaded_file = @service.finalize(session.id)
      assert_equal content, uploaded_file.read
    end

    it "publishes only once when finalize is called twice" do
      session = complete_session(@service, "once")

      first  = @service.finalize(session.id)
      second = @service.finalize(session.id)

      assert_equal first.id, second.id
      assert_equal first, second
      assert_equal 1, @shrine.storages[:cache].store.count
    end

    it "publishes empty files" do
      session = @service.create_session(total_size: 0)
      uploaded_file = @service.finalize(session.id)

      assert_equal "", uploaded_file.read
      assert_equal 0, uploaded_file.metadata["size"]
      assert_equal 1, @shrine.storages[:cache].store.count
    end

    it "uses the custom location callback" do
      service = @shrine.resumable_upload(:cache, location: ->(session) { "custom/#{session.id}.bin" })
      session = complete_session(service, "data")

      uploaded_file = service.finalize(session.id)
      assert_equal "custom/#{session.id}.bin", uploaded_file.id
    end

    it "uses the custom metadata callback" do
      service = @shrine.resumable_upload(:cache, metadata: ->(session) { { "custom" => session.id } })
      session = complete_session(service, "data")

      uploaded_file = service.finalize(session.id)
      assert_equal session.id, uploaded_file.metadata["custom"]
    end

    it "uses the custom upload callback" do
      uploaded_file = nil
      service = @shrine.resumable_upload(:cache, upload: ->(io, session, **options) {
        uploaded_file = @shrine.upload(io, :cache, **options)
      })
      session = complete_session(service, "data")

      result = service.finalize(session.id)
      assert_equal uploaded_file, result
      assert_equal "data", result.read
    end
  end

  describe "cleanup" do
    it "removes expired unfinished sessions" do
      expired = @service.create_session(total_size: 10, expires_in: -10)
      current = @service.create_session(total_size: 10)

      deleted = @service.cleanup

      assert_equal [expired.id], deleted.map(&:id)
      assert_nil @service.session_store.find(expired.id)
      assert @service.session_store.find(current.id)
    end

    it "does not affect files already published" do
      session = complete_session(@service, "keep me")
      uploaded_file = @service.finalize(session.id)
      session.expires_at = Time.now.utc - 10
      @service.session_store.update(session)

      @service.cleanup

      assert uploaded_file.exists?
      assert_equal "keep me", uploaded_file.read
    end

    it "aborts unfinished sessions" do
      session = @service.create_session(total_size: 5)
      @service.put_chunk(session.id, "ab", start_offset: 0)

      @service.abort(session.id)

      assert_nil @service.session_store.find(session.id)
      assert_raises(Shrine::ResumableUpload::SessionNotFound) do
        @service.get_session(session.id)
      end
    end

    it "does not abort a finalized session" do
      session = complete_session(@service, "abc")
      @service.finalize(session.id)

      assert_raises(Shrine::ResumableUpload::AlreadyFinalized) do
        @service.abort(session.id)
      end
    end
  end

  describe "custom session store" do
    it "accepts any object implementing the session store interface" do
      store = Shrine::ResumableUpload::FileSystemSessionStore.new(
        File.join(@tmpdir, SecureRandom.hex(4))
      )
      service = @shrine.resumable_upload(:cache, session_store: store)

      content = "disk persisted content"
      session = service.create_session(total_size: content.bytesize)
      service.put_chunk(session.id, content.byteslice(10, 10), start_offset: 10)
      service.put_chunk(session.id, content.byteslice(0, 10), start_offset: 0)
      service.put_chunk(session.id, content.byteslice(20..), start_offset: 20)

      reloaded = store.find(session.id)
      assert_equal [[0, content.bytesize]], reloaded.merged_ranges

      uploaded_file = service.finalize(session.id)
      assert_equal content, uploaded_file.read
    end

    it "keeps finalized file data readable after cleaning the assembly" do
      dir = File.join(@tmpdir, SecureRandom.hex(4))
      store = Shrine::ResumableUpload::FileSystemSessionStore.new(dir)
      service = @shrine.resumable_upload(:cache, session_store: store)

      session = complete_session(service, "published")
      uploaded_file = service.finalize(session.id)
      session.expires_at = Time.now.utc - 10
      store.update(session)

      service.cleanup

      assert uploaded_file.exists?
      assert_equal "published", uploaded_file.read
    end
  end

  it "defines #inspect and #to_s" do
    assert_equal "#<#{@shrine.inspect}::ResumableUpload(:cache)>", @service.inspect
    assert_equal @service.inspect, @service.to_s
  end

  private

  def complete_session(service, content, total_size: content.bytesize, checksum: nil,
                       filename: nil, content_type: nil)
    session = service.create_session(
      total_size: total_size,
      checksum: checksum,
      filename: filename,
      content_type: content_type,
    )

    (0...content.bytesize).each_slice(5) do |offsets|
      start = offsets.first
      bytes = content.byteslice(start, offsets.length)
      service.put_chunk(session.id, bytes, start_offset: start)
    end

    session
  end
end
