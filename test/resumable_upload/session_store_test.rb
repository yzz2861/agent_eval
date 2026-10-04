require "test_helper"
require "shrine/plugins/resumable_uploads"
require "fileutils"

describe Shrine::ResumableUpload::MemorySessionStore do
  before do
    @store = Shrine::ResumableUpload::MemorySessionStore.new
  end

  it "returns nil for unknown sessions" do
    assert_nil @store.find("missing")
  end

  it "writes and reads chunks, including at out-of-order offsets" do
    session = new_session("s1", 12)
    @store.create(session)

    @store.write_chunk(session, 8, "ijkl")
    @store.write_chunk(session, 0, "abcdefgh")

    assert_equal "abc", @store.read_chunk(session, 0, 3)
    assert_equal "ijkl", @store.read_chunk(session, 8, 4)
    assert_equal "fgh", @store.read_chunk(session, 5, 3)
  end

  it "enumerates sessions and deletes them" do
    first  = new_session("a", 1)
    second = new_session("b", 2)
    @store.create(first)
    @store.create(second)

    assert_equal %w[a b], @store.map(&:id)

    @store.delete(second)
    assert_equal %w[a], @store.map(&:id)
    assert_nil @store.find("b")
  end

  private

  def new_session(id, size)
    Shrine::ResumableUpload::Session.new(id: id, total_size: size)
  end
end

describe Shrine::ResumableUpload::FileSystemSessionStore do
  before do
    @directory = File.join("tmp", "session-store-test", SecureRandom.hex(4))
    FileUtils.rm_rf(@directory)
    @store = Shrine::ResumableUpload::FileSystemSessionStore.new(@directory)
  end

  after do
    FileUtils.rm_rf(@directory)
  end

  it "persists sessions and chunks across instances" do
    session = Shrine::ResumableUpload::Session.new(
      id: "abc123", total_size: 11, ranges: [],
      expires_at: Time.now.utc + 3600,
    )
    @store.create(session)
    @store.write_chunk(session, 6, "world")
    @store.write_chunk(session, 0, "hello ")
    session.ranges = [[0, 6], [6, 11]]
    @store.update(session)

    reopened = Shrine::ResumableUpload::FileSystemSessionStore.new(@directory)
    loaded = reopened.find("abc123")

    refute_nil loaded
    assert_equal 11, loaded.total_size
    assert_equal [[0, 11]], loaded.merged_ranges

    reopened.open(loaded) do |io|
      assert_equal "hello world", io.read
    end
  end

  it "supports out-of-order writes beyond the current assembly size" do
    session = Shrine::ResumableUpload::Session.new(id: "ooo", total_size: 8)
    @store.create(session)
    @store.write_chunk(session, 4, "EFGH")
    @store.write_chunk(session, 0, "ABCD")

    assert_equal "ABCDEFGH", @store.read_chunk(session, 0, 8)
  end

  it "cleans up expired sessions and their assemblies" do
    expired = Shrine::ResumableUpload::Session.new(
      id: "old", total_size: 1, ranges: [], expires_at: Time.now.utc - 10,
    )
    current = Shrine::ResumableUpload::Session.new(
      id: "new", total_size: 1, ranges: [], expires_at: Time.now.utc + 10,
    )
    @store.create(expired)
    @store.create(current)
    @store.write_chunk(expired, 0, "x")

    deleted = @store.cleanup

    assert_equal %w[old], deleted.map(&:id)
    assert_nil @store.find("old")
    refute_nil @store.find("new")
    refute File.exist?(File.join(@directory, "old.part"))
  end

  it "refuses to look up ids that could escape the directory" do
    assert_nil @store.find("../../etc/passwd")
  end
end
