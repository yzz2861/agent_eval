require "test_helper"
require "shrine/upload_session"

describe Shrine::UploadSession do
  it "tracks and merges adjacent ranges" do
    session = described(total_size: 10, ranges: [[6, 10]])

    session.add_range!(0, 6)

    assert_equal [[0, 10]], session.ranges
    assert session.complete?
  end

  it "keeps gappy ranges separate" do
    session = described(total_size: 10, ranges: [[8, 10]])

    session.add_range!(0, 2)

    assert_equal [[0, 2], [8, 10]], session.ranges
    refute session.complete?
  end

  it "treats an empty file as complete without ranges" do
    session = described(total_size: 0)

    assert session.complete?
  end

  it "is finalized only once an uploaded id is assigned" do
    refute described(total_size: 1).finalized?

    session = described(total_size: 1, uploaded_id: "file")

    assert session.finalized?
  end

  it "is expired once the expiration time is reached" do
    now = Time.now

    refute described(total_size: 1, expires_at: now + 10).expired?(now)
    assert described(total_size: 1, expires_at: now).expired?(now)
    refute described(total_size: 1).expired?(now)
  end

  it "round-trips through a JSON-compatible hash" do
    session = described(total_size: 3, ranges: [[0, 3]], expires_at: Time.now)
    hash    = session.to_h

    assert_equal 3, hash["total_size"]

    restored = Shrine::UploadSession.from_h(JSON.parse(JSON.generate(hash)))

    assert_equal session.id, restored.id
    assert_equal session.ranges, restored.ranges
    assert_kind_of Time, restored.expires_at
  end

  it "generates unique ids" do
    ids = Array.new(3) { Shrine::UploadSession.generate_id }

    assert_equal 3, ids.uniq.count
    assert(ids.all? { |id| id =~ /\Aus-[0-9a-f]{32}\z/ })
  end

  def described(**options)
    defaults = { id: "session", total_size: 1 }
    Shrine::UploadSession.new(**defaults.merge(options))
  end
end

describe Shrine::UploadSessions::Memory do
  before do
    @store = Shrine::UploadSessions::Memory.new
    @session = Shrine::UploadSession.new(id: "session", total_size: 1)
  end

  it "creates and reads sessions" do
    @store.create(@session)

    assert_equal @session, @store.read("session")
  end

  it "rejects creating a duplicate session" do
    @store.create(@session)

    assert_raises(Shrine::UploadSessionError) { @store.create(@session) }
  end

  it "raises a not found error for unknown sessions" do
    assert_raises(Shrine::UploadSessionNotFound) { @store.read("missing") }
    assert_raises(Shrine::UploadSessionNotFound) do
      @store.fetch("missing") { }
    end
  end

  it "atomically read-modify-writes sessions" do
    @store.create(@session)

    @store.fetch("session") { |session| session.add_range!(0, 1) }

    assert_equal [[0, 1]], @store.read("session").ranges
  end

  it "rolls back modifications when the block raises" do
    @store.create(@session)

    assert_raises(RuntimeError) do
      @store.fetch("session") do |session|
        session.add_range!(0, 1)
        raise "boom"
      end
    end

    assert_equal [], @store.read("session").ranges
  end

  it "deletes sessions" do
    @store.create(@session)

    assert_equal @session, @store.delete("session")
    assert_nil @store.delete("session")
  end

  it "prunes only expired sessions" do
    expired = Shrine::UploadSession.new(id: "expired", total_size: 1, expires_at: Time.now - 1)
    fresh   = Shrine::UploadSession.new(id: "fresh",   total_size: 1, expires_at: Time.now + 10)

    @store.create(expired)
    @store.create(fresh)

    removed = @store.prune_expired!

    assert_equal ["expired"], removed.map(&:id)
    assert @store.read("fresh")
    assert_raises(Shrine::UploadSessionNotFound) { @store.read("expired") }
  end
end
