require "test_helper"
require "shrine/plugins/deletion_protection"

describe Shrine::Plugins::DeletionProtection do
  # Controllable clock shared by the lambda and the test: advancing it moves
  # the clock that the plugin sees, so boundary values can be checked without
  # any background service.
  class TestClock
    attr_accessor :now
    def initialize(time)
      @now = time
    end

    def advance(seconds)
      @now += seconds
    end
  end

  before do
    @clock = TestClock.new(Time.at(1_000_000))
    clock = @clock
    @attacher = attacher do
      plugin :deletion_protection, retention_period: 60, clock: -> { clock.now }
    end
    @shrine   = @attacher.shrine_class
    @registry = @shrine::Attacher.deletion_protection_registry
  end

  describe "configuration" do
    it "accepts a custom registry" do
      registry = Shrine::Plugins::DeletionProtection::ProtectionRegistry.new
      shrine = Class.new(Shrine)
      shrine.storages[:store] = Shrine::Storage::Memory.new
      shrine.plugin :deletion_protection, registry: registry
      assert_same registry, shrine::Attacher.deletion_protection_registry
    end

    it "gives each configured uploader its own in-memory registry" do
      other = Class.new(Shrine)
      other.storages[:store] = Shrine::Storage::Memory.new
      other.plugin :deletion_protection
      refute_same @registry, other::Attacher.deletion_protection_registry
    end
  end

  describe "Attacher#hold and #release_hold" do
    before do
      @file = @attacher.attach(fakeio)
    end

    it "blocks deletion while a hold is active" do
      @attacher.hold
      assert_equal [:hold_admin], @attacher.deletion_block_reasons(@file)
      assert @attacher.deletion_blocked?(@file)
    end

    it "supports named holds" do
      @attacher.hold(name: :legal)
      assert_equal [:hold_legal], @attacher.deletion_block_reasons(@file)
    end

    it "allows deletion once the hold is released" do
      @attacher.hold
      @attacher.release_hold
      assert_equal [], @attacher.deletion_block_reasons(@file)
    end

    it "keeps other holds when releasing one" do
      @attacher.hold(name: :admin)
      @attacher.hold(name: :legal)
      @attacher.release_hold(name: :admin)
      assert_equal [:hold_legal], @attacher.deletion_block_reasons(@file)
    end

    it "supports timed holds that expire at the boundary" do
      deadline = @clock.now + 60
      @attacher.hold(until_time: deadline)
      @clock.advance(59)
      assert_equal [:hold_admin], @attacher.deletion_block_reasons(@file)
      @clock.advance(1)
      assert_equal [], @attacher.deletion_block_reasons(@file)
    end
  end

  describe "retention" do
    before do
      @file = @attacher.attach(fakeio)
    end

    it "records an absolute deadline with retain_until!" do
      @attacher.retain_until!(@clock.now + 30)
      @attacher.request_destroy(@file)
      assert_equal [:retain_until], @attacher.deletion_block_reasons(@file)
      @clock.advance(29)
      assert_equal [:retain_until], @attacher.deletion_block_reasons(@file)
      @clock.advance(1)
      assert_equal [], @attacher.deletion_block_reasons(@file)
    end

    it "records a relative duration with retain_for!" do
      @attacher.retain_for!(45)
      @attacher.request_destroy(@file)
      @clock.advance(44)
      assert_equal [:retain_until], @attacher.deletion_block_reasons(@file)
      @clock.advance(1)
      assert_equal [], @attacher.deletion_block_reasons(@file)
    end

    it "does not shorten a previously recorded deadline" do
      @attacher.retain_until!(@clock.now + 100)
      @attacher.retain_until!(@clock.now + 10)
      @attacher.request_destroy(@file)
      @clock.advance(50)
      assert_includes @attacher.deletion_block_reasons(@file), :retain_until
    end

    it "applies the configured retention period when destruction is requested" do
      deleted = @attacher.request_destroy(@file)
      refute deleted
      assert @file.exists?
      assert_equal [:retain_until], @attacher.deletion_block_reasons(@file)
      @clock.advance(60)
      assert_equal [], @attacher.deletion_block_reasons(@file)
    end

    it "releasing a hold does not bypass the remaining retention" do
      @attacher.hold
      @attacher.request_destroy(@file)
      @clock.advance(10)
      @attacher.release_hold
      assert_equal [:retain_until], @attacher.deletion_block_reasons(@file)
      assert @file.exists?
    end
  end

  describe "Attacher#request_destroy" do
    it "deletes immediately when no protection is configured" do
      attacher = attacher { plugin :deletion_protection }
      file = attacher.attach(fakeio)
      assert attacher.request_destroy(file)
      refute file.exists?
    end

    it "defers deletion while blocked and deletes once unblocked" do
      file = @attacher.attach(fakeio)
      @attacher.hold
      refute @attacher.request_destroy(file)
      assert file.exists?
      assert @attacher.pending_deletion?(file)
      @attacher.release_hold
      assert_equal [:retain_until], @attacher.deletion_block_reasons(file)
      @clock.advance(60)
      assert @attacher.request_destroy(file)
      refute file.exists?
    end

    it "keeps the file referenced on the attacher when deletion is deferred" do
      file = @attacher.attach(fakeio)
      @attacher.hold
      @attacher.request_destroy(file)
      assert_same file, @attacher.file
    end

    it "returns false when no file is given" do
      refute @attacher.request_destroy(nil)
    end
  end

  describe "replacement" do
    it "marks the old stored file pending instead of deleting it" do
      old_file = @attacher.attach(fakeio)
      @attacher.attach(fakeio)
      @attacher.destroy_previous
      assert old_file.exists?
      state = @registry.get(old_file.storage_key, old_file.id)
      assert state[:pending]
      refute_nil state[:retain_until]
    end

    it "deletes the old file through cleanup once protection expires" do
      old_file = @attacher.attach(fakeio)
      @attacher.attach(fakeio)
      @attacher.destroy_previous
      @clock.advance(59)
      assert_equal [], @attacher.cleanup_deletions
      assert old_file.exists?
      @clock.advance(1)
      assert_equal [old_file.id], @attacher.cleanup_deletions
      refute old_file.exists?
    end

    it "deletes replaced cached files immediately" do
      cached_file = @attacher.attach_cached(fakeio)
      @attacher.attach_cached(fakeio)
      @attacher.destroy_previous
      refute cached_file.exists?
    end
  end

  describe "record destruction" do
    it "routes destroy_attached through the protection rules" do
      file = @attacher.attach(fakeio)
      @attacher.destroy_attached
      assert file.exists?
      assert @registry.get(file.storage_key, file.id)[:pending]
    end
  end

  describe "Attacher#cancel_destroy" do
    it "revokes the pending deletion state" do
      file = @attacher.attach(fakeio)
      @attacher.request_destroy(file)
      @attacher.cancel_destroy(file)
      refute @attacher.pending_deletion?(file)
      assert_includes @attacher.deletion_block_reasons(file), :retain_until
      @clock.advance(60)
      assert_equal [], @attacher.cleanup_deletions
      assert file.exists?
    end

    it "preserves holds and retention after cancelling" do
      file = @attacher.attach(fakeio)
      @attacher.hold
      @attacher.request_destroy(file)
      @attacher.cancel_destroy(file)
      assert_includes @attacher.deletion_block_reasons(file), :hold_admin
    end
  end

  describe "Attacher#deletion_block_reasons" do
    it "returns no reasons for an unknown file" do
      file = @attacher.attach(fakeio)
      assert_equal [], @attacher.deletion_block_reasons(file)
    end

    it "combines retention and hold reasons" do
      file = @attacher.attach(fakeio)
      @attacher.hold
      @attacher.retain_until!(@clock.now + 10)
      assert_equal [:retain_until, :hold_admin],
                   @attacher.deletion_block_reasons(file)
    end
  end

  describe "Attacher#cleanup_deletions" do
    it "deletes only expired pending files" do
      file = @attacher.attach(fakeio)
      @attacher.request_destroy(file)
      @clock.advance(59)
      assert_equal [], @attacher.cleanup_deletions
      assert file.exists?
      @clock.advance(1)
      assert_equal [file.id], @attacher.cleanup_deletions
      refute file.exists?
    end

    it "is scoped to the given storage" do
      @shrine.storages[:other_store] = Shrine::Storage::Memory.new
      file  = @attacher.attach(fakeio)
      other = @attacher.upload(fakeio, :other_store)
      @attacher.request_destroy(file)
      @attacher.request_destroy(other, retain_for: nil)
      @clock.advance(60)
      assert_equal [other.id], @attacher.cleanup_deletions(storage_key: :other_store)
      assert file.exists?
      refute other.exists?
      assert_equal [file.id], @attacher.cleanup_deletions(storage_key: :store)
    end

    it "deletes from every registered storage with cleanup_all_deletions" do
      @shrine.storages[:other_store] = Shrine::Storage::Memory.new
      file  = @attacher.attach(fakeio)
      other = @attacher.upload(fakeio, :other_store)
      @attacher.request_destroy(file)
      @attacher.request_destroy(other, retain_for: nil)
      @clock.advance(60)
      deleted = @attacher.cleanup_all_deletions
      assert_includes deleted, file.id
      assert_includes deleted, other.id
    end

    it "forgets expired records of files that are not pending" do
      file = @attacher.attach(fakeio)
      @attacher.retain_until!(@clock.now + 10)
      @clock.advance(11)
      @attacher.cleanup_deletions
      assert_nil @registry.get(file.storage_key, file.id)
    end

    it "can be triggered as an Attacher class method" do
      file = @attacher.attach(fakeio)
      @attacher.request_destroy(file)
      @clock.advance(60)
      assert_equal [file.id], @shrine::Attacher.cleanup_deletions
      refute file.exists?
    end
  end
end
