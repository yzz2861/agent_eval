# frozen_string_literal: true

require "test_helper"
require "shrine/plugins/deletion_protection"

class ControlledClock
  attr_accessor :time

  def initialize(time)
    @time = time
  end

  def now
    @time
  end

  def advance(seconds)
    @time += seconds
  end
end

describe Shrine::Plugins::DeletionProtection do
  before do
    @now = Time.now
    @clock = ControlledClock.new(@now)
    Thread.current[:dp_clock] = @clock
    @attacher = attacher do
      plugin :deletion_protection, clock: -> { Thread.current[:dp_clock].now }
    end
    @shrine   = @attacher.shrine_class
    @klass    = @shrine::Attacher
  end

  describe "without retention or holds" do
    it "marks pending and deletes immediately on destroy" do
      @attacher.attach(fakeio)
      file = @attacher.file

      assert_equal [:not_pending], @klass.deletion_blockers(file)

      @attacher.destroy

      refute file.exists?
      refute @klass.protection_record(file)
    end

    it "does nothing when no file is attached" do
      @attacher.destroy # should not raise
      refute @attacher.attached?
    end
  end

  describe "retention period" do
    before do
      @shrine.plugin :deletion_protection, retention: 60
    end

    it "keeps the file while retention is active" do
      @attacher.attach(fakeio)
      file = @attacher.file

      @attacher.destroy

      assert file.exists?
      assert_includes @klass.deletion_blockers(file), :retention
      @clock.time = @now + 59
      assert_includes @klass.deletion_blockers(file), :retention
      @clock.time = @now + 60
      assert_equal [], @klass.deletion_blockers(file)
    end

    it "uses the boundary time exactly (retain_until is inclusive)" do
      @attacher.attach(fakeio)
      file = @attacher.file
      @attacher.destroy

      deadline = @klass.protection_record(file)[:retain_until]
      assert_equal @now + 60, deadline
      assert_includes @klass.deletion_blockers(file, at: deadline - 1), :retention
      assert_equal [], @klass.deletion_blockers(file, at: deadline)
    end

    it "deletes in cleanup once retention expires" do
      @attacher.attach(fakeio)
      file = @attacher.file
      @attacher.destroy

      @clock.time = @now + 59
      assert_equal [], @klass.cleanup_pending_deletions
      assert file.exists?

      @clock.time = @now + 60
      deleted = @klass.cleanup_pending_deletions
      assert_equal [file.id], deleted.map(&:id)
      refute file.exists?
      refute @klass.protection_record(file)
    end

    it "supports a callable retention" do
      @shrine.plugin :deletion_protection, retention: ->(file, context) { context[:keep] ? 100 : 10 }
      @attacher.context[:keep] = true
      @attacher.attach(fakeio)
      file = @attacher.file
      @attacher.destroy

      assert_equal @now + 100, @klass.protection_record(file)[:retain_until]
    end
  end

  describe "holds" do
    it "blocks deletion while a hold is active" do
      @attacher.attach(fakeio)
      file = @attacher.file

      @klass.hold_deletion(file, :legal)
      @klass.mark_pending_deletion(file)

      assert @klass.deletion_held?(file)
      assert_includes @klass.deletion_blockers(file), :hold
      refute @klass.deletable?(file)
    end

    it "allows deletion after the hold is released" do
      @attacher.attach(fakeio)
      file = @attacher.file

      @attacher.hold_deletion(:legal)
      @attacher.destroy
      assert file.exists?

      @attacher.release_deletion_hold(:legal)
      refute @attacher.deletion_held?
      assert_equal [], @attacher.deletion_blockers
    end

    it "does not bypass remaining retention when the hold is released" do
      @shrine.plugin :deletion_protection, retention: 30
      @attacher.attach(fakeio)
      file = @attacher.file

      @attacher.hold_deletion(:legal)
      @attacher.destroy
      @attacher.release_deletion_hold(:legal)

      assert_equal [:retention], @klass.deletion_blockers(file)
    end

    it "supports multiple independent holds" do
      @attacher.attach(fakeio)
      file = @attacher.file

      @klass.hold_deletion(file, :legal)
      @klass.hold_deletion(file, :audit)
      @klass.mark_pending_deletion(file)
      @klass.release_deletion_hold(file, :legal)

      assert_includes @klass.deletion_blockers(file), :hold

      @klass.release_deletion_hold(file, :audit)
      assert_equal [], @klass.deletion_blockers(file)
    end

    it "expires timed holds automatically" do
      @attacher.attach(fakeio)
      file = @attacher.file

      @klass.hold_deletion(file, :freeze, until: @now + 10)
      @klass.mark_pending_deletion(file)

      assert @klass.deletion_held?(file, at: @now + 9)
      refute @klass.deletion_held?(file, at: @now + 10)
      assert_equal [], @klass.deletion_blockers(file, at: @now + 10)
    end

    it "keeps a file through retention expiry when an untimed hold remains" do
      @shrine.plugin :deletion_protection, retention: 5
      @attacher.attach(fakeio)
      file = @attacher.file

      @klass.hold_deletion(file, :legal)
      @klass.mark_pending_deletion(file)

      assert_equal [], @klass.cleanup_pending_deletions(at: @now + 100)
      assert file.exists?
    end
  end

  describe "replacement" do
    it "routes the old file through the same rules as destroy" do
      @shrine.plugin :deletion_protection, retention: 60

      @attacher.attach(fakeio)
      old_file = @attacher.file
      @attacher.attach(fakeio)
      @attacher.destroy_previous

      assert old_file.exists?
      assert @klass.pending_deletion?(old_file)
      assert_includes @klass.deletion_blockers(old_file), :retention
      assert @attacher.file.exists?
    end

    it "physically removes the old file immediately without protection" do
      @attacher.attach(fakeio)
      old_file = @attacher.file
      @attacher.attach(fakeio)
      @attacher.destroy_previous

      refute old_file.exists?
    end

    it "honours holds on replaced old files" do
      @attacher.attach(fakeio)
      old_file = @attacher.file
      @klass.hold_deletion(old_file, :legal)
      @attacher.attach(fakeio)
      @attacher.destroy_previous

      assert old_file.exists?
      assert_includes @klass.deletion_blockers(old_file), :hold
    end

    it "protects old files cleaned up through finalize" do
      @shrine.plugin :deletion_protection, retention: 30

      @attacher.attach(fakeio)
      old_file = @attacher.file
      @attacher.attach(fakeio)
      @attacher.finalize

      assert old_file.exists?
      assert_includes @klass.deletion_blockers(old_file), :retention
    end
  end

  describe "undo pending deletion" do
    it "clears the pending state and reports :not_pending" do
      @shrine.plugin :deletion_protection, retention: 60
      @attacher.attach(fakeio)
      file = @attacher.file

      @attacher.destroy
      assert @klass.pending_deletion?(file)

      @klass.undo_pending_deletion(file)
      refute @klass.pending_deletion?(file)
      blockers = @klass.deletion_blockers(file)
      assert_includes blockers, :not_pending
      assert file.exists?
    end

    it "keeps holds and retention history" do
      @attacher.attach(fakeio)
      file = @attacher.file

      @klass.hold_deletion(file, :legal)
      @klass.mark_pending_deletion(file)
      @klass.undo_pending_deletion(file)

      assert @klass.deletion_held?(file)
    end
  end

  describe "cached files" do
    it "deletes cached files directly" do
      @shrine.plugin :deletion_protection, retention: 60
      @attacher.assign(fakeio)
      cached_file = @attacher.file
      assert @attacher.cached?

      @attacher.destroy

      refute cached_file.exists?
    end
  end

  describe "cleanup" do
    it "only deletes pending files" do
      @attacher.attach(fakeio)
      referenced = @attacher.file

      deleted = @klass.cleanup_pending_deletions

      assert_equal [], deleted
      assert referenced.exists?
    end

    it "can reconstruct files across attacher instances" do
      @shrine.plugin :deletion_protection, retention: 1
      @attacher.attach(fakeio)
      file = @attacher.file
      @attacher.destroy

      new_attacher = @shrine::Attacher.new
      deleted = new_attacher.class.cleanup_pending_deletions(at: @now + 1)
      assert_equal [file.id], deleted.map(&:id)
    end

    it "deletes a file once an expiring hold lapses" do
      @attacher.attach(fakeio)
      file = @attacher.file
      @klass.hold_deletion(file, :freeze, until: @now + 10)
      @klass.mark_pending_deletion(file)

      @clock.advance(9)
      assert_equal [], @klass.cleanup_pending_deletions
      assert file.exists?

      @clock.advance(1)
      assert_equal [file.id], @klass.cleanup_pending_deletions.map(&:id)
      refute file.exists?
    end
  end

  describe "custom store" do
    it "uses the configured store" do
      store = Shrine::Plugins::DeletionProtection::MemoryStore.new
      shrine = shrine { plugin :deletion_protection, store: store }
      attacher = shrine::Attacher.new
      attacher.attach(fakeio)
      file = attacher.file
      attacher.hold_deletion(:legal)
      attacher.destroy

      assert_same store, shrine::Attacher.deletion_protection_store
      assert store.fetch([file.storage_key.to_s, file.id])
    end
  end
end
