require "test_helper"

require "shrine/storage/file_system_ref_store"

require "fileutils"
require "tmpdir"

describe Shrine::Storage::FileSystemRefStore do
  def ref_store(directory = root)
    Shrine::Storage::FileSystemRefStore.new(directory)
  end

  def root
    File.join(Dir.tmpdir, "shrine-ref-store")
  end

  before do
    FileUtils.rm_rf(root)
    @store = ref_store
  end

  after do
    FileUtils.rm_rf(root)
  end

  it "implements the RefStore protocol" do
    assert_kind_of Shrine::Storage::RefStore, @store
    assert_respond_to @store, :acquire
    assert_respond_to @store, :release
  end

  describe "#acquire" do
    it "marks the first reference as creator and later references as existing" do
      created, result = @store.acquire("key1") { |create| create ? :written : :skipped }

      assert_equal true, created
      assert_equal :written, result
      assert_equal 1, @store.count("key1")

      created, result = @store.acquire("key1") { |create| create ? :written : :skipped }

      assert_equal false, created
      assert_equal :skipped, result
      assert_equal 2, @store.count("key1")
    end

    it "returns the block result" do
      _, result = @store.acquire("key1") { 42 }
      assert_equal 42, result
    end

    it "rolls back the first reference when the block raises" do
      assert_raises(RuntimeError) do
        @store.acquire("key1") { raise "upload failed" }
      end

      assert_equal 0, @store.count("key1")

      created, = @store.acquire("key1") { |create| create }
      assert_equal true, created
    end

    it "rejects keys that escape the reference directory" do
      assert_raises(Shrine::Error) do
        @store.acquire("../evil") { }
      end
    end

    it "persists reference counts across instances" do
      @store.acquire("key1") { }

      assert_equal 1, ref_store.count("key1")
    end

    it "serializes simultaneous creation of the first reference" do
      entries = Queue.new
      proceed = Queue.new
      creators = ThreadSafeArray.new
      uploads = AtomicCounter.new

      instrumented = build_instrumented_store do |phase, key|
        if Thread.current[:ref_phase] && key == "race-create" && phase == :synchronize
          entries << :entered
          proceed.pop
        end
      end

      threads = 2.times.map do
        Thread.new do
          Thread.current[:ref_phase] = :acquire
          instrumented.acquire("race-create") do |created|
            creators << created
            uploads.increment if created
          end
        end
      end

      release_one(entries, proceed, threads)
      release_one(entries, proceed, threads)
      threads.each(&:join)

      assert_equal [true, false], creators.to_a.sort_by { |created| created ? 0 : 1 }
      assert_equal 1, uploads.value
      assert_equal 2, instrumented.count("race-create")
    end
  end

  describe "#release" do
    it "returns false while other references remain" do
      @store.acquire("key1") { }
      @store.acquire("key1") { }

      assert_equal false, @store.release("key1")
      assert_equal 1, @store.count("key1")
    end

    it "returns true for the last reference" do
      @store.acquire("key1") { }

      assert_equal true, @store.release("key1")
      assert_equal 0, @store.count("key1")
    end

    it "yields the last flag while holding the lock and is idempotent" do
      @store.acquire("key1") { }

      yielded = []
      result = @store.release("key1") { |last| yielded << last; :deleted }
      assert_equal :deleted, result
      assert_equal [true], yielded

      assert_equal false, @store.release("key1") { |last| last }
    end

    it "lets a queued new reference recreate the blob when the last release completes first" do
      @store.acquire("race-key") { }

      release_entered = Queue.new
      release_proceed = Queue.new
      acquire_entered = Queue.new
      acquire_proceed = Queue.new
      deletions = AtomicCounter.new

      instrumented = build_instrumented_store do |phase, key|
        case [Thread.current[:ref_phase], key, phase]
        when [:release, "race-key", :synchronize]
          release_entered << true
          release_proceed.pop
        when [:acquire, "race-key", :synchronize]
          acquire_entered << true
          acquire_proceed.pop
        end
      end

      deleter = Thread.new do
        Thread.current[:ref_phase] = :release
        instrumented.release("race-key") { |last| deletions.increment if last }
      end

      joiner = Thread.new do
        Thread.current[:ref_phase] = :acquire
        created, = instrumented.acquire("race-key") { |create| create }
        created
      end

      assert release_entered.pop # deleter owns the lock
      sleep 0.05
      assert joiner.alive?, "joiner must block while the deleter holds the lock"

      release_proceed << true
      deleter.join

      assert acquire_entered.pop # joiner owns the lock only after release
      assert joiner.alive?
      acquire_proceed << true
      assert_equal true, joiner.value      # queued acquire becomes the new creator
      assert_equal 1, deletions.value      # last release deleted the old blob
      assert_equal 1, instrumented.count("race-key")

      # The freshly acquired reference is fully functional and its release
      # deletes the recreated blob.
      instrumented.release("race-key") { |last| deletions.increment if last }
      assert_equal 2, deletions.value
      assert_equal 0, instrumented.count("race-key")
    end

    it "keeps the blob when a release and a joining acquire interleave" do
      # Two attachments reference the blob.
      2.times { @store.acquire("race-key") { } }

      acquire_entered = Queue.new
      acquire_proceed = Queue.new
      release_entered = Queue.new
      release_proceed = Queue.new
      deletions = AtomicCounter.new

      instrumented = build_instrumented_store do |phase, key|
        case [Thread.current[:ref_phase], key, phase]
        when [:acquire, "race-key", :synchronize]
          acquire_entered << true
          acquire_proceed.pop
        when [:release, "race-key", :synchronize]
          release_entered << true
          release_proceed.pop
        end
      end

      # A new reference joins first (count 2 -> 3) ...
      joiner = Thread.new do
        Thread.current[:ref_phase] = :acquire
        instrumented.acquire("race-key") { |create| create }
      end
      assert acquire_entered.pop
      acquire_proceed << true
      joiner.join

      # ... and then a release runs (count 3 -> 2), which must not be
      # treated as the last reference even though it raced with the join.
      releaser = Thread.new do
        Thread.current[:ref_phase] = :release
        instrumented.release("race-key") { |last| deletions.increment if last }
      end
      assert release_entered.pop
      release_proceed << true
      releaser.join

      assert_equal 0, deletions.value
      assert_equal 2, instrumented.count("race-key")
    end

    it "keeps counts consistent under concurrent acquire/release interchanges" do
      keys = Array.new(8) { |i| "stress#{i}" }
      errors = ThreadSafeArray.new

      threads = 4.times.map do
        Thread.new do
          100.times do |i|
            key = keys[i % keys.size]
            @store.acquire(key) { }
            @store.release(key)
          rescue => error
            errors << error
          end
        end
      end
      threads.each(&:join)

      assert_empty errors.to_a
      keys.each { |key| assert_equal 0, @store.count(key) }
    end
  end

  it "can be cleared" do
    @store.acquire("key1") { }
    @store.clear!
    assert_equal 0, @store.count("key1")
  end

  if Process.respond_to?(:fork)
    it "coordinates references across separate processes with file locks" do
      created_read, created_write = IO.pipe
      blobs = File.join(root, "blobs")
      FileUtils.mkpath(blobs)

      pid = fork do
        created_read.close
        store = ref_store
        created, = store.acquire("shared-key") do |create|
          File.write(File.join(blobs, "shared-key"), "bytes") if create
        end
        created_write.write(created ? "1" : "0")
        created_write.close
      end

      created_write.close
      Process.wait(pid)
      assert_equal "1", created_read.read

      # The parent now joins the existing reference created in the child.
      created, = @store.acquire("shared-key") { |create| create }
      assert_equal false, created
      assert_equal 2, @store.count("shared-key")
    end
  end

  private

  # Builds a RefStore whose per-key locking can be paused at a barrier.
  # The given hook runs just before a thread parks waiting for permission,
  # which makes thread interleavings deterministic.
  def build_instrumented_store(&barrier)
    Class.new(Shrine::Storage::FileSystemRefStore) do
      attr_writer :barrier

      private

      define_method(:synchronize) do |key, &block|
        @barrier&.call(:synchronize, key)
        super(key, &block)
      end
    end.new(root).tap { |store| store.barrier = barrier }
  end

  def release_one(entries, proceed, threads)
    assert_equal :entered, entries.pop
    proceed << true
    finished = threads.select { |thread| !thread.alive? }
    finished.each(&:join)
  end
end
