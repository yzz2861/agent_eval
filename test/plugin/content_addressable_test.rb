require "test_helper"

require "shrine/storage/ref_store"
require "digest"

# In-process RefStore used to exercise the content_addressable plugin. It
# serializes per key with a Mutex and accepts injection points so tests can
# park threads at precise barriers and reproduce upload/delete interleave.
class TestRefStore
  include Shrine::Storage::RefStore

  attr_accessor :before_release

  def initialize
    @mutex         = Mutex.new
    @counts        = Hash.new(0)
    @known         = {}
    @waiters       = Hash.new(0)
    @waiters_mutex = Mutex.new
  end

  def acquire(key)
    synchronize(key) do
      created = !@known.key?(key)

      begin
        result = yield(created)
      rescue
        @known.delete(key) if created
        @counts.delete(key) if created
        raise
      end

      @known[key] = true
      @counts[key] += 1
      [created, result]
    end
  end

  def release(key)
    synchronize(key) do
      before_release&.call(key)

      return block_given? ? yield(false) : false unless @known.key?(key)

      @counts[key] -= 1

      if @counts[key] <= 0
        @known.delete(key)
        @counts.delete(key)
        last = true
      else
        last = false
      end

      block_given? ? yield(last) : last
    end
  end

  def count(key)
    @mutex.synchronize { @counts[key] || 0 }
  end

  def waiters(key)
    @waiters_mutex.synchronize { @waiters[key] }
  end

  # Wraps the per-key critical section and tracks how many threads are
  # currently waiting on or holding the lock, letting tests deterministically
  # park a thread at a barrier and confirm another is queued behind it.
  def synchronize(key)
    @waiters_mutex.synchronize { @waiters[key] += 1 }
    @mutex.synchronize { yield }
  ensure
    @waiters_mutex.synchronize { @waiters[key] -= 1 }
  end

  def clear!
    @mutex.synchronize { @counts.clear; @known.clear }
  end
end

describe "content_addressable plugin" do
  before do
    @ref_store = TestRefStore.new
    ref_store = @ref_store
    @shrine = shrine do
      plugin :content_addressable, ref_store: ref_store
    end
  end

  def digest(content, algorithm = :sha256)
    Digest.const_get(algorithm.to_s.upcase).hexdigest(content)
  end

  it "requires a ref_store" do
    assert_raises(Shrine::Error) do
      Class.new(Shrine) { plugin :content_addressable }
    end
  end

  it "accepts per-storage ref stores and an optional storage allowlist" do
    store_refs = TestRefStore.new
    cache_refs = TestRefStore.new

    uploader_class = shrine do
      plugin :content_addressable,
             ref_store: { store: store_refs, cache: cache_refs },
             storages: [:store]
    end

    assert_equal store_refs, uploader_class.content_addressable_ref_store(:store)
    assert_nil uploader_class.content_addressable_ref_store(:cache)
  end

  describe "Shrine#upload" do
    it "stores the blob under the digest of the server-read content" do
      file = @shrine.upload(fakeio("hello"), :store)

      assert_equal digest("hello"), file.id
      assert @shrine.storages[:store].exists?(file.id)
    end

    it "shares one blob for identical content while keeping independent metadata" do
      first  = @shrine.upload(fakeio("hello", filename: "a.txt", content_type: "text/plain"), :store)
      second = @shrine.upload(fakeio("hello", filename: "b.csv", content_type: "text/csv"), :store)

      assert_equal first.id, second.id
      assert_equal 1, @shrine.storages[:store].store.keys.count
      assert_equal "a.txt", first.original_filename
      assert_equal "b.csv", second.original_filename
      assert_equal "text/plain", first.mime_type
      assert_equal "text/csv", second.mime_type
      assert_equal 2, @ref_store.count(first.id)
    end

    it "creates separate blobs for different content" do
      first  = @shrine.upload(fakeio("hello"), :store)
      second = @shrine.upload(fakeio("world"), :store)

      refute_equal first.id, second.id
      assert_equal 1, @ref_store.count(first.id)
      assert_equal 1, @ref_store.count(second.id)
    end

    it "closes non-file IO objects after upload" do
      io = fakeio("hello")
      @shrine.upload(io, :store)
      assert io.closed?
    end

    it "can read the shared content back" do
      file = @shrine.upload(fakeio("shared"), :store)
      assert_equal "shared", file.read
    end

    it "bypasses reference management for explicit locations" do
      io = fakeio("hello")
      file = @shrine.upload(io, :store, location: "manual/path.txt")

      assert_equal "manual/path.txt", file.id
      assert_equal 0, @ref_store.count(digest("hello"))
    end

    it "leaves storages without a ref store untouched" do
      uploader_class = shrine do
        plugin :content_addressable, ref_store: { store: TestRefStore.new }
      end

      file = uploader_class.upload(fakeio("hello", filename: "x.txt"), :cache, location: nil)
      refute_equal digest("hello"), file.id
    end

    it "raises and does not add a reference when a referenced blob is physically missing" do
      first = @shrine.upload(fakeio("hello"), :store)
      @shrine.storages[:store].delete(first.id) # corrupt: ref remains, blob gone

      assert_raises(Shrine::Error) do
        @shrine.upload(fakeio("hello"), :store)
      end

      assert_equal 1, @ref_store.count(first.id) # unchanged
    end

    describe "failure isolation" do
      it "rolls back the reference when the first blob upload fails" do
        underlying = @shrine.storages[:store]
        attempts = 0
        failing_storage = Object.new
        failing_storage.define_singleton_method(:method_missing) { |name, *args, **options, &block| underlying.send(name, *args, **options, &block) }
        failing_storage.define_singleton_method(:respond_to_missing?) { |name, include_private = false| underlying.respond_to?(name, include_private) }
        failing_storage.define_singleton_method(:upload) do |io, id, **options|
          attempts += 1
          raise StandardError, "disk full" if attempts == 1

          underlying.upload(io, id, **options)
        end
        @shrine.storages[:store] = failing_storage

        assert_raises(StandardError) { @shrine.upload(fakeio("hello"), :store) }
        assert_equal 0, @ref_store.count(digest("hello"))

        # A later upload of the same content becomes the creator again and
        # succeeds; nothing references the failed attempt's blob.
        file = @shrine.upload(fakeio("hello"), :store)
        assert_equal digest("hello"), file.id
        assert_equal 1, @ref_store.count(file.id)
      end

      it "does not delete another attachment's blob when an upload fails" do
        first = @shrine.upload(fakeio("shared"), :store)

        underlying = @shrine.storages[:store]
        failing_storage = Object.new
        failing_storage.define_singleton_method(:method_missing) { |name, *args, **options, &block| underlying.send(name, *args, **options, &block) }
        failing_storage.define_singleton_method(:respond_to_missing?) { |name, include_private = false| underlying.respond_to?(name, include_private) }
        failing_storage.define_singleton_method(:upload) { |*| raise StandardError, "boom" }
        @shrine.storages[:store] = failing_storage

        # A different upload fails for an unrelated reason; the existing
        # attachment's blob must remain untouched.
        assert_raises(StandardError) { @shrine.upload(fakeio("different"), :store) }

        assert first.exists?
        assert_equal 1, @ref_store.count(first.id)
      end
    end

    describe "concurrency" do
      it "uploads identical content only once when first references are created simultaneously" do
        uploads  = AtomicCounter.new
        storage  = @shrine.storages[:store]
        started  = Queue.new
        proceed  = Queue.new

        storage.singleton_class.alias_method(:original_upload, :upload)
        storage.define_singleton_method(:upload) do |io, id, **options|
          started << id
          proceed.pop
          uploads.increment
          original_upload(io, id, **options)
        end

        threads = 2.times.map do
          Thread.new { @shrine.upload(fakeio("same"), :store) }
        end

        assert_equal digest("same"), started.pop
        proceed << true
        files = threads.map { |thread| thread.join.value }

        assert_equal 1, uploads.value
        assert_equal files.first.id, files.last.id
        assert_equal 2, @ref_store.count(files.first.id)
      end

      it "keeps a shared blob when the last delete releases while a new reference is joining" do
        first  = @shrine.upload(fakeio("same"), :store)
        second = @shrine.upload(fakeio("same"), :store)
        key    = first.id

        release_locked  = Queue.new
        release_proceed = Queue.new

        @ref_store.before_release = lambda do |release_key|
          next unless release_key == key && Thread.current[:phase] == :delete

          release_locked << true
          release_proceed.pop
        end

        # The deleter wins the mutex first (two refs exist, so this release
        # is not the last) and parks while still holding it.
        deleter = Thread.new do
          Thread.current[:phase] = :delete
          first.delete
        end
        assert release_locked.pop

        # The joiner reaches the mutex and queues behind the parked release.
        joiner = Thread.new do
          Thread.current[:phase] = :join
          @shrine.upload(fakeio("same"), :store)
        end
        deadline = Time.now + 2
        nil while @ref_store.waiters(key) == 0 && joiner.alive? && Time.now < deadline
        assert_equal 1, @ref_store.waiters(key)
        assert joiner.alive?

        # Release completes without deleting; the queued joiner then enters
        # the critical section as an existing-blob reference.
        release_proceed << true
        deleter.join
        joined = joiner.join.value

        assert_equal key, joined.id
        assert second.exists?
        assert_equal 2, @ref_store.count(key) # second attachment + joiner

        joined.delete
        assert second.exists?
        second.delete
        refute second.exists?
        assert_equal 0, @ref_store.count(key)
      end

      it "deletes the blob only when the final reference is released" do
        first  = @shrine.upload(fakeio("same"), :store)
        second = @shrine.upload(fakeio("same"), :store)

        first.delete
        assert second.exists?, "blob must survive while a reference remains"
        assert_equal 1, @ref_store.count(first.id)

        second.delete
        refute second.exists?
        assert_equal 0, @ref_store.count(first.id)
      end
    end
  end

  describe "Attacher integration" do
    it "shares blobs across attachments and releases them on destroy" do
      attacher_one = @shrine::Attacher.new
      attacher_two = @shrine::Attacher.new

      attacher_one.attach(fakeio("record", filename: "one.bin"))
      attacher_two.attach(fakeio("record", filename: "two.bin"))

      assert_equal attacher_one.file.id, attacher_two.file.id
      assert_equal "one.bin", attacher_one.file.original_filename
      assert_equal "two.bin", attacher_two.file.original_filename
      assert_equal 2, @ref_store.count(attacher_one.file.id)

      attacher_one.destroy
      assert attacher_two.file.exists?
      attacher_two.destroy
      refute attacher_two.file.exists?
    end

    it "uses independent ref stores for cache and store when promoting" do
      cache_refs = TestRefStore.new
      store_refs = TestRefStore.new
      uploader_class = shrine do
        plugin :content_addressable, ref_store: { cache: cache_refs, store: store_refs }
      end

      attacher = uploader_class::Attacher.new
      attacher.attach(fakeio("data"), storage: :cache)
      cached = attacher.file
      assert_equal 1, cache_refs.count(cached.id)

      attacher.promote
      stored = attacher.file
      # Shrine leaves cached blobs for the application to clean up.
      assert_equal 1, cache_refs.count(cached.id)
      assert_equal 1, store_refs.count(stored.id)
      assert stored.exists?

      attacher.destroy
      assert_equal 0, store_refs.count(stored.id)
      refute stored.exists?
    end
  end
end
