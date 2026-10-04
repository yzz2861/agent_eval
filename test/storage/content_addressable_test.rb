require "test_helper"
require "shrine/storage/content_addressable"
require "shrine/storage/linter"

describe Shrine::Storage::ContentAddressable do
  # Memory storage which allows hooking into upload/delete, so that tests
  # can pause inside storage operations and reproduce race interleavings.
  class HookedMemory < Shrine::Storage::Memory
    attr_accessor :on_upload, :on_delete
    attr_reader :uploads, :deletes

    def initialize(*)
      super
      @uploads = Queue.new
      @deletes = Queue.new
    end

    def upload(...)
      @on_upload.call if @on_upload
      super
      @uploads << true
    end

    def delete(...)
      @on_delete.call if @on_delete
      super
      @deletes << true
    end
  end

  # Holds the current thread until +release+ is called, and signals via
  # +entered+ that it has been reached.
  class Gate
    def initialize
      @entered  = Queue.new
      @released = Queue.new
    end

    def wait
      @entered << true
      @released.pop
    end

    def entered
      @entered.pop
    end

    def release
      @released << true
    end
  end

  before do
    @backend = HookedMemory.new
    @refs    = Shrine::Storage::ContentAddressable::MemoryRefs.new
    @storage = Shrine::Storage::ContentAddressable.new(@backend, refs: @refs)
  end

  it "passes the linter" do
    assert Shrine::Storage::Linter.call(@storage)
  end

  it "forwards keyword arguments to the backend" do
    backend = mock
    backend.expects(:upload).with(kind_of(FakeIO), "key", shrine_metadata: { "foo" => "bar" }, foo: "bar")
    storage = Shrine::Storage::ContentAddressable.new(backend, refs: @refs)

    storage.upload(fakeio, "key", shrine_metadata: { "foo" => "bar" }, foo: "bar")
  end

  describe "#upload" do
    it "uploads the file only once for multiple references" do
      @storage.upload(fakeio("one"), "key")
      @storage.upload(fakeio("two"), "key")

      assert_equal 1, @backend.uploads.size
      assert_equal "one", @backend.open("key").read
      assert_equal 2, @refs.count("key")
    end

    it "rolls back the reference when the upload fails" do
      @backend.stubs(:upload).raises(Errno::ENOENT)

      assert_raises(Errno::ENOENT) { @storage.upload(fakeio, "key") }
      assert_equal 0, @refs.count("key")

      @backend.unstub(:upload)
      @storage.upload(fakeio("content"), "key")

      assert_equal "content", @backend.open("key").read
      assert_equal 1, @refs.count("key")
    end

    it "uploads only once when first references are created concurrently" do
      gate = Gate.new
      @backend.on_upload = -> { gate.wait }

      thread_one = Thread.new { @storage.upload(fakeio("one"), "key") }
      gate.entered # first thread is now uploading, holding the reference lock

      thread_two = Thread.new { @storage.upload(fakeio("two"), "key") }
      sleep 0.1 # give the second thread a chance to run

      assert_nil thread_two.join(0), "second upload should wait for the first one"
      gate.release
      thread_one.join
      thread_two.join

      assert_equal 1, @backend.uploads.size
      assert_equal "one", @backend.open("key").read
      assert_equal 2, @refs.count("key")
    end
  end

  describe "#delete" do
    it "deletes the file only when the last reference is removed" do
      @storage.upload(fakeio("content"), "key")
      @storage.upload(fakeio("content"), "key")

      @storage.delete("key")
      assert @storage.exists?("key")

      @storage.delete("key")
      refute @storage.exists?("key")
      assert_equal 0, @refs.count("key")
    end

    it "doesn't fail when deleting a file without references" do
      @storage.delete("key")
    end

    it "retains the reference when the deletion fails" do
      @storage.upload(fakeio("content"), "key")
      @backend.stubs(:delete).raises(Errno::ENOENT)

      assert_raises(Errno::ENOENT) { @storage.delete("key") }
      assert_equal 1, @refs.count("key")

      @backend.unstub(:delete)
      @storage.delete("key")

      assert_equal 0, @refs.count("key")
    end

    it "re-creates the file when a reference is added during deletion" do
      @storage.upload(fakeio("old"), "key")

      gate = Gate.new
      @backend.on_delete = -> { gate.wait }

      thread_one = Thread.new { @storage.delete("key") }
      gate.entered # last-reference deletion is now in progress

      thread_two = Thread.new { @storage.upload(fakeio("new"), "key") }
      sleep 0.1 # give the second thread a chance to run

      assert_nil thread_two.join(0), "upload should wait for the deletion to finish"
      gate.release
      thread_one.join
      thread_two.join

      assert_equal 1, @backend.deletes.size
      assert_equal 1, @refs.count("key")
      assert_equal "new", @backend.open("key").read
    end
  end

  describe "#clear!" do
    it "clears files and references" do
      @storage.upload(fakeio("content"), "key")
      @storage.clear!

      refute @storage.exists?("key")
      assert_equal 0, @refs.count("key")
    end
  end
end
