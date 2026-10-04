require "test_helper"
require "shrine/plugins/content_addressable"
require "shrine/storage/content_addressable"
require "digest"

describe Shrine::Plugins::ContentAddressable do
  before do
    @uploader = uploader { plugin :content_addressable }
    @shrine   = @uploader.class
  end

  describe "#generate_location" do
    it "generates a location from the hash of the file content" do
      location = @uploader.generate_location(fakeio("content"), metadata: { "filename" => "image.jpg" })

      assert_equal "#{Digest::SHA256.hexdigest("content")}.jpg", location
    end

    it "generates the same location for the same content" do
      one = @uploader.generate_location(fakeio("content", filename: "one.txt"))
      two = @uploader.generate_location(fakeio("content", filename: "two.txt"))

      assert_equal one, two
    end

    it "generates different locations for different content" do
      one = @uploader.generate_location(fakeio("one", filename: "file.txt"))
      two = @uploader.generate_location(fakeio("two", filename: "file.txt"))

      refute_equal one, two
    end

    it "rewinds the IO after hashing" do
      io = fakeio("content")
      @uploader.generate_location(io)

      assert_equal "content", io.read
    end

    it "accepts a :prefix option" do
      @shrine.plugin :content_addressable, prefix: "blobs"

      location = @uploader.generate_location(fakeio("content"), metadata: { "filename" => "image.jpg" })

      assert_equal "blobs/#{Digest::SHA256.hexdigest("content")}.jpg", location
    end

    it "accepts a :digest option" do
      @shrine.plugin :content_addressable, digest: :md5

      location = @uploader.generate_location(fakeio("content"), metadata: { "filename" => "image.jpg" })

      assert_equal "#{Digest::MD5.hexdigest("content")}.jpg", location
    end

    it "generates the same location when re-uploading an uploaded file" do
      uploaded   = @uploader.upload(fakeio("content", filename: "file.txt"))
      reuploaded = @uploader.upload(uploaded)

      assert_equal uploaded.id, reuploaded.id
    end
  end

  describe "with ContentAddressable storage" do
    before do
      @backend = Shrine::Storage::Memory.new
      @refs    = Shrine::Storage::ContentAddressable::MemoryRefs.new
      @shrine.storages[:store] = Shrine::Storage::ContentAddressable.new(@backend, refs: @refs)
    end

    it "shares the blob between attachments while keeping separate metadata" do
      one = @uploader.upload(fakeio("content", filename: "one.txt"))
      two = @uploader.upload(fakeio("content", filename: "two.txt"))

      assert_equal one.id, two.id
      assert_equal "one.txt", one.original_filename
      assert_equal "two.txt", two.original_filename
      assert_equal 1, @backend.store.count
    end

    it "keeps the blob until the last referencing attachment is deleted" do
      one = @uploader.upload(fakeio("content", filename: "one.txt"))
      two = @uploader.upload(fakeio("content", filename: "two.txt"))

      one.delete
      assert two.exists?

      two.delete
      refute @backend.exists?(one.id)
    end
  end
end
