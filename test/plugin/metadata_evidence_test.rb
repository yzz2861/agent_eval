require "test_helper"
require "shrine/plugins/metadata_evidence"
require "shrine/plugins/restore_cached_data"
require "shrine/plugins/determine_mime_type"

describe Shrine::Plugins::MetadataEvidence do
  before do
    @attacher = attacher { plugin :metadata_evidence }
    @shrine   = @attacher.shrine_class
    @uploader = @attacher.store
  end

  describe "metadata extraction" do
    it "records declared, probed and adopted values" do
      file = @uploader.upload(fakeio("content", filename: "file.txt", content_type: "text/plain"))

      assert_equal 1, file.evidence["version"]

      assert_equal "file.txt",   file.evidence["filename"]["declared"]
      assert_nil                 file.evidence["filename"]["probed"]
      assert_equal "file.txt",   file.evidence["filename"]["adopted"]

      assert_nil                 file.evidence["size"]["declared"]
      assert_equal 7,            file.evidence["size"]["probed"]
      assert_equal 7,            file.evidence["size"]["adopted"]

      assert_equal "text/plain", file.evidence["mime_type"]["declared"]
      assert_nil                 file.evidence["mime_type"]["probed"]
      assert_equal "text/plain", file.evidence["mime_type"]["adopted"]
    end

    it "records probed MIME type when determine_mime_type analyzes content" do
      @shrine.plugin :determine_mime_type, analyzer: -> (io) { "text/plain" }

      file = @uploader.upload(fakeio("content", content_type: "image/png"))

      assert_equal "image/png",  file.evidence["mime_type"]["declared"]
      assert_equal "text/plain", file.evidence["mime_type"]["probed"]
      assert_equal "text/plain", file.evidence["mime_type"]["adopted"]
    end

    it "doesn't record MIME type as probed with the :content_type analyzer" do
      @shrine.plugin :determine_mime_type, analyzer: :content_type

      file = @uploader.upload(fakeio("content", content_type: "text/plain"))

      assert_nil file.evidence["mime_type"]["probed"]
      assert_equal :declared, file.metadata_source("mime_type")
    end

    it "treats metadata of an unopened uploaded file as declared" do
      cached_file = @attacher.upload(fakeio("content"), :cache)

      file = @uploader.upload(cached_file, metadata: true)

      assert_equal 7,   file.evidence["size"]["declared"]
      assert_nil        file.evidence["size"]["probed"]
      assert_equal 7,   file.evidence["size"]["adopted"]
      assert_equal :declared, file.metadata_source("size")
    end

    it "treats metadata of an opened uploaded file as probed" do
      cached_file = @attacher.upload(fakeio("content"), :cache)
      cached_file.metadata["size"] = 5

      cached_file.open
      file = @uploader.upload(cached_file, metadata: true)
      cached_file.close

      assert_equal 5, file.evidence["size"]["declared"]
      assert_equal 7, file.evidence["size"]["probed"]
      assert_equal 7, file.evidence["size"]["adopted"]
    end

    it "supports configuring tracked fields" do
      @shrine.plugin :metadata_evidence, fields: %i[size]

      file = @uploader.upload(fakeio("content", filename: "file.txt"))

      assert_equal %w[version size], file.evidence.keys
    end
  end

  describe "UploadedFile" do
    it "returns the source each metadata value was adopted from" do
      file = @uploader.upload(fakeio("content", filename: "file.txt", content_type: "text/plain"))

      assert_equal :declared, file.metadata_source(:filename)
      assert_equal :probed,   file.metadata_source(:size)
      assert_equal :declared, file.metadata_source(:mime_type)
      assert_nil              file.metadata_source(:unknown)
    end

    it "returns :unknown when current value matches neither declared nor probed" do
      file = @uploader.upload(fakeio("content"))
      file.metadata["size"] = 100

      assert_equal :unknown, file.metadata_source(:size)
    end

    it "prefers :probed when declared and probed values are equal" do
      file = @uploader.upload(fakeio("content", content_type: "text/plain"))
      file.metadata["evidence"]["mime_type"]["probed"] = "text/plain"

      assert_equal :probed, file.metadata_source(:mime_type)
    end

    it "survives serialization round trip" do
      file = @uploader.upload(fakeio("content", filename: "file.txt"))

      file = @shrine.uploaded_file(file.to_json)

      assert_equal 1, file.evidence["version"]
      assert_equal "file.txt", file.evidence["filename"]["declared"]
      assert_equal :probed, file.metadata_source(:size)
    end

    it "reads old attachments without evidence" do
      file = @shrine.uploaded_file(
        id:       "foo",
        storage:  "store",
        metadata: { "filename" => "old.txt", "size" => 10, "mime_type" => "text/plain" },
      )

      assert_equal "old.txt", file.original_filename
      assert_equal 10,        file.size
      assert_nil              file.evidence
      assert_nil              file.metadata_source(:size)
    end

    it "ignores evidence with an unsupported version" do
      file = @uploader.upload(fakeio("content"))
      file.metadata["evidence"]["version"] = 2

      assert_nil file.evidence
      assert_nil file.metadata_source(:size)
    end
  end

  describe "validation" do
    it "passes when values come from an allowed source" do
      @attacher.class.validate { validate_metadata_source :size, sources: [:probed] }

      @attacher.attach(fakeio("content"))

      assert_empty @attacher.errors
    end

    it "fails when values come from a disallowed source" do
      @attacher.class.validate { validate_metadata_source :mime_type, sources: [:probed] }

      @attacher.attach(fakeio("content", content_type: "text/plain"))

      assert_equal 1, @attacher.errors.count
      assert_match(/mime_type/, @attacher.errors.first)
    end

    it "doesn't fall back to declared values when probed values are missing" do
      @attacher.class.validate { validate_metadata_source :size, sources: [:probed] }

      cached_file = @attacher.upload(fakeio("content"), :cache)
      @attacher.attach_cached(cached_file.data.merge("metadata" => cached_file.metadata.merge("size" => 5)))

      assert_equal 1, @attacher.errors.count
    end

    it "fails closed when there is no evidence" do
      @attacher.class.validate { validate_metadata_source :size, sources: [:probed] }

      old_file = @shrine.uploaded_file(id: "foo", storage: "cache", metadata: { "size" => 10 })
      @attacher.change(old_file)
      @attacher.validate

      assert_equal 1, @attacher.errors.count
    end

    it "supports custom error messages" do
      @attacher.class.validate do
        validate_metadata_source :size, sources: [:probed], message: "size is not trustworthy"
      end

      @attacher.attach(fakeio("content", content_type: "text/plain"))
      @attacher.file.metadata["evidence"]["size"]["probed"] = nil
      @attacher.validate

      assert_equal ["size is not trustworthy"], @attacher.errors
    end
  end

  describe "metadata refresh" do
    it "preserves prior evidence and updates adopted values" do
      file = @uploader.upload(fakeio("content", filename: "file.txt", content_type: "text/plain"))
      file.metadata["size"] = 5

      file.refresh_metadata!

      assert_equal 7, file.metadata["size"]
      assert_equal 5, file.evidence["size"]["declared"]
      assert_equal 7, file.evidence["size"]["probed"]
      assert_equal 7, file.evidence["size"]["adopted"]

      assert_equal "file.txt", file.evidence["filename"]["declared"]
      assert_equal "file.txt", file.evidence["filename"]["adopted"]
    end

    it "fills in declared values from prior evidence when claims are gone" do
      file = @uploader.upload(fakeio("content", filename: "file.txt"))
      file.metadata.delete("filename")

      file.refresh_metadata!

      assert_equal "file.txt", file.evidence["filename"]["declared"]
      assert_nil               file.evidence["filename"]["adopted"]
    end

    it "never inherits probed values from file data" do
      file = @uploader.upload(fakeio("content", content_type: "text/plain"))
      file.metadata["evidence"]["mime_type"] = {
        "declared" => "text/plain",
        "probed"   => "image/png",
        "adopted"  => "image/png",
      }

      file.refresh_metadata!

      assert_nil                 file.evidence["mime_type"]["probed"]
      assert_equal "text/plain", file.evidence["mime_type"]["adopted"]
    end

    it "works on the attacher level" do
      @attacher.file = @uploader.upload(fakeio("content"))
      @attacher.file.metadata["size"] = 5

      @attacher.refresh_metadata!

      assert_equal 7, @attacher.file.evidence["size"]["probed"]
      assert_equal 7, @attacher.file.evidence["size"]["adopted"]
    end
  end

  describe "with restore_cached_data" do
    before do
      @attacher = attacher do
        plugin :restore_cached_data
        plugin :metadata_evidence
      end
      @shrine = @attacher.shrine_class
    end

    it "re-records evidence when restoring forged cached data" do
      cached_file = @attacher.upload(fakeio("a" * 1024, filename: "real.txt", content_type: "text/plain"), :cache)

      forged = cached_file.data
      forged["metadata"].merge!(
        "filename"  => "fake.png",
        "size"      => 5,
        "mime_type" => "image/png",
        "evidence"  => {
          "version"  => 1,
          "filename" => { "declared" => "real.txt", "probed" => "real.txt", "adopted" => "real.txt" },
          "size"     => { "declared" => 5, "probed" => 5, "adopted" => 5 },
          "mime_type"=> { "declared" => "image/png", "probed" => "image/png", "adopted" => "image/png" },
        },
      )

      @attacher.assign(forged.to_json)
      file = @attacher.file

      # forged probed values are not inherited
      assert_equal 5,    file.evidence["size"]["declared"]
      assert_equal 1024, file.evidence["size"]["probed"]
      assert_equal 1024, file.evidence["size"]["adopted"]
      assert_equal 1024, file.metadata["size"]

      # unmeasurable fields stay marked as declared
      assert_equal "fake.png", file.evidence["filename"]["declared"]
      assert_nil               file.evidence["filename"]["probed"]
      assert_equal "fake.png", file.evidence["filename"]["adopted"]

      # without content analysis the forged MIME type is adopted but marked declared
      assert_equal "image/png", file.evidence["mime_type"]["declared"]
      assert_nil                file.evidence["mime_type"]["probed"]
      assert_equal "image/png", file.evidence["mime_type"]["adopted"]
    end

    it "exposes forged MIME type when content is analyzed" do
      @shrine.plugin :determine_mime_type, analyzer: -> (io) { "text/plain" }

      cached_file = @attacher.upload(fakeio("a" * 1024, content_type: "text/plain"), :cache)

      forged = cached_file.data
      forged["metadata"]["mime_type"] = "image/png"

      @attacher.assign(forged.to_json)
      file = @attacher.file

      assert_equal "image/png",  file.evidence["mime_type"]["declared"]
      assert_equal "text/plain", file.evidence["mime_type"]["probed"]
      assert_equal "text/plain", file.evidence["mime_type"]["adopted"]
      assert_equal "text/plain", file.metadata["mime_type"]
    end

    it "enforces trusted sources on forged cached data" do
      @attacher.class.validate do
        validate_metadata_source :size, :mime_type, sources: [:probed]
      end

      cached_file = @attacher.upload(fakeio("a" * 1024, content_type: "text/plain"), :cache)

      forged = cached_file.data
      forged["metadata"].merge!(
        "size"      => 5,
        "mime_type" => "image/png",
        "evidence"  => {
          "version"  => 1,
          "size"     => { "declared" => 5, "probed" => 5, "adopted" => 5 },
          "mime_type"=> { "declared" => "image/png", "probed" => "image/png", "adopted" => "image/png" },
        },
      )

      @attacher.assign(forged.to_json)

      # size passes because it was re-measured, mime_type fails because the
      # forged probed value was discarded and no real measurement exists
      assert_equal 1, @attacher.errors.count
      assert_match(/mime_type/, @attacher.errors.first)
    end

    it "passes source validation on forged cached data when content is analyzed" do
      @shrine.plugin :determine_mime_type, analyzer: -> (io) { "text/plain" }
      @attacher.class.validate do
        validate_metadata_source :size, :mime_type, sources: [:probed]
      end

      cached_file = @attacher.upload(fakeio("a" * 1024, content_type: "text/plain"), :cache)

      forged = cached_file.data
      forged["metadata"].merge!("size" => 5, "mime_type" => "image/png")

      @attacher.assign(forged.to_json)

      assert_empty @attacher.errors
      assert_equal 1024,        @attacher.file.metadata["size"]
      assert_equal "text/plain", @attacher.file.metadata["mime_type"]
    end
  end
end
