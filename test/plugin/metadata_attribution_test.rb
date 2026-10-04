require "test_helper"
require "shrine/plugins/metadata_attribution"

describe Shrine::Plugins::MetadataAttribution do
  before do
    @attacher = attacher { plugin :metadata_attribution }
    @uploader = @attacher.store
    @shrine   = @uploader.class
  end

  describe "uploading" do
    it "records the measured size" do
      file = @uploader.upload(fakeio("content"))

      assert_equal 7, file.metadata["size"]
      assert_equal :measured, file.metadata_source("size")
      assert_equal 7, file.measured_metadata("size")
      assert_nil file.declared_metadata("size")
    end

    it "records the declared filename and MIME type from the client" do
      file = @uploader.upload(fakeio("content", filename: "matrix.mp4", content_type: "video/mp4"))

      assert_equal "matrix.mp4", file.declared_metadata("filename")
      assert_nil file.measured_metadata("filename")
      assert_equal :declared, file.metadata_source("filename")

      assert_equal "video/mp4", file.declared_metadata("mime_type")
      assert_nil file.measured_metadata("mime_type")
      assert_equal :declared, file.metadata_source("mime_type")
    end

    it "treats a filename derived from a server path as measured" do
      file = @uploader.upload(tempfile("content", "file"))

      assert_equal :measured, file.metadata_source("filename")
    end

    it "records declared values passed through the metadata option" do
      file = @uploader.upload(fakeio("content"), metadata: { "mime_type" => "text/plain" })

      assert_equal "text/plain", file.declared_metadata("mime_type")
      assert_equal :declared, file.metadata_source("mime_type")
    end

    it "keeps declared and measured values distinct when both are present" do
      @shrine.plugin :add_metadata
      file = @uploader.upload(
        fakeio("content", content_type: "image/png"),
        metadata: { "mime_type" => "application/x-evil" },
      )

      assert_equal "application/x-evil", file.declared_metadata("mime_type")
    end

    it "stores versioned evidence inside the metadata hash" do
      file = @uploader.upload(fakeio("content"))

      evidence = file.metadata_evidence
      assert_equal 1, evidence["version"]
      assert_includes evidence["fields"].keys, "size"
      assert_includes evidence["fields"]["size"].keys, "observations"
    end

    it "is not added when metadata extraction is disabled" do
      file = @uploader.upload(fakeio("content"), metadata: false)

      assert_nil file.metadata_evidence
      assert_nil file.metadata_source("size")
    end

    it "only records configured fields" do
      @shrine.plugin :metadata_attribution, fields: [:size]
      file = @uploader.upload(fakeio("content", filename: "a.txt"))

      assert file.metadata_evidence["fields"].key?("size")
      refute file.metadata_evidence["fields"].key?("filename")
    end
  end

  describe "adopted value" do
    it "prefers the measured value over a conflicting declared value" do
      measured_shrine = Class.new(@shrine)
      measured_shrine.plugin :determine_mime_type, analyzer: ->(io) { "text/plain" }
      uploader = measured_shrine.new(:store)

      file = uploader.upload(
        fakeio("content", content_type: "image/png"),
        metadata: { "mime_type" => "application/x-evil" },
      )

      assert_equal "text/plain", file.mime_type
      assert_equal "text/plain", file.metadata_attribution("mime_type")["adopted"]
      assert_equal :measured, file.metadata_source("mime_type")
      assert_equal "application/x-evil", file.declared_metadata("mime_type")
    end

    it "never substitutes a declared cached value for a missing measured value" do
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source(:size, :mime_type) }

      cached_file = @attacher.upload(fakeio("a" * 10), :cache, metadata: false)
      cached_data = cached_file.data.dup
      cached_data["metadata"] = {
        "size" => 999,
        "mime_type" => "image/png",
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => 999, "measured" => nil, "adopted" => 999,
              "source" => "declared",
              "observations" => [{ "source" => "declared", "value" => 999 }],
            },
            "mime_type" => {
              "declared" => "image/png", "measured" => nil, "adopted" => "image/png",
              "source" => "declared",
              "observations" => [{ "source" => "declared", "value" => "image/png" }],
            },
          },
        },
      }

      @attacher.attach_cached(cached_data)
      @attacher.validate

      assert_equal 2, @attacher.errors.size
      assert_nil @attacher.file.measured_metadata("size")
      assert_equal 999, @attacher.file.declared_metadata("size")
      assert_equal :declared, @attacher.file.metadata_source("size")
    end
  end

  describe "serialization" do
    it "round-trips evidence through JSON" do
      file = @uploader.upload(fakeio("content", filename: "a.txt"))
      loaded = @shrine.uploaded_file(file.to_json)

      assert_equal file.metadata_evidence, loaded.metadata_evidence
      assert_equal :measured, loaded.metadata_source("size")
      assert_equal :declared, loaded.metadata_source("filename")
    end

    it "reads old attachments that have no evidence" do
      data = {
        "id" => "foo",
        "storage" => "store",
        "metadata" => { "size" => 10, "filename" => "old.txt" },
      }
      file = @shrine.uploaded_file(data.to_json)

      assert_nil file.metadata_evidence
      assert_nil file.metadata_source("size")
      assert_equal 10, file.size
    end

    it "reads evidence produced by a future format version" do
      data = {
        "id" => "foo",
        "storage" => "store",
        "metadata" => {
          "size" => 10,
          "metadata_evidence" => { "version" => 99, "fields" => {} },
        },
      }
      file = @shrine.uploaded_file(data.to_json)

      assert_equal 99, file.metadata_evidence["version"]
    end

    it "is not trusted for old attachments that lack evidence under a measured policy" do
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source(:size) }

      attacher = @shrine::Attacher.new
      attacher.attach(fakeio("content"))
      attacher.file.metadata.delete("metadata_evidence")
      attacher.validate

      refute_empty attacher.errors
    end
  end

  describe "promotion" do
    it "preserves evidence when copying to another storage" do
      cached = @attacher.upload(fakeio("content", filename: "a.txt"), :cache)
      stored = @shrine.upload(cached, :store)

      assert_equal cached.metadata_evidence, stored.metadata_evidence
      assert_equal :measured, stored.metadata_source("size")
    end
  end

  describe "refresh_metadata!" do
    it "keeps prior observations and records the new measurement" do
      file = @uploader.upload(fakeio("content", filename: "a.txt"))
      original_observations = file.metadata_attribution("size")["observations"].size

      file.metadata["size"] = 999
      file.refresh_metadata!

      assert_equal 7, file.metadata["size"]
      assert_equal :measured, file.metadata_source("size")
      assert_operator file.metadata_attribution("size")["observations"].size, :>, original_observations
    end

    it "retains declared evidence even after a measured refresh" do
      file = @uploader.upload(fakeio("content", content_type: "image/png"))
      file.refresh_metadata!

      assert_equal "image/png", file.declared_metadata("mime_type")
    end

    it "updates adopted metadata after the refresh" do
      file = @uploader.upload(fakeio("abc"))
      file.metadata["size"] = 1
      file.refresh_metadata!

      assert_equal 3, file.metadata_attribution("size")["adopted"]
      assert_equal 3, file.size
    end

    it "works through the attacher" do
      @attacher.file = @uploader.upload(fakeio("content"), metadata: false)
      @attacher.refresh_metadata!

      assert_equal 7, @attacher.file.size
      assert_equal :measured, @attacher.file.metadata_source("size")
    end

    it "preserves the declared value alongside a later measured refresh" do
      file = @uploader.upload(fakeio("content", content_type: "image/png"))
      assert_equal :declared, file.metadata_source("mime_type")
      original_observations = file.metadata_attribution("mime_type")["observations"].size

      file.refresh_metadata!

      # Stays declared, but the prior declaration is retained in history.
      assert_equal :declared, file.metadata_source("mime_type")
      assert_equal "image/png", file.declared_metadata("mime_type")
      assert_operator file.metadata_attribution("mime_type")["observations"].size, :>, original_observations
    end
  end

  describe "cached data" do
    it "downgrades measured values forged into cached data to declared" do
      cached_file = @attacher.upload(fakeio("a" * 100), :cache, metadata: false)
      forged = cached_file.data.dup
      forged["metadata"] = {
        "size" => 1,
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => nil,
              "measured" => 1,
              "adopted" => 1,
              "source" => "measured",
              "observations" => [{ "source" => "measured", "value" => 1 }],
            },
          },
        },
      }

      @attacher.attach_cached(forged)

      assert_equal :declared, @attacher.file.metadata_source("size")
      assert_nil @attacher.file.measured_metadata("size")
      assert_equal 1, @attacher.file.declared_metadata("size")
    end

    it "rejects forged cached data when only measured sources are trusted" do
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source(:size, :mime_type) }

      cached_file = @attacher.upload(fakeio, :cache, metadata: false)
      forged = cached_file.data.dup
      forged["metadata"] = {
        "size" => 1,
        "mime_type" => "image/png",
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => nil, "measured" => 1, "adopted" => 1,
              "source" => "measured",
              "observations" => [{ "source" => "measured", "value" => 1 }],
            },
            "mime_type" => {
              "declared" => nil, "measured" => "image/png", "adopted" => "image/png",
              "source" => "measured",
              "observations" => [{ "source" => "measured", "value" => "image/png" }],
            },
          },
        },
      }

      @attacher.attach_cached(forged)
      @attacher.validate

      assert_equal 2, @attacher.errors.size
      assert_equal :declared, @attacher.file.metadata_source("size")
    end

    it "accepts freshly measured cached uploads under a measured-only policy" do
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source(:size) }

      @attacher.attach_cached(fakeio("content"))
      @attacher.validate

      assert_empty @attacher.errors
      assert_equal :measured, @attacher.file.metadata_source("size")
    end

    it "re-measures and accepts when restore_cached_data is loaded" do
      @shrine.plugin :restore_cached_data
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source(:size) }

      cached_file = @attacher.upload(fakeio("a" * 100), :cache, metadata: false)
      forged = cached_file.data.dup
      forged["metadata"] = {
        "size" => 1,
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => nil, "measured" => 1, "adopted" => 1,
              "source" => "measured",
              "observations" => [{ "source" => "measured", "value" => 1 }],
            },
          },
        },
      }

      @attacher.attach_cached(forged)
      @attacher.validate

      assert_empty @attacher.errors
      assert_equal 100, @attacher.file.size
      assert_equal :measured, @attacher.file.metadata_source("size")
    end

    it "re-measures correctly regardless of plugin load order" do
      reversed = shrine do
        plugin :restore_cached_data
        plugin :metadata_attribution
      end
      reversed::Attacher.metadata_trusted_sources :measured
      reversed::Attacher.validate { validate_metadata_source(:size) }

      attacher = reversed::Attacher.new
      target = reversed.upload(fakeio("a" * 100), :cache, metadata: false)
      forged = target.data.dup
      forged["metadata"] = {
        "size" => 1,
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => nil, "measured" => 1, "adopted" => 1,
              "source" => "measured",
              "observations" => [{ "source" => "measured", "value" => 1 }],
            },
          },
        },
      }

      attacher.attach_cached(forged)
      attacher.validate

      assert_empty attacher.errors
      assert_equal 100, attacher.file.size
      assert_equal :measured, attacher.file.metadata_source("size")
    end

    it "supports per-field trusted source policies" do
      @shrine::Attacher.metadata_trusted_sources :declared, size: :measured
      @shrine::Attacher.validate { validate_metadata_source(:size, :mime_type) }

      @attacher.attach_cached(fakeio("content", content_type: "image/png"))
      @attacher.validate

      assert_empty @attacher.errors
    end

    it "downgrades forged evidence inside versions data" do
      @shrine.plugin :versions

      cached_file = @attacher.upload(fakeio, :cache, metadata: false)
      forged = cached_file.data.dup
      forged["metadata"] = {
        "size" => 1,
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => nil, "measured" => 1, "adopted" => 1,
              "source" => "measured",
              "observations" => [{ "source" => "measured", "value" => 1 }],
            },
          },
        },
      }

      @attacher.attach_cached({ "thumb" => forged })

      assert_equal :declared, @attacher.file[:thumb].metadata_source("size")
    end
  end

  describe "validate_metadata_source" do
    it "adds a custom error message" do
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source(:size, message: "untrusted") }

      cached_file = @attacher.upload(fakeio, :cache, metadata: false)
      forged = cached_file.data.dup
      forged["metadata"] = {
        "size" => 1,
        "metadata_evidence" => {
          "version" => 1,
          "fields" => {
            "size" => {
              "declared" => 1, "measured" => nil, "adopted" => 1,
              "source" => "declared",
              "observations" => [{ "source" => "declared", "value" => 1 }],
            },
          },
        },
      }
      @attacher.attach_cached(forged)
      @attacher.validate

      assert_includes @attacher.errors, "untrusted"
    end

    it "validates all recorded fields when none are given" do
      @shrine::Attacher.metadata_trusted_sources :measured
      @shrine::Attacher.validate { validate_metadata_source }

      @attacher.attach_cached(fakeio("content", filename: "a.txt", content_type: "text/plain"))
      @attacher.validate

      refute_empty @attacher.errors
    end
  end
end
