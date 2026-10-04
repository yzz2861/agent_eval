require "test_helper"
require "shrine/plugins/quarantine"

describe Shrine::Plugins::Quarantine do
  before do
    @shrine = shrine do
      storages[:quarantine] = Shrine::Storage::Memory.new
      plugin :quarantine
    end
    @attacher = @shrine::Attacher.new
  end

  describe "configuration" do
    it "uses the registered quarantine storage as the cache storage" do
      assert_equal :quarantine, @attacher.cache_key
    end

    it "accepts a custom quarantine storage" do
      uploader = Class.new(Shrine)
      uploader.storages[:holding] = Shrine::Storage::Memory.new
      uploader.storages[:store] = Shrine::Storage::Memory.new
      uploader.plugin :quarantine, storage: :holding

      assert_equal :holding, uploader::Attacher.new.cache_key
    end

    it "registers a scanner callable through .scanner" do
      callable = ->(file, context) { :clean }
      @shrine::Attacher.scanner(callable)

      assert_equal callable, @shrine.opts[:quarantine][:scanner]
    end
  end

  describe "entering quarantine" do
    it "uploads new files into quarantine with pending status and scan identity" do
      @attacher.attach_cached(fakeio("contents"))
      file = @attacher.file

      assert @attacher.quarantined?
      assert @attacher.scan_pending?
      assert_equal "pending", file.metadata["scan_status"]
      assert_match(/\A[0-9a-f]{32}\z/, file.metadata["scan_id"])
      assert_equal 1, @attacher.scan_generation
    end

    it "does not generate a public URL while in quarantine" do
      @attacher.attach_cached(fakeio("contents"))

      assert_nil @attacher.url
      assert_raises(Shrine::FileInQuarantine) { @attacher.file.url }
    end

    it "increments the attachment generation when replaced" do
      @attacher.attach_cached(fakeio("first"))
      assert_equal 1, @attacher.scan_generation
      first_id = @attacher.scan_id

      @attacher.attach_cached(fakeio("second"))
      assert_equal 2, @attacher.scan_generation
      refute_equal first_id, @attacher.scan_id
    end

    it "keeps files uploaded directly to store publicly available and clean" do
      @attacher.attach(fakeio("contents"))

      assert @attacher.stored?
      assert @attacher.scan_clean?
      refute_nil @attacher.url
    end
  end

  describe "scanning" do
    it "publishes synchronously clean files and removes the quarantine copy" do
      @shrine::Attacher.scanner { :clean }
      @attacher.attach_cached(fakeio("contents"))
      quarantined = @attacher.file

      @attacher.finalize
      assert @attacher.stored?
      assert @attacher.scan_clean?
      refute_nil @attacher.url
      refute quarantined.exists?
    end

    it "passes the scan payload and attacher context to the scanner" do
      received = nil
      @shrine::Attacher.scanner do |file, context|
        received = [file, context]
        :clean
      end
      @attacher.attach_cached(fakeio("contents"))
      quarantine_id = @attacher.file.id
      @attacher.finalize

      file, context = received
      assert_equal quarantine_id, file.id
      assert_equal file.data, context[:scan_data]
      assert_equal "pending", context[:scan_data]["metadata"]["scan_status"]
    end

    it "refuses to publish a pending file directly" do
      @attacher.attach_cached(fakeio("contents"))

      assert_raises(Shrine::FileInQuarantine) { @attacher.promote }
      assert @attacher.quarantined?
    end

    it "records a rejection and keeps the quarantined file private" do
      @shrine::Attacher.scanner { :infected }
      @attacher.attach_cached(fakeio("virus"))
      quarantined = @attacher.file

      @attacher.finalize
      assert @attacher.quarantined?
      assert @attacher.scan_infected?
      assert_nil @attacher.url
      assert_raises(Shrine::FileInQuarantine) { quarantined.url }
      assert quarantined.exists?
    end

    it "records a scanner failure without publishing" do
      @shrine::Attacher.scanner { :failed }
      @attacher.attach_cached(fakeio("contents"))

      @attacher.finalize
      assert @attacher.quarantined?
      assert @attacher.scan_failed?
      assert_nil @attacher.url
    end

    it "treats a raised scanner exception as a failed scan" do
      @shrine::Attacher.scanner { raise "scanner is down" }
      @attacher.attach_cached(fakeio("contents"))

      @attacher.finalize
      assert @attacher.scan_failed?
      assert_match(/scanner is down/, @attacher.file.metadata["scan_error"])
    end

    it "treats an unknown verdict as a failed scan" do
      @shrine::Attacher.scanner { :maybe }
      @attacher.attach_cached(fakeio("contents"))

      @attacher.finalize

      assert @attacher.scan_failed?
    end

    it "keeps a pending verdict in quarantine for an asynchronous scan" do
      @shrine::Attacher.scanner { :pending }
      @attacher.attach_cached(fakeio("contents"))

      @attacher.finalize
      assert @attacher.quarantined?
      assert @attacher.scan_pending?
    end

    it "supports string verdicts" do
      @shrine::Attacher.scanner { "infected" }
      @attacher.attach_cached(fakeio("virus"))

      @attacher.finalize
      assert @attacher.scan_infected?
    end
  end

  describe "asynchronous callbacks" do
    before do
      @shrine::Attacher.scanner { :pending }
      @attacher.attach_cached(fakeio("contents"))
      @payload = @attacher.scan_data
    end

    it "publishes on scan_pass" do
      quarantined = @attacher.file

      assert_equal :clean, @attacher.scan_pass(@payload)
      assert @attacher.stored?
      refute quarantined.exists?
    end

    it "rejects on scan_reject" do
      assert_equal :infected, @attacher.scan_reject(@payload, error: "EICAR")
      assert @attacher.scan_infected?
      assert_equal "EICAR", @attacher.file.metadata["scan_error"]
    end

    it "fails on scan_fail" do
      assert_equal :failed, @attacher.scan_fail(@payload, error: "timeout")
      assert @attacher.scan_failed?
    end

    it "resolves verdicts through resolve_scan" do
      assert_equal :infected, @attacher.resolve_scan(:infected, @payload)
    end

    it "is idempotent for duplicate rejection callbacks" do
      assert_equal :infected, @attacher.scan_reject(@payload)
      assert_equal :infected, @attacher.scan_reject(@payload)
      assert @attacher.scan_infected?
    end

    it "is idempotent for duplicate failure callbacks" do
      assert_equal :failed, @attacher.scan_fail(@payload)
      assert_equal :failed, @attacher.scan_fail(@payload)
      assert @attacher.scan_failed?
    end

    it "is idempotent for duplicate clean callbacks after promotion" do
      @attacher.scan_pass(@payload)

      assert_equal :stale, @attacher.scan_pass(@payload)
      assert @attacher.stored?
    end

    it "allows retrying a failed scan" do
      @attacher.scan_fail(@payload)
      @shrine::Attacher.scanner { "clean" }

      assert_equal :clean, @attacher.retry_scan
      assert @attacher.stored?
    end

    it "does not retry scans that did not fail" do
      refute @attacher.retry_scan
      assert @attacher.scan_pending?
    end
  end

  describe "stale callbacks after replacement" do
    before do
      @shrine::Attacher.scanner { :pending }
      @attacher.attach_cached(fakeio("old"))
      @old_payload = @attacher.scan_data
      @old_file = @attacher.file

      @attacher.attach_cached(fakeio("new"))
      @new_file = @attacher.file
    end

    it "does not modify the current attachment from an old clean callback" do
      assert_equal :stale, @attacher.scan_pass(@old_payload)

      assert @attacher.quarantined?
      assert_equal @new_file.id, @attacher.file.id
      assert @attacher.scan_pending?
      assert @old_file.exists?
    end

    it "does not modify the current attachment from an old reject callback" do
      assert_equal :stale, @attacher.scan_reject(@old_payload)

      assert @attacher.scan_pending?
      assert_equal @new_file.id, @attacher.file.id
    end

    it "only cleans up the quarantined object owned by the stale scan" do
      assert_equal true, @attacher.clean_scan(@old_payload)

      refute @old_file.exists?
      assert @new_file.exists?
    end

    it "never deletes permanent storage objects during stale cleanup" do
      stored = @shrine.upload(fakeio("kept"), :store)

      assert_equal false, @attacher.clean_scan(stored.data)
      assert stored.exists?
    end

    it "never deletes the currently attached file through cleanup" do
      assert_equal false, @attacher.clean_scan(@attacher.scan_data)
      assert @new_file.exists?
    end

    it "detects attachment changes through the class finder" do
      @shrine.plugin :model
      record_class = model_class(:file_data)
      record = record_class.new
      record.extend(@shrine::Attachment.new(:file))
      record.file_attacher.set(@new_file)

      assert_raises(Shrine::AttachmentChanged) do
        @shrine::Attacher.find_scan(model: record, name: :file, file: @old_payload)
      end

      attacher = @shrine::Attacher.find_scan(model: record, name: :file, file: @attacher.scan_data)
      assert_equal @new_file.id, attacher.file.id
    end

    it "resolves stale callbacks by cleaning the owned object only" do
      assert_equal :stale, @attacher.resolve_scan(:clean, @old_payload)
      assert_equal true, @attacher.clean_scan(@old_payload)
      refute @old_file.exists?
      assert @new_file.exists?
      assert @attacher.scan_pending?
    end
  end

  describe "persistence" do
    it "invokes a configured scan persistence block on state changes" do
      persisted = []
      @shrine::Attacher.scan_persist_block { |attacher| persisted << attacher.scan_status }
      @shrine::Attacher.scanner { :infected }
      @attacher.attach_cached(fakeio("virus"))

      @attacher.finalize

      assert_equal ["infected"], persisted
    end
  end

  describe "with the model plugin" do
    before do
      @shrine.plugin :model
      @record_class = model_class(:document_data)
      @record_class.include @shrine::Attachment.new(:document)
      @record = @record_class.new
    end

    it "publishes through a background-style callback and syncs the column" do
      @shrine::Attacher.scanner { :pending }
      attacher = @record.document_attacher
      attacher.assign(fakeio("background contents"))
      payload = attacher.scan_data

      assert_nil attacher.url
      assert_equal "pending", JSON.parse(@record.document_data)["metadata"]["scan_status"]

      callback_attacher = @shrine::Attacher.find_scan(model: @record, name: :document, file: payload)
      assert_equal :clean, callback_attacher.resolve_scan(:clean, payload)

      assert callback_attacher.stored?
      column_data = JSON.parse(@record.document_data)
      assert_equal "clean", column_data["metadata"]["scan_status"]
      refute_nil @record.document_url
    end

    it "persists rejected status to the model column" do
      @shrine::Attacher.scanner { :infected }
      attacher = @record.document_attacher
      attacher.assign(fakeio("virus"))
      attacher.finalize

      column_data = JSON.parse(@record.document_data)
      assert_equal "infected", column_data["metadata"]["scan_status"]
      assert_nil @record.document_url
    end
  end
end
