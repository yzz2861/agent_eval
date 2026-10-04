require "test_helper"
require "shrine/plugins/virus_scanning"

describe Shrine::Plugins::VirusScanning do
  before do
    @shrine = shrine do
      plugin :virus_scanning
    end
  end

  def scanner(result = true)
    -> (file) { result.respond_to?(:call) ? result.call(file) : result }
  end

  describe "Attacher" do
    describe "#attach_cached" do
      it "uploads new files to quarantine in a pending state" do
        attacher = @shrine::Attacher.new

        attacher.attach_cached(fakeio)

        assert_equal :pending, attacher.scan_status
        assert attacher.scan_pending?
        assert attacher.cached?
        assert attacher.file.metadata.key?("scan_generation")
      end

      it "runs the configured scanner synchronously" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(true)

        attacher.attach_cached(fakeio)

        assert attacher.scan_passed?
        assert attacher.stored?
      end

      it "passes the uploaded file to the scanner callable" do
        scanned = nil
        quarantine_id = nil
        content = nil
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = lambda do |file|
          scanned = file
          quarantine_id = file.id
          content = file.read
          true
        end

        attacher.attach_cached(fakeio("payload"))

        assert_instance_of @shrine::UploadedFile, scanned
        assert_equal quarantine_id, scanned.id
        refute_equal attacher.file.id, scanned.id
        assert_equal "payload", content
      end

      it "accepts an object responding to #call as scanner" do
        scanner_class = Class.new do
          def call(file) = true
        end

        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner_class.new

        attacher.attach_cached(fakeio)

        assert attacher.scan_passed?
      end

      it "runs the scan block instead of the scanner when both are configured" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(-> (_) { fail "scanner should not be called" })
        called = false
        attacher.scan_block { |a| called = true }

        attacher.attach_cached(fakeio)

        assert called
        assert attacher.scan_pending?
      end

      it "stays pending when neither scanner nor scan block are configured" do
        attacher = @shrine::Attacher.new

        attacher.attach_cached(fakeio)

        assert attacher.scan_pending?
      end

      it "uses a configured custom quarantine storage" do
        shrine = shrine { plugin :virus_scanning, quarantine: :other_cache }
        attacher = shrine::Attacher.new

        attacher.attach_cached(fakeio)

        assert_equal :other_cache, attacher.file.storage_key
      end

      it "copies an existing cached file into quarantine" do
        attacher = @shrine::Attacher.new
        cached = attacher.upload(fakeio, :cache)

        attacher.attach_cached(cached.data)

        assert attacher.scan_pending?
        assert attacher.cached?
      end
    end

    describe "#attach" do
      it "quarantines new files regardless of requested storage" do
        attacher = @shrine::Attacher.new

        attacher.attach(fakeio, storage: :store)

        assert_equal :cache, attacher.file.storage_key
        assert attacher.scan_pending?
      end

      it "still clears the attachment when given nil" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.attach(nil)

        refute attacher.attached?
      end
    end

    describe "#url" do
      it "does not generate a URL while pending" do
        attacher = @shrine::Attacher.new

        attacher.attach_cached(fakeio)

        assert_nil attacher.url
        assert_nil attacher.file.url
      end

      it "generates a URL after the file passed the scan" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(true)

        attacher.attach_cached(fakeio)

        assert_equal attacher.file.url, attacher.url
      end

      it "does not generate a URL when rejected" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(false)

        attacher.attach_cached(fakeio)

        assert_nil attacher.url
      end

      it "does not generate a URL when the scan failed" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(-> (_) { raise "scanner offline" })

        attacher.attach_cached(fakeio)

        assert_nil attacher.url
      end

      it "does not block URLs for files without scan metadata" do
        attacher = @shrine::Attacher.new
        file = attacher.upload(fakeio, :store)
        attacher.set(file)

        assert_nil attacher.scan_status
        refute_nil attacher.url
      end
    end

    describe "scan results" do
      it "stores a passed status and promotes the file" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.accept_scan!(attacher.scan_generation)

        assert attacher.scan_passed?
        assert attacher.stored?
        assert_equal "passed", attacher.file.metadata["scan_status"]
      end

      it "stores a rejected status and removes the quarantined object" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)
        quarantined = attacher.file

        attacher.reject_scan!(attacher.scan_generation)

        assert attacher.scan_rejected?
        refute quarantined.exists?
        assert_equal attacher.file.id, quarantined.id
      end

      it "stores a failed status with the error message and keeps the object" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)
        quarantined = attacher.file

        attacher.fail_scan!(attacher.scan_generation, "scanner unavailable")

        assert attacher.scan_failed?
        assert_equal "scanner unavailable", attacher.file.metadata["scan_error"]
        assert quarantined.exists?
      end

      it "interprets false and :infected as rejection" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(:infected)

        attacher.attach_cached(fakeio)

        assert attacher.scan_rejected?
      end

      it "interprets true and :clean as passed" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(:clean)

        attacher.attach_cached(fakeio)

        assert attacher.scan_passed?
      end

      it "marks the scan as failed when the scanner raises" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(-> (_) { raise "kaboom" })

        attacher.attach_cached(fakeio)

        assert attacher.scan_failed?
        assert_equal "kaboom", attacher.file.metadata["scan_error"]
      end
    end

    describe "#rescan!" do
      it "requires the current scan to be failed" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        assert_raises(Shrine::Error) { attacher.rescan! }
      end

      it "retries a failed scan with the same generation" do
        attacher = @shrine::Attacher.new
        attempts = 0
        attacher.virus_scanner = -> (_) do
          attempts += 1
          raise "temporary" if attempts == 1
          true
        end
        attacher.attach_cached(fakeio)
        generation = attacher.scan_generation

        assert attacher.scan_failed?

        attacher.rescan!

        assert attacher.scan_passed?
        assert_equal generation, attacher.scan_generation
      end
    end

    describe "#promote_cached" do
      it "does not promote files that have not passed the scan" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.promote_cached

        assert attacher.cached?
      end

      it "promotes files after they passed the scan" do
        attacher = @shrine::Attacher.new
        attacher.virus_scanner = scanner(true)
        attacher.attach_cached(fakeio)

        attacher.promote_cached

        assert attacher.stored?
      end

      it "does not interfere with untracked attachments" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)
        file = attacher.file
        file.metadata.delete("scan_status")
        file.metadata.delete("scan_generation")

        attacher.promote_cached

        assert attacher.stored?
      end
    end

    describe "stale callbacks" do
      it "binds the scan task to the attachment generation" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio("first"))

        assert_equal 1, attacher.scan_generation

        attacher.attach_cached(fakeio("second"))

        assert_equal 2, attacher.scan_generation
      end

      it "ignores an accept callback from a replaced attachment" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio("first"))
        old_generation = attacher.scan_generation
        attacher.attach_cached(fakeio("second"))
        current_file = attacher.file

        attacher.accept_scan!(old_generation)

        assert attacher.scan_pending?
        assert_equal current_file, attacher.file
        assert current_file.exists?
      end

      it "ignores a reject callback from a replaced attachment" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio("first"))
        old_generation = attacher.scan_generation
        attacher.attach_cached(fakeio("second"))
        current_file = attacher.file

        attacher.reject_scan!(old_generation)

        assert attacher.scan_pending?
        assert current_file.exists?
      end

      it "ignores a fail callback from a replaced attachment" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio("first"))
        old_generation = attacher.scan_generation
        attacher.attach_cached(fakeio("second"))

        attacher.fail_scan!(old_generation, "late error")

        assert attacher.scan_pending?
        assert_nil attacher.file.metadata["scan_error"]
      end

      it "seeds the generation counter when loaded from persisted data" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        reloaded = @shrine::Attacher.new
        reloaded.load_data(attacher.data)
        reloaded.attach_cached(fakeio)

        assert_equal 2, reloaded.scan_generation
      end
    end

    describe "idempotent callbacks" do
      it "accepts repeated accept callbacks" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.accept_scan!(1)
        stored = attacher.file
        attacher.accept_scan!(1)
        attacher.accept_scan!(1)

        assert attacher.scan_passed?
        assert_equal stored, attacher.file
      end

      it "accepts repeated reject callbacks without re-deleting" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.reject_scan!(1)
        attacher.reject_scan!(1)

        assert attacher.scan_rejected?
      end

      it "accepts repeated fail callbacks" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.fail_scan!(1, "first")
        attacher.fail_scan!(1, "second")

        assert attacher.scan_failed?
        assert_equal "first", attacher.file.metadata["scan_error"]
      end

      it "does not let a late conflicting result overwrite a terminal result" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio)

        attacher.accept_scan!(1)
        attacher.reject_scan!(1)

        assert attacher.scan_passed?
        assert attacher.stored?
      end
    end

    describe "cleanup" do
      it "deletes only the quarantine object owned by the accepted task" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio("first"))
        old_file = attacher.file
        attacher.attach_cached(fakeio("second"))
        new_file = attacher.file

        attacher.accept_scan!(attacher.scan_generation)

        refute new_file.exists?
        assert old_file.exists?
      end

      it "does not delete objects owned by other generations on rejection" do
        attacher = @shrine::Attacher.new
        attacher.attach_cached(fakeio("first"))
        old_file = attacher.file
        attacher.attach_cached(fakeio("second"))

        attacher.reject_scan!(attacher.scan_generation)

        assert old_file.exists?
      end
    end

    describe ".scan_block" do
      it "registers a global scan block inherited by new attachers" do
        @shrine::Attacher.scan_block { |attacher| }

        assert_respond_to @shrine::Attacher.new, :scan_block
        assert_instance_of Proc, @shrine::Attacher.scan_block
      end
    end
  end
end
