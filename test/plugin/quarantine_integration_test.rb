require "test_helper"
require "shrine/plugins/quarantine"
require "shrine/storage/file_system"

require "fileutils"
require "tmpdir"

# End-to-end flow on top of local FileSystem storage: uploads are first held
# in an on-disk quarantine directory, an external scanner (integrated through
# a plain callable, without any scanning software installed) confirms them,
# and only then are they published to the public store directory.
describe "quarantine integration with FileSystem storage" do
  def build_uploader(scanner)
    root = File.join(Dir.tmpdir, "shrine-quarantine-test")
    FileUtils.rm_rf(root)

    uploader = Class.new(Shrine)
    uploader.storages = {
      quarantine: Shrine::Storage::FileSystem.new(File.join(root, "quarantine")),
      store:      Shrine::Storage::FileSystem.new(File.join(root, "store")),
    }
    uploader.plugin :quarantine
    uploader::Attacher.scanner(scanner)

    [uploader, root]
  end

  after do
    FileUtils.rm_rf(File.join(Dir.tmpdir, "shrine-quarantine-test"))
  end

  it "holds the file in quarantine until scanned, then publishes and cleans up" do
    uploader, root = build_uploader(->(file, context) { :clean })
    attacher = uploader::Attacher.new

    attacher.attach_cached(fakeio("clean contents"))
    quarantine_path = File.join(root, "quarantine", attacher.file.id)

    assert File.file?(quarantine_path)
    assert_nil attacher.url
    assert_raises(Shrine::FileInQuarantine) { attacher.file.url }

    attacher.finalize

    store_path = File.join(root, "store", attacher.file.id)
    assert File.file?(store_path)
    refute File.file?(quarantine_path)
    assert_equal File.join(root, "store", attacher.file.id), attacher.url
    assert_equal "clean contents", File.binread(store_path)
    assert attacher.scan_clean?
  end

  it "keeps infected files quarantined on disk and never publishes them" do
    uploader, root = build_uploader(->(file, context) { :infected })
    attacher = uploader::Attacher.new

    attacher.attach_cached(fakeio("malicious"))
    quarantine_path = File.join(root, "quarantine", attacher.file.id)

    attacher.finalize

    assert File.file?(quarantine_path)
    assert attacher.scan_infected?
    assert_nil attacher.url
    assert_equal 0, Dir[File.join(root, "store", "**", "*")].count { |path| File.file?(path) }
  end

  it "keeps failed scans quarantined and allows a later retry to publish" do
    uploader, root = build_uploader(->(file, context) { raise "scanner offline" })
    attacher = uploader::Attacher.new

    attacher.attach_cached(fakeio("retry me"))
    quarantine_path = File.join(root, "quarantine", attacher.file.id)
    attacher.finalize

    assert attacher.scan_failed?
    assert File.file?(quarantine_path)
    assert_nil attacher.url

    uploader::Attacher.scanner { :clean }
    assert_equal :clean, attacher.retry_scan

    assert attacher.stored?
    assert File.file?(File.join(root, "store", attacher.file.id))
    refute File.file?(quarantine_path)
  end

  it "completes an asynchronous scan round-trip through scan payloads" do
    delivered = nil
    uploader, root = build_uploader(->(file, context) do
      delivered = context[:scan_data]
      :pending
    end)
    attacher = uploader::Attacher.new

    attacher.attach_cached(fakeio("async contents"))
    attacher.finalize

    assert attacher.scan_pending?
    assert_nil attacher.url

    quarantine_path = File.join(root, "quarantine", attacher.file.id)
    assert File.file?(quarantine_path)

    # Simulate the external scanner callback arriving in a fresh process:
    # reconstruct the attacher purely from the serialized payload.
    callback_attacher = uploader::Attacher.from_data(delivered)
    result = callback_attacher.resolve_scan(:clean, delivered)

    assert_equal :clean, result
    assert callback_attacher.stored?
    assert File.file?(File.join(root, "store", callback_attacher.file.id))
    refute File.file?(quarantine_path)
  end

  it "ignores stale callbacks after the attachment is replaced" do
    uploader, root = build_uploader(->(file, context) { :pending })
    attacher = uploader::Attacher.new

    attacher.attach_cached(fakeio("old version"))
    old_payload = attacher.scan_data
    old_path = File.join(root, "quarantine", attacher.file.id)

    # The user replaces the attachment before the old scan completes.
    attacher.attach_cached(fakeio("new version"))
    new_payload = attacher.scan_data
    new_path = File.join(root, "quarantine", attacher.file.id)

    # Stale callbacks never mutate the current attachment; explicit cleanup
    # acts only on the object owned by the outdated scan.
    assert_equal :stale, attacher.resolve_scan(:clean, old_payload)
    assert_equal true, attacher.clean_scan(old_payload)
    refute File.file?(old_path)
    assert File.file?(new_path)
    assert attacher.scan_pending?

    # The current generation can still be published by its own callback.
    callback_attacher = uploader::Attacher.from_data(attacher.scan_data)
    assert_equal :clean, callback_attacher.resolve_scan(:clean, new_payload)
    assert File.file?(File.join(root, "store", callback_attacher.file.id))
  end

  it "is idempotent when the same scan callback is delivered twice" do
    uploader, root = build_uploader(->(file, context) { :pending })
    attacher = uploader::Attacher.new

    attacher.attach_cached(fakeio("duplicated webhook"))
    attacher.finalize
    payload = attacher.scan_data

    callback_attacher = uploader::Attacher.from_data(payload)
    assert_equal :infected, callback_attacher.resolve_scan(:infected, payload)
    assert_equal :infected, callback_attacher.resolve_scan(:infected, payload)

    quarantine_files = Dir[File.join(root, "quarantine", "**", "*")].count { |path| File.file?(path) }
    store_files = Dir[File.join(root, "store", "**", "*")].count { |path| File.file?(path) }
    assert_equal 0, store_files
    assert callback_attacher.scan_infected?
  end
end
