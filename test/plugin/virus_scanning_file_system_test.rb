require "test_helper"
require "shrine/storage/file_system"
require "shrine/plugins/virus_scanning"

require "fileutils"
require "tmpdir"

describe "Shrine::Plugins::VirusScanning with FileSystem storage" do
  before do
    @root = File.join(Dir.tmpdir, "shrine-virus-scanning-#{$$}-#{rand(1_000_000)}")
    @cache_directory = File.join(@root, "quarantine")
    @store_directory = File.join(@root, "store")

    @shrine = Class.new(Shrine)
    @shrine.storages[:cache] = Shrine::Storage::FileSystem.new(@cache_directory)
    @shrine.storages[:store] = Shrine::Storage::FileSystem.new(@store_directory)
    @shrine.plugin :virus_scanning
  end

  after do
    FileUtils.rm_r(@root) if File.directory?(@root)
  end

  def file_system_attacher
    @shrine::Attacher.new
  end

  it "runs the complete upload -> quarantine -> scan -> publish lifecycle on disk" do
    attacher = file_system_attacher
    attacher.virus_scanner = -> (file) { file.read == "clean contents" }

    # 1. Upload enters quarantine in a pending state.
    attacher.attach_cached(fakeio("clean contents"))
    quarantine_file = attacher.file

    # 2. The scanner runs synchronously and the file is published.
    assert attacher.scan_passed?
    assert attacher.stored?

    stored_file = attacher.file
    assert_equal :store, stored_file.storage_key
    assert File.file?(File.join(@store_directory, stored_file.id))
    refute File.file?(File.join(@cache_directory, quarantine_file.id))
    assert_equal "clean contents", File.binread(File.join(@store_directory, stored_file.id))
    refute_nil attacher.url
  end

  it "keeps pending files in quarantine without a download address" do
    attacher = file_system_attacher
    attacher.scan_block { |_| }

    attacher.attach_cached(fakeio("waiting"))
    quarantine_file = attacher.file

    assert_equal :cache, quarantine_file.storage_key
    assert attacher.scan_pending?
    assert File.file?(File.join(@cache_directory, quarantine_file.id))
    assert Dir.empty?(@store_directory)
    assert_nil attacher.url
    assert_nil quarantine_file.url
  end

  it "keeps rejected files out of permanent storage" do
    attacher = file_system_attacher
    attacher.virus_scanner = -> (file) { false }

    attacher.attach_cached(fakeio("malicious"))
    rejected_file = attacher.file

    assert attacher.scan_rejected?
    assert_nil attacher.url
    assert attacher.cached?
    refute File.file?(File.join(@cache_directory, rejected_file.id))
    assert !File.directory?(@store_directory) || Dir.empty?(@store_directory)
  end

  it "keeps failed scans in quarantine with the error and allows retry" do
    attacher = file_system_attacher
    attempts = 0
    attacher.virus_scanner = lambda do |file|
      attempts += 1
      raise "scanner offline" if attempts == 1
      true
    end

    attacher.attach_cached(fakeio("retry me"))
    quarantined_file = attacher.file

    assert attacher.scan_failed?
    assert_equal "scanner offline", attacher.file.metadata["scan_error"]
    assert File.file?(File.join(@cache_directory, quarantined_file.id))
    assert_nil attacher.url

    attacher.rescan!

    assert attacher.scan_passed?
    assert attacher.stored?
  end

  it "applies asynchronous scanner callbacks bound to file identity and generation" do
    attacher = file_system_attacher
    task = nil
    attacher.scan_block do |a|
      task = { generation: a.scan_generation, file_id: a.file.id }
    end

    attacher.attach_cached(fakeio("queued"))

    assert attacher.scan_pending?
    assert_equal 1, task[:generation]
    assert_nil attacher.url
    assert File.file?(File.join(@cache_directory, task[:file_id]))

    # External scanner reports a clean file through the generic callable flow.
    attacher.accept_scan!(task[:generation])

    assert attacher.scan_passed?
    assert attacher.stored?
    refute File.file?(File.join(@cache_directory, task[:file_id]))
  end

  it "ignores stale callbacks after the user replaced the attachment" do
    attacher = file_system_attacher
    attacher.scan_block { |_| }

    attacher.attach_cached(fakeio("first"))
    first_generation = attacher.scan_generation
    first_id = attacher.file.id

    attacher.attach_cached(fakeio("second"))
    second_generation = attacher.scan_generation
    second_id = attacher.file.id

    # Old task's callback arrives late and must not touch the new attachment.
    attacher.accept_scan!(first_generation)

    assert attacher.scan_pending?
    assert_equal second_id, attacher.file.id
    assert File.file?(File.join(@cache_directory, first_id))
    assert File.file?(File.join(@cache_directory, second_id))

    # The current task's callback still works.
    attacher.accept_scan!(second_generation)

    assert attacher.scan_passed?
    assert File.file?(File.join(@store_directory, attacher.file.id))
    # The first task's object is not owned by the current task, so it stays.
    assert File.file?(File.join(@cache_directory, first_id))
  end

  it "makes repeated callbacks idempotent on disk" do
    attacher = file_system_attacher
    attacher.scan_block { |_| }

    attacher.attach_cached(fakeio("duplicates"))
    generation = attacher.scan_generation
    quarantine_id = attacher.file.id

    attacher.accept_scan!(generation)
    attacher.accept_scan!(generation)
    attacher.accept_scan!(generation)

    assert attacher.scan_passed?
    assert attacher.stored?
    stored_files = Dir.children(@store_directory).select do |name|
      File.file?(File.join(@store_directory, name))
    end
    assert_equal 1, stored_files.length
    refute File.file?(File.join(@cache_directory, quarantine_id))
  end
end
