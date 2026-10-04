# frozen_string_literal: true

# Tests for the storage migration plan/executor. Two temporary directories
# simulate the source and target storages.
#
#   bundle exec ruby examples/storage_migration/test_storage_migration.rb

require "minitest/autorun"
require "tmpdir"
require "stringio"
require "fileutils"
require "json"

require_relative "lib/storage_migration"
require_relative "support/document"

# Storage wrapper that records uploaded object ids.
class CountingStorage
  attr_reader :uploads

  def initialize(storage)
    @storage = storage
    @uploads = []
  end

  def upload(io, id, **options)
    @uploads << id
    @storage.upload(io, id, **options)
  end

  def method_missing(name, *args, **options, &block)
    @storage.public_send(name, *args, **options, &block)
  end

  def respond_to_missing?(name, include_private = false)
    @storage.respond_to?(name, include_private) || super
  end
end

# Storage wrapper that fails the given number of uploads, then recovers.
class FlakyStorage < CountingStorage
  def initialize(storage, failures:)
    super(storage)
    @failures = failures
  end

  def upload(io, id, **options)
    if @failures > 0
      @failures -= 1
      raise Shrine::Error, "simulated storage outage"
    end

    super
  end
end

class StorageMigrationTest < Minitest::Test
  def setup
    @dirs = 4.times.map { Dir.mktmpdir }
    source_dir, target_dir, cache_dir, manifest_dir = @dirs

    MyUploader.storages = {
      cache:   Shrine::Storage::FileSystem.new(cache_dir),
      store:   Shrine::Storage::FileSystem.new(source_dir),
      archive: Shrine::Storage::FileSystem.new(target_dir),
    }

    @db   = DocumentStore.new
    @plan = StorageMigration::Plan.new(
      source_storage:  :store,
      target_storage:  :archive,
      target_location: "migrated",
      manifest_path:   File.join(manifest_dir, "manifest.jsonl"),
    )
  end

  def teardown
    @dirs.each { FileUtils.remove_entry(_1) }
  end

  def test_copy_switch_and_cleanup
    docs = [seed(1, "first"), seed(2, "second")]

    executor.run(docs)

    docs.each do |doc|
      data = column(doc)
      assert_equal "archive", data["storage"]
      assert data["id"].start_with?("migrated/"), "expected migrated location, got #{data['id']}"
      assert_equal content_of(doc), read_from(:archive, data["id"])
      assert_equal "switched", entry_for(doc)["status"]
    end

    # source objects are untouched until the explicit cleanup phase
    assert_equal 2, object_count(:store)

    executor.cleanup_phase(docs)

    assert_equal 0, object_count(:store)
    assert_equal 2, object_count(:archive)
    docs.each { |doc| assert_equal "cleaned", entry_for(doc)["status"] }
  end

  def test_copy_failure_is_recorded_and_resumed
    doc  = seed(1, "contents")
    good = seed(2, "other")

    flaky = FlakyStorage.new(MyUploader.storages[:archive], failures: 1)
    MyUploader.storages[:archive] = flaky

    executor.run([doc, good]) # first upload fails, second succeeds

    assert_equal "failed", entry_for(doc)["status"]
    assert_match "simulated storage outage", entry_for(doc)["error"]
    assert_equal "store", column(doc)["storage"] # untouched
    assert_equal "switched", entry_for(good)["status"]

    executor.run([doc, good]) # storage recovered; resume from the manifest

    assert_equal "switched", entry_for(doc)["status"]
    assert_equal "archive", column(doc)["storage"]
    assert_equal "contents", read_from(:archive, column(doc)["id"])
    assert_equal 2, flaky.uploads.size # one retry, no re-upload of the good doc
  end

  def test_switch_is_skipped_when_attachment_was_replaced
    doc = seed(1, "original")

    executor.copy_phase([doc])
    assert_equal "copied", entry_for(doc)["status"]

    # the user replaces the attachment before the switch phase runs
    replacement = upload_to(:store, "replacement", filename: "new.txt")
    @db.write(doc.id, replacement.to_json)

    executor.switch_phase([doc])

    assert_equal "skipped", entry_for(doc)["status"]
    assert_equal "attachment_changed", entry_for(doc)["reason"]
    assert_equal replacement.id, column(doc)["id"] # user's file untouched
    assert_equal "store", column(doc)["storage"]

    executor.run([doc]) # next run migrates the replacement

    assert_equal "switched", entry_for(doc)["status"]
    assert_equal "archive", column(doc)["storage"]
    assert_equal "replacement", read_from(:archive, column(doc)["id"])
  end

  def test_rerun_does_not_reupload_and_cleanup_is_idempotent
    docs = [seed(1, "first"), seed(2, "second")]

    counting = CountingStorage.new(MyUploader.storages[:archive])
    MyUploader.storages[:archive] = counting

    executor.run(docs)
    assert_equal 2, counting.uploads.size

    # a fresh executor (e.g. after a restart) resumes from the manifest
    StorageMigration::Executor.new(@plan, uploader: MyUploader, name: :image).run(docs)
    assert_equal 2, counting.uploads.size, "expected no re-upload of verified objects"
    docs.each { |doc| assert_equal "switched", entry_for(doc)["status"] }

    executor.cleanup_phase(docs)
    executor.cleanup_phase(docs) # idempotent

    assert_equal 0, object_count(:store)
    docs.each { |doc| assert_equal "cleaned", entry_for(doc)["status"] }
  end

  private

  def executor
    @executor ||= StorageMigration::Executor.new(@plan, uploader: MyUploader, name: :image)
  end

  def seed(id, content)
    file = upload_to(:store, content, filename: "doc-#{id}.txt")
    @db.create(id, file.to_json)
    Document.new(@db, id)
  end

  def upload_to(storage, content, filename:)
    MyUploader.upload(StringIO.new(content), storage,
      metadata: { "filename" => filename, "mime_type" => "text/plain" })
  end

  def column(doc)
    JSON.parse(doc.image_data)
  end

  def content_of(doc)
    MyUploader.uploaded_file(JSON.parse(@db.read(doc.id))).read
  end

  def read_from(storage, id)
    MyUploader.storages[storage.to_sym].open(id).read
  end

  def entry_for(doc)
    executor.manifest["Document##{doc.id}"]
  end

  def object_count(storage)
    dir = MyUploader.storages[storage.to_sym]
    dir = dir.instance_variable_get(:@storage) while dir.is_a?(CountingStorage)
    count_files(dir.directory.to_s)
  end

  def count_files(dir)
    Dir.children(dir).sum do |child|
      path = File.join(dir, child)
      File.directory?(path) ? count_files(path) : 1
    end
  end
end
