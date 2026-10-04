# frozen_string_literal: true

require "test_helper"
require "shrine/plugins/model"
require "shrine/storage/file_system"
require "shrine/storage_migration"

describe Shrine::StorageMigration do
  before do
    @root_dir = Dir.mktmpdir("shrine-storage-migration")
    @source_dir = File.join(@root_dir, "source")
    @target_dir = File.join(@root_dir, "target")

    @source_storage = CountingFileSystem.new(@source_dir)
    @target_storage = CountingFileSystem.new(@target_dir)

    @shrine = Class.new(Shrine)
    @shrine.plugin :model
    @shrine.storages[:source] = @source_storage
    @shrine.storages[:target] = @target_storage

    @record_class = model_class(:id, :image_data)
    @record_class.include @shrine::Attachment.new(:image, cache: :source, store: :source)

    @records = {}
    @persisted = {}

    @migrator = Shrine::StorageMigration.new(
      find_attacher: ->(item) { attacher_for(@records[item.id]) },
      reload:        method(:reload_attacher),
      persist:       method(:persist_attacher),
    )
  end

  after do
    FileUtils.remove_entry(@root_dir)
  end

  it "copies, verifies and atomically switches attachments without deleting source files" do
    record = record_for("one", "image one", "one.txt")
    plan = plan_for(record, target_id: "one-copy.txt")
    log = result_log("success")

    results = @migrator.run(plan, log)

    assert_equal "switched", results.first["status"]
    assert_equal "target", @records["one"].image.storage_key.to_s
    assert_equal "one-copy.txt", @records["one"].image.id
    assert_equal content(@source_dir, "one.txt"), content(@target_dir, "one-copy.txt")
    assert_equal "image one", content(@source_dir, "one.txt")
    assert_equal 1, @target_storage.upload_count
    assert_equal plan.items.first.metadata, results.first["target_file"]["metadata"]
  end

  it "uses the attacher's built-in atomic persistence when no callbacks are supplied" do
    record = record_for("orm", "orm image", "orm.txt")
    plan = plan_for(record, target_id: "orm-copy.txt")
    log = result_log("orm-persistence")

    migrator = Shrine::StorageMigration.new(
      find_attacher: ->(item) { attacher_with_atomic_persistence(@records[item.id], item) },
    )

    results = migrator.run(plan, log)

    assert_equal "switched", results.first["status"]
    assert_equal "target", @records["orm"].image.storage_key.to_s
    assert_equal "orm-copy.txt", @records["orm"].image.id
    assert_equal "target", @shrine::Attacher.from_model(@records["orm"], :image).file.storage_key.to_s
  end

  it "retries a failed copy and does not reupload an already verified object after interruption" do
    record = record_for("one", "image one", "one.txt")
    plan = plan_for(record, target_id: "one-copy.txt")
    log = result_log("copy-failure")

    @target_storage.fail_next_upload

    first = @migrator.run(plan, log)
    assert_equal "copy_failed", first.first["status"]
    assert_equal 1, first.first["attempts"]
    refute File.exist?(File.join(@target_dir, "one-copy.txt"))

    results = @migrator.run(plan, log)
    assert_equal "switched", results.first["status"]
    assert_equal 2, @target_storage.upload_count
    interrupted_record = record_for("two", "image two", "two.txt")
    interrupted_storage = CountingFileSystem.new(File.join(@root_dir, "interrupted-target"))
    @shrine.storages[:interrupted_target] = interrupted_storage
    interrupted_plan = plan_for(
      interrupted_record,
      target_storage: :interrupted_target,
      target_id: "two-copy.txt",
    )
    interrupted_log = result_log("interrupted-switch")
    interrupt_switch

    interrupted = @migrator.run(interrupted_plan, interrupted_log)
    assert_equal "switch_failed", interrupted.first["status"]
    resume = @migrator.run(interrupted_plan, interrupted_log)
    assert_equal "switched", resume.first["status"]
    assert_equal 1, interrupted_storage.upload_count
    assert_equal "two-copy.txt", @records["two"].image.id
  end

  it "does not switch or copy when the user has replaced the attachment before retry" do
    record = record_for("one", "original", "one.txt")
    plan = plan_for(record, target_id: "one-copy.txt")
    log = result_log("attachment-replaced")

    @target_storage.fail_next_upload
    assert_equal "copy_failed", @migrator.run(plan, log).first["status"]

    replacement = record_for("one", "replacement", "replacement-one.txt")
    @records["one"] = replacement
    @persisted["one"] = replacement.image_data

    results = @migrator.run(plan, log)
    assert_equal "attachment_changed", results.first["status"]
    assert_equal "source", @records["one"].image.storage_key.to_s
    assert_equal replacement.image.id, @records["one"].image.id
    assert_equal 1, @target_storage.upload_count
  end

  it "does not switch when the attachment changes after verification, then resumes after it is restored" do
    record = record_for("one", "original", "one.txt")
    plan = plan_for(record, target_id: "one-copy.txt")
    log = result_log("post-copy-change")

    should_replace = true
    reload_hook = -> { replace_record("one", "replaced") if should_replace }
    @migrator = Shrine::StorageMigration.new(
      find_attacher: ->(item) { attacher_for(@records[item.id]) },
      switch:      ->(**arguments) { switch_attacher_with_hook(reload_hook, **arguments) },
    )

    results = @migrator.run(plan, log)
    assert_equal "attachment_changed", results.first["status"]
    assert_equal "attachment_changed", log["one"]["status"]
    assert_equal "source", @records["one"].image.storage_key.to_s
    assert_equal "replaced", @records["one"].image.open(&:read)

    @records["one"] = record
    @persisted["one"] = record.image_data
    should_replace = false
    resumed = @migrator.run(plan, log)
    assert_equal "switched", resumed.first["status"]
    assert_equal "target", @records["one"].image.storage_key.to_s
    assert_equal "one-copy.txt", @records["one"].image.id
  end

  it "is idempotent when executed repeatedly" do
    record = record_for("one", "image one", "one.txt")
    plan = plan_for(record, target_id: "one-copy.txt")
    log = result_log("idempotent")

    first = @migrator.run(plan, log)
    second = @migrator.run(plan, log)
    third = @migrator.run(plan, log)

    assert_equal ["switched"], first.map { |result| result["status"] }
    assert_equal first, second
    assert_equal first, third
    assert_equal 1, @target_storage.upload_count
  end

  private

  def record_for(id, contents, location)
    attacher = @shrine::Attacher.from_model(@record_class.new(id: id), :image)
    attacher.attach(FakeIO.new(contents, filename: File.basename(location)),
                    storage: :source, location: location,
                    metadata: { "filename" => File.basename(location), "size" => contents.bytesize })

    record = attacher.record
    @records[id] = record
    @persisted[id] = record.image_data
    record
  end

  def plan_for(record, target_storage: :target, target_id:)
    attacher = attacher_for(record)
    plan = Shrine::StorageMigration::Plan.build([
      {
        id: record.id,
        attacher: attacher,
        target_storage: target_storage,
        target_id: target_id,
      },
    ])
    plan_path = File.join(@root_dir, "plan-#{record.id}.json")
    plan.save(plan_path)
    Shrine::StorageMigration::Plan.load(plan_path)
  end

  def result_log(name)
    Shrine::StorageMigration::ResultLog.load(File.join(@root_dir, "results-#{name}.json"))
  end

  def attacher_for(record)
    @shrine::Attacher.from_model(record, :image)
  end

  def attacher_with_atomic_persistence(record, item)
    attacher = attacher_for(record)
    record_class = @record_class
    shrine = @shrine
    persisted = @persisted
    attacher.define_singleton_method(:atomic_persist) do |source_file|
      reloaded = record_class.new(id: item.id)
      reloaded.image_data = persisted[item.id]
      reloaded_attacher = shrine::Attacher.from_model(reloaded, :image)

      fail Shrine::AttachmentChanged unless reloaded_attacher.file == source_file

      yield if block_given?
      persisted[item.id] = record.image_data
      record.image_data = persisted[item.id]
    end
    attacher
  end

  def reload_attacher(attacher, item)
    reloaded = @record_class.new(id: item.id)
    reloaded.image_data = @persisted[item.id]
    yield @shrine::Attacher.from_model(reloaded, :image)
  end

  def persist_attacher(attacher, item)
    @persisted[item.id] = attacher.record.image_data
    @records[item.id].image_data = attacher.record.image_data
  end

  def interrupt_switch
    original_persist = method(:persist_attacher)
    attempts = 0

    @migrator = Shrine::StorageMigration.new(
      find_attacher: ->(plan_item) { attacher_for(@records[plan_item.id]) },
      reload: ->(attacher, plan_item, &block) { reload_attacher(attacher, plan_item, &block) },
      persist: ->(attacher, plan_item) {
        attempts += 1
        fail("simulated interruption") if attempts == 1
        original_persist.call(attacher, plan_item)
      },
    )
  end

  def replace_record(id, contents)
    record = record_for(id, contents, "replacement-#{id}.txt")
    @records[id] = record
    @persisted[id] = record.image_data
  end

  def switch_attacher_with_hook(reload_hook, item:, attacher:, source_file:, target_file:)
    reload_hook.call
    reloaded = @record_class.new(id: item.id)
    reloaded.image_data = @persisted[item.id]
    reloaded_attacher = @shrine::Attacher.from_model(reloaded, :image)
    fail Shrine::AttachmentChanged unless reloaded_attacher.file == source_file

    reloaded_attacher.set(target_file)
    persist_attacher(reloaded_attacher, item)
  end

  def content(directory, id)
    File.read(File.join(directory, id))
  end

  class CountingFileSystem < Shrine::Storage::FileSystem
    attr_reader :upload_count

    def initialize(*)
      super
      @upload_count = 0
      @fail_next = false
    end

    def fail_next_upload
      @fail_next = true
    end

    def upload(io, id, **)
      @upload_count += 1
      if @fail_next
        @fail_next = false
        fail Errno::EIO, "simulated copy failure"
      end
      super
    end
  end
end
