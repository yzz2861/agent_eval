# frozen_string_literal: true

require "test_helper"
require "shrine/storage/file_system"
require "shrine/plugins/model"
require "shrine/plugins/validation"
require "shrine/plugins/versions"
require "tmpdir"

describe Shrine::AttacherGroup do
  before do
    @root = Dir.mktmpdir
    @cache_storage = failure_storage(:cache)
    @store_storage = failure_storage(:store)

    @shrine = Class.new(Shrine)
    @shrine.storages[:cache] = @cache_storage
    @shrine.storages[:store] = @store_storage
    @shrine.plugin :model
    @shrine.plugin :validation
    @shrine.plugin :versions
    @shrine::Attacher.validate {}

    @application_class = Struct.new(:body_data, :cover_data, :attachments_data)
    @application = @application_class.new

    @body_attacher = @shrine::Attacher.from_model(@application, :body)
    @cover_attacher = @shrine::Attacher.from_model(@application, :cover)
    @attachments_attacher = @shrine::Attacher.from_model(@application, :attachments)
  end

  after do
    FileUtils.remove_entry(@root) if File.exist?(@root)
  end

  it "prepares, commits once, and cleans old objects for a group" do
    old_body = @body_attacher.attach(fakeio("old body"))
    old_cover = @cover_attacher.attach(fakeio("old cover"))
    old_attachments = @attachments_attacher.attach([fakeio("old attachment")])
    persist_application!(old_body, old_cover, old_attachments)

    @body_attacher.attach_cached(fakeio("new body"))
    @cover_attacher.attach_cached(fakeio("new cover"))
    @attachments_attacher.attach_cached([fakeio("new attachment 1"), fakeio("new attachment 2")])

    references = nil
    group = Shrine::AttacherGroup.new(
      body: @body_attacher,
      cover: @cover_attacher,
      attachments: @attachments_attacher,
    )

    group.prepare
    assert @body_attacher.stored?
    assert @cover_attacher.stored?
    assert_equal :store, @attachments_attacher.file.first.storage_key
    assert_equal 2, @attachments_attacher.file.length
    assert old_body.exists?
    assert old_cover.exists?
    assert old_attachments.first.exists?

    group.commit { |new_references| references = persist_references(new_references) }

    assert group.committed?
    assert_equal JSON.parse(@application.body_data)["id"], JSON.parse(references[:body])["id"]
    assert_equal JSON.parse(@application.cover_data)["id"], JSON.parse(references[:cover])["id"]
    assert_equal 2, JSON.parse(@application.attachments_data).length
    assert old_body.exists?
    assert old_cover.exists?
    assert old_attachments.first.exists?

    group.cleanup

    refute old_body.exists?
    refute old_cover.exists?
    refute old_attachments.first.exists?
    assert @body_attacher.file.exists?
    assert @cover_attacher.file.exists?
    assert @attachments_attacher.file.all?(&:exists?)
    refute @body_attacher.changed?
    refute @cover_attacher.changed?
    refute @attachments_attacher.changed?
  end

  it "keeps old references and deletes new objects when persistence fails" do
    old_body = @body_attacher.attach(fakeio("old body"))
    old_cover = @cover_attacher.attach(fakeio("old cover"))
    persist_application!(old_body, old_cover, nil)

    @body_attacher.attach_cached(fakeio("new body"))
    @cover_attacher.attach_cached(fakeio("new cover"))

    group = Shrine::AttacherGroup.new(body: @body_attacher, cover: @cover_attacher)
    group.prepare
    new_body = @body_attacher.file
    new_cover = @cover_attacher.file

    error = assert_raises(Shrine::AttacherGroup::CommitFailed) do
      group.commit { raise "database is unavailable" }
    end

    assert_equal "database is unavailable", error.cause.message
    assert_equal old_body, @body_attacher.file
    assert_equal old_cover, @cover_attacher.file
    assert_equal old_body.data, JSON.parse(@application.body_data)
    assert_equal old_cover.data, JSON.parse(@application.cover_data)
    assert old_body.exists?
    assert old_cover.exists?
    refute new_body.exists?
    refute new_cover.exists?
  end

  it "retries post-commit cleanup without undoing the commit" do
    old_body = @body_attacher.attach(fakeio("old body"))
    persist_application!(old_body, nil, nil)
    @body_attacher.attach_cached(fakeio("new body"))

    group = Shrine::AttacherGroup.new(body: @body_attacher)
    new_body = nil
    group.commit do |references|
      new_body = @shrine.uploaded_file(references[:body])
    end

    @store_storage.fail_next(:delete)

    assert_raises(RuntimeError) { group.cleanup }
    assert group.committed?
    assert old_body.exists?
    assert new_body.exists?
    assert_equal new_body, @body_attacher.file

    group.cleanup

    refute old_body.exists?
    assert new_body.exists?
    refute @body_attacher.changed?
  end

  it "restores old references after an upload failure and deletes prepared objects" do
    old_body = @body_attacher.attach(fakeio("old body"))
    persist_application!(old_body, nil, nil)
    @body_attacher.attach_cached(fakeio("new body"))
    @cover_attacher.attach_cached(fakeio("new cover"))

    @store_storage.fail_upload_after(1)
    @store_storage.reset_upload_failures

    group = Shrine::AttacherGroup.new(body: @body_attacher, cover: @cover_attacher)

    assert_raises(RuntimeError) { group.prepare }

    assert_equal old_body, @body_attacher.file
    assert_equal :store, old_body.storage_key
    assert_nil @cover_attacher.file
    assert old_body.exists?
    assert_empty stored_files
  end

  it "aggregates validation failures, keeps old objects, and deletes new objects" do
    old_body = @body_attacher.attach(fakeio("old body"))
    persist_application!(old_body, nil, nil)
    @body_attacher.singleton_class.validate { errors << "body is invalid" }
    @cover_attacher.singleton_class.validate { errors << "cover is invalid" }
    @body_attacher.attach_cached(fakeio("new body"))
    @cover_attacher.attach_cached(fakeio("new cover"))

    group = Shrine::AttacherGroup.new(body: @body_attacher, cover: @cover_attacher)

    error = assert_raises(Shrine::AttacherGroup::ValidationFailed) do
      group.prepare
    end

    assert_equal [["body is invalid"], ["cover is invalid"]], error.errors
    assert_equal old_body, @body_attacher.file
    assert_nil @cover_attacher.file
    assert old_body.exists?
    assert_empty Dir[File.join(@root, "store", "**", "*")].select { |path| File.file?(path) }
  end

  it "accepts IO objects when constructing the group" do
    group = Shrine::AttacherGroup.new(body: [@body_attacher, fakeio("new body")])
    references = nil

    group.commit { |new_references| references = persist_references(new_references) }
    group.cleanup

    assert_equal "new body", @body_attacher.file.read
    assert_equal @application.body_data, references[:body]
  end

  it "restores a cleared attachment after persistence failure" do
    old_body = @body_attacher.attach(fakeio("old body"))
    persist_application!(old_body, nil, nil)

    group = Shrine::AttacherGroup.new(body: [@body_attacher, nil])
    group.prepare
    assert_nil @body_attacher.file

    assert_raises(Shrine::AttacherGroup::CommitFailed) do
      group.commit { raise "database is unavailable" }
    end

    assert_equal old_body, @body_attacher.file
    assert_equal old_body.data, JSON.parse(@application.body_data)
    assert old_body.exists?
  end

  it "retries deleting new objects after a failed callback rollback" do
    old_body = @body_attacher.attach(fakeio("old body"))
    persist_application!(old_body, nil, nil)
    @body_attacher.attach_cached(fakeio("new body"))

    group = Shrine::AttacherGroup.new(body: @body_attacher)
    group.prepare
    new_body = @body_attacher.file
    @store_storage.fail_next(:delete)

    assert_raises(RuntimeError) do
      group.commit { raise "database is unavailable" }
    end

    assert_equal old_body, @body_attacher.file
    assert new_body.exists?

    group.abort

    assert_equal old_body, @body_attacher.file
    refute new_body.exists?
    assert old_body.exists?
  end

  private

  def failure_storage(key)
    directory = File.join(@root, key.to_s)
    storage = Class.new(Shrine::Storage::FileSystem) do
      attr_reader :failures

      define_method(:initialize) do |directory|
        super(directory)
        @failures = {}
        @upload_attempts = 0
        @fail_upload_after = nil
      end

      define_method(:fail_next) do |method|
        @failures[method] = true
      end

      define_method(:fail_upload_after) do |attempts|
        @fail_upload_after = attempts
      end

      define_method(:reset_upload_failures) do
        @upload_attempts = 0
      end

      define_method(:upload) do |io, id, **options|
        @upload_attempts += 1
        raise "injected upload failure" if @failures.delete(:upload) || (@fail_upload_after && @upload_attempts > @fail_upload_after)

        super(io, id, **options)
      end

      define_method(:delete) do |id|
        raise "injected delete failure" if @failures.delete(:delete)

        super(id)
      end
    end

    storage.new(directory)
  end

  def persist_application!(body, cover, attachments)
    @application.body_data = body && body.to_json
    @application.cover_data = cover && cover.to_json
    @application.attachments_data = attachments && attachments.to_json
    @body_attacher = @shrine::Attacher.from_model(@application, :body)
    @cover_attacher = @shrine::Attacher.from_model(@application, :cover)
    @attachments_attacher = @shrine::Attacher.from_model(@application, :attachments)
  end

  def persist_references(references)
    @application.body_data = references[:body]
    @application.cover_data = references[:cover]
    @application.attachments_data = references[:attachments]
    references
  end

  def stored_files
    Dir[File.join(@root, "store", "**", "*")].select { |path| File.file?(path) }
  end
end
