require "test_helper"
require "shrine/plugins/attachment_group_commit"
require "shrine/storage/file_system"
require "tmpdir"
require "fileutils"
require "json"

describe Shrine::AttachmentGroupCommit do
  # FileSystem storage with injectable upload/delete failures and call
  # tracking, used for failing each phase of the group commit on demand and
  # asserting which objects were uploaded or reclaimed.
  class FlakyFileSystem < Shrine::Storage::FileSystem
    attr_accessor :delete_error
    attr_reader :uploaded_ids, :deleted_ids

    def initialize(*)
      super
      @uploaded_ids = []
      @deleted_ids  = []
      @upload_count = 0
    end

    def fail_upload_at=(count)
      @upload_count   = 0
      @fail_upload_at = count
    end

    def upload(io, id, **)
      @upload_count += 1
      raise Shrine::Error, "upload failed" if @fail_upload_at && @upload_count >= @fail_upload_at

      super
      @uploaded_ids << id
    end

    def delete(id)
      raise delete_error if delete_error

      super
      @deleted_ids << id
    end
  end

  before do
    @root  = Dir.mktmpdir
    @cache = FlakyFileSystem.new(File.join(@root, "cache"))
    @store = FlakyFileSystem.new(File.join(@root, "store"))

    @shrine = Class.new(Shrine)
    @shrine.storages[:cache] = @cache
    @shrine.storages[:store] = @store
    @shrine.plugin :entity
    @shrine.plugin :validation
    @shrine.plugin :attachment_group_commit

    @shrine::Attacher.validate do
      errors << "is too large" if file.size > 20
    end

    @application_class = Class.new(ShrineHelper::Struct) do
      attr_accessor :body_data, :cover_data, :attachments_data
    end
    @application_class.include @shrine::Attachment.new(:body)
    @application_class.include @shrine::Attachment.new(:cover)
    @application_class.include @shrine::Attachment.new(:attachments)

    @record = @application_class.new(
      body_data:        uploaded_data("old body"),
      cover_data:       uploaded_data("old cover"),
      attachments_data: uploaded_data("old attachments"),
    )

    @old_files = {
      body:        @record.body_attacher.file,
      cover:       @record.cover_attacher.file,
      attachments: @record.attachments_attacher.file,
    }

    # only track uploads/deletes happening inside the tests
    @store.uploaded_ids.clear
    @cache.uploaded_ids.clear
  end

  after do
    FileUtils.remove_entry(@root)
  end

  it "replaces the whole group through prepare, commit, and cleanup" do
    group = new_group

    group.prepare

    # new files are uploaded, but old references are still in place
    assert_equal 3, @store.uploaded_ids.size
    assert_old_files_exist
    assert_equal "old body", @record.body_attacher.file.read

    calls = 0
    group.commit do |columns|
      calls += 1
      assert_equal %i[body_data cover_data attachments_data], columns.keys
      columns.each_value { |data| assert_equal "store", JSON.parse(data)["storage"] }
      apply_columns(columns)
    end

    # the whole group of new references was published through one callback
    assert_equal 1, calls
    assert_equal "new body",        @record.body_attacher.file.read
    assert_equal "new cover",       @record.cover_attacher.file.read
    assert_equal "new attachments", @record.attachments_attacher.file.read
    assert_equal [], @store.deleted_ids

    group.cleanup

    # old objects are deleted, new objects stay
    assert_equal old_file_ids, @store.deleted_ids.sort
    @old_files.each_value { |file| refute file.exists? }
    assert_equal "new body", @record.body_attacher.file.read
  end

  it "runs all phases at once via .commit" do
    calls = 0
    group = Shrine::AttachmentGroupCommit.commit(@record,
      body:        fakeio("new body"),
      cover:       fakeio("new cover"),
      attachments: fakeio("new attachments"),
    ) do |columns|
      calls += 1
      apply_columns(columns)
    end

    assert_equal 1, calls
    assert_equal old_file_ids, @store.deleted_ids.sort
    assert_equal "new body", @record.body_attacher.file.read
    assert_instance_of Shrine::AttachmentGroupCommit, group
  end

  it "keeps old references and reclaims new objects when validation fails" do
    group = new_group(cover: fakeio("this cover is way too large to be valid"))

    error = assert_raises(Shrine::AttachmentGroupCommit::ValidationError) do
      group.prepare
    end

    assert_equal({ cover: ["is too large"] }, error.errors)
    assert_equal [], @store.uploaded_ids # nothing was promoted
    assert_equal 3, @cache.uploaded_ids.size
    assert_equal @cache.uploaded_ids.sort, @cache.deleted_ids.sort # reclaimed
    assert_old_files_exist
    assert_equal "old body",  @record.body_attacher.file.read
    assert_equal "old cover", @record.cover_attacher.file.read
  end

  it "keeps old references and reclaims new objects when an upload fails" do
    @store.fail_upload_at = 2 # first promote succeeds, second one fails
    group = new_group

    error = assert_raises(Shrine::Error) { group.prepare }

    assert_equal "upload failed", error.message
    assert_equal 1, @store.uploaded_ids.size
    assert_equal @store.uploaded_ids.sort, @store.deleted_ids.sort # reclaimed
    assert_equal @cache.uploaded_ids.sort, @cache.deleted_ids.sort # reclaimed
    assert_old_files_exist
    assert_equal "old body", @record.body_attacher.file.read
  end

  it "keeps old references and reclaims new objects when the commit callback fails" do
    group = new_group
    group.prepare
    assert_equal 3, @store.uploaded_ids.size

    error = assert_raises(RuntimeError) do
      group.commit { |columns| raise "database is down" }
    end

    assert_equal "database is down", error.message

    # this round's objects were reclaimed, old objects were kept
    assert_equal (@store.uploaded_ids + @cache.uploaded_ids).sort,
                 (@store.deleted_ids + @cache.deleted_ids).sort
    assert_equal [], @store.deleted_ids & old_file_ids
    assert_old_files_exist
    assert_equal "old body",        @record.body_attacher.file.read
    assert_equal "old cover",       @record.cover_attacher.file.read
    assert_equal "old attachments", @record.attachments_attacher.file.read

    # a new round can be committed afterwards
    group = new_group
    group.prepare
    group.commit { |columns| apply_columns(columns) }
    group.cleanup

    assert_equal "new body", @record.body_attacher.file.read
    assert_equal old_file_ids, (@store.deleted_ids & old_file_ids).sort
  end

  it "allows retrying a failed cleanup without undoing the commit" do
    columns = nil
    group = new_group
    group.prepare
    group.commit { |values| columns = values; apply_columns(values) }

    @store.delete_error = Shrine::Error.new("delete failed")

    error = assert_raises(Shrine::AttachmentGroupCommit::CleanupError) do
      group.cleanup
    end

    assert_equal 3, error.remaining.size
    assert_same group, error.group
    assert_equal [], @store.deleted_ids

    # the completed commit is not rolled back
    assert_equal "new body", @record.body_attacher.file.read
    assert uploaded(columns[:body_data]).exists?
    assert_old_files_exist

    # cleanup can be retried
    @store.delete_error = nil
    group.cleanup
    assert_equal old_file_ids, @store.deleted_ids.sort

    # and is idempotent afterwards
    group.cleanup
    assert_equal 3, @store.deleted_ids.size
  end

  it "supports removing an attachment by assigning nil" do
    group = new_group(attachments: nil)
    group.prepare
    group.commit { |columns| apply_columns(columns) }

    assert_nil @record.attachments_data
    assert_nil @record.attachments_attacher.file

    group.cleanup

    assert_equal 2, @store.uploaded_ids.size
    assert_equal old_file_ids, @store.deleted_ids.sort
    assert_equal "new body", @record.body_attacher.file.read
  end

  it "enforces phase order" do
    group = new_group

    assert_raises(Shrine::AttachmentGroupCommit::Error) { group.commit { } }
    assert_raises(Shrine::AttachmentGroupCommit::Error) { group.cleanup }

    group.prepare

    assert_raises(Shrine::AttachmentGroupCommit::Error) { group.prepare }
    assert_raises(ArgumentError) { group.commit }
  end

  it "requires at least one attachment" do
    assert_raises(ArgumentError) { Shrine::AttachmentGroupCommit.new(@record) }
  end

  it "is exposed through the attacher class when the plugin is loaded" do
    group = @shrine::Attacher.group_commit(@record, body: fakeio("new body"))

    assert_instance_of Shrine::AttachmentGroupCommit, group
    assert_equal %i[body], group.names
    assert_same @record, group.record
  end

  private

  def new_group(**overrides)
    assignments = {
      body:        fakeio("new body"),
      cover:       fakeio("new cover"),
      attachments: fakeio("new attachments"),
    }.merge(overrides)

    Shrine::AttachmentGroupCommit.new(@record, **assignments)
  end

  def apply_columns(columns)
    columns.each { |name, value| @record.public_send(:"#{name}=", value) }
  end

  def uploaded_data(content)
    @shrine.upload(fakeio(content), :store).to_json
  end

  def uploaded(data)
    @shrine::UploadedFile.new(JSON.parse(data))
  end

  def old_file_ids
    @old_files.values.map(&:id).sort
  end

  def assert_old_files_exist
    @old_files.each_value { |file| assert file.exists? }
  end
end
