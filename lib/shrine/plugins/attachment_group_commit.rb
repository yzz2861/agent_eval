# frozen_string_literal: true

class Shrine
  module Plugins
    # Documentation can be found on doc/plugins/attachment_group_commit.md
    module AttachmentGroupCommit
      module AttacherClassMethods
        # Returns a helper for replacing multiple attachments of a record as
        # a group. See `Shrine::AttachmentGroupCommit` for details.
        #
        #     group = Shrine::Attacher.group_commit(application,
        #       body: body_io, cover: cover_io, attachments: attachments_io)
        def group_commit(record, **assignments)
          Shrine::AttachmentGroupCommit.new(record, **assignments)
        end
      end
    end

    register_plugin(:attachment_group_commit, AttachmentGroupCommit)
  end

  # Replaces multiple attachments of a record as a group (e.g. an application
  # with a body, a cover, and an attachment list that need to be swapped
  # together).
  #
  # File storage is not transactional, so instead of pretending it is, the
  # group commit is split into three explicit phases:
  #
  # 1. *prepare* – assigns the new files to each attacher, validates them,
  #    and uploads them to permanent storage. The record is not modified.
  # 2. *commit* – publishes the whole group of new file references through a
  #    single persistence callback provided by the caller (e.g. one database
  #    update). If the callback fails, old references are kept and the files
  #    uploaded in this round are reclaimed.
  # 3. *cleanup* – deletes the old files. If deletion fails, the error is
  #    retryable (call `#cleanup` again); the completed commit is never
  #    rolled back.
  #
  #     group = Shrine::AttachmentGroupCommit.new(application,
  #       body: body_io, cover: cover_io, attachments: attachments_io)
  #
  #     group.prepare
  #     group.commit do |columns|
  #       application.update!(columns) # one persistence call for the whole group
  #     end
  #     group.cleanup
  #
  # Or all at once:
  #
  #     Shrine::AttachmentGroupCommit.commit(application, body: body_io, ...) do |columns|
  #       application.update!(columns)
  #     end
  #
  # Assigning `nil` removes the corresponding attachment. Validation requires
  # the `validation` plugin; the record is expected to use the `entity` or
  # `model` plugin so that `#<name>_attacher` methods are defined.
  class AttachmentGroupCommit
    # Generic group commit error.
    class Error < Shrine::Error; end

    # Raised when one or more attachments fail validation during prepare.
    # Carries a hash of attachment name => validation error messages.
    class ValidationError < Error
      attr_reader :errors

      def initialize(errors)
        @errors = errors

        messages = errors.flat_map do |name, name_errors|
          name_errors.map { |message| "#{name} #{message}" }
        end

        super("validation failed: #{messages.join(', ')}")
      end
    end

    # Raised when deleting old files fails after a successful commit. The
    # completed commit is *not* rolled back; call
    # `Shrine::AttachmentGroupCommit#cleanup` again to retry deleting the
    # remaining files.
    class CleanupError < Error
      attr_reader :group, :remaining

      def initialize(group, remaining)
        @group     = group
        @remaining = remaining

        ids = remaining.map { |file| file.id.inspect }.join(", ")

        super("failed to delete old files (#{ids}); retry with `group.cleanup`")
      end
    end

    attr_reader :record, :names

    # Runs prepare, commit, and cleanup in one go.
    def self.commit(record, **assignments, &persist)
      group = new(record, **assignments)
      group.prepare
      group.commit(&persist)
      group.cleanup
      group
    end

    def initialize(record, **assignments)
      fail ArgumentError, "no attachments given" if assignments.empty?

      @record      = record
      @names       = assignments.keys
      @assignments = assignments
      @phase       = :initialized
      @uploads     = [] # files uploaded during this round (reclaimed on failure)
      @previous    = {} # attachment name => previously attached file
      @remaining   = [] # old files still to be deleted
    end

    # Assigns the new files to all attachers, validates them, and uploads
    # them to permanent storage. On any failure the files uploaded in this
    # round are reclaimed and old references are kept.
    def prepare
      assert_phase :initialized, message: "group has already been prepared"

      begin
        @names.each do |name|
          attacher = attacher_for(name)
          @previous[name] = attacher.file
          attacher.assign(@assignments[name])
          @uploads << attacher.file if uploaded_this_round?(attacher)
        end

        validate!

        @names.each do |name|
          attacher = attacher_for(name)
          attacher.promote_cached
          @uploads << attacher.file if attacher.file && attacher.file != @previous[name]
        end
      rescue Exception
        compensate
        raise
      end

      @phase = :prepared
      self
    end

    # Publishes the whole group of new file references through the given
    # persistence callback, which is called exactly once with a hash of
    # attachment column values (e.g. `{ body_data: "...", ... }`).
    #
    # If the callback fails, old references are kept and the files uploaded
    # in this round are reclaimed.
    def commit(&persist)
      assert_phase :prepared, message: "prepare must be called before commit"
      fail ArgumentError, "persistence callback is required" unless persist

      begin
        persist.call(column_values)
      rescue Exception
        compensate
        raise
      end

      @phase     = :committed
      @remaining = @previous.values.compact
      self
    end

    # Deletes the old files replaced by the commit. Failures raise
    # `Shrine::AttachmentGroupCommit::CleanupError` and can be retried by
    # calling this method again; the completed commit is never rolled back.
    def cleanup
      assert_phase :committed, :cleaned, message: "commit must be called before cleanup"
      return self if @phase == :cleaned

      failed = @remaining.reject do |file|
        begin
          file.delete
          true
        rescue StandardError
          false
        end
      end

      @remaining = failed
      fail CleanupError.new(self, failed) if failed.any?

      @phase = :cleaned
      self
    end

    # Returns the new attachment column values for the whole group, e.g.
    # `{ body_data: "...", cover_data: "...", attachments_data: "..." }`.
    def column_values
      @names.map { |name| attacher_for(name).column_values }.reduce(:merge)
    end

    private

    def attacher_for(name)
      (@attachers ||= {})[name] ||= @record.public_send(:"#{name}_attacher")
    end

    def validate!
      errors = @names.each_with_object({}) do |name, hash|
        attacher = attacher_for(name)
        hash[name] = attacher.errors.dup if attacher.respond_to?(:errors) && attacher.errors.any?
      end

      fail ValidationError, errors if errors.any?
    end

    # Whether the current attachment is a new object uploaded during this
    # round (as opposed to an existing cached file assigned by reference).
    def uploaded_this_round?(attacher)
      value = @assignments[attacher.name]
      attacher.file && !value.nil? && !value.is_a?(String) && !value.is_a?(Hash)
    end

    # Reclaims the files uploaded during this round and restores old
    # references, leaving the record as if the group commit never happened.
    def compensate
      @uploads.reverse_each do |file|
        begin
          file.delete
        rescue StandardError
          # best effort: keep reclaiming the remaining objects
        end
      end
      @uploads.clear

      @previous.each { |name, file| attacher_for(name).set(file) }

      @phase = :initialized
    end

    def assert_phase(*phases, message:)
      return if phases.include?(@phase)

      fail Error, message
    end
  end
end
