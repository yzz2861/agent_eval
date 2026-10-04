# frozen_string_literal: true

require "monitor"

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/deletion_protection
    module DeletionProtection
      # Thread-safe in-memory registry of deletion state. The state is keyed
      # by storage and file id, so it is independent from the records that
      # reference the file and survives attachment replacement and record
      # destruction.
      #
      # A custom registry (backed by Redis, a database table, ...) can be
      # configured with the :registry option, as long as it responds to the
      # same public methods.
      class ProtectionRegistry
        include MonitorMixin

        def initialize
          super
          @records = {}
        end

        # Records that the file was requested for deletion. When a default
        # retention duration is given, its absolute deadline is recorded the
        # first time the file leaves application references. Existing holds
        # and deadlines are always preserved.
        def mark_pending(storage_key, id, at:, retain_for: nil)
          synchronize do
            record = record_for(storage_key, id)

            if !record[:pending] && retain_for && record[:retain_until].nil?
              record[:retain_until] = at + retain_for
            end

            record[:pending] = true
            dup_record(record)
          end
        end

        # Cancels a pending deletion. Holds and the retention deadline remain
        # recorded and can still block future deletions. Returns the recorded
        # state, or nil when nothing was recorded for the file.
        def unmark_pending(storage_key, id)
          synchronize do
            record = @records.dig(storage_key.to_sym, id)
            record[:pending] = false if record
            record && dup_record(record)
          end
        end

        # Adds a named hold. A nil until_time means the hold is indefinite;
        # otherwise the hold expires automatically at the given time.
        # Re-adding an existing hold replaces its deadline.
        def add_hold(storage_key, id, name, until_time: nil)
          synchronize do
            record = record_for(storage_key, id)
            record[:holds][name.to_sym] = until_time
            dup_record(record)
          end
        end

        # Removes a named hold. Other holds and the retention deadline stay in
        # effect. Returns nil when no state was recorded for the file.
        def release_hold(storage_key, id, name)
          synchronize do
            record = @records.dig(storage_key.to_sym, id)
            record&.fetch(:holds, nil)&.delete(name.to_sym)
            record && dup_record(record)
          end
        end

        # Sets an absolute retention deadline. An earlier deadline never
        # shortens a deadline that was already recorded.
        def set_retain_until(storage_key, id, until_time)
          synchronize do
            record  = record_for(storage_key, id)
            current = record[:retain_until]

            if current.nil? || (until_time && until_time > current)
              record[:retain_until] = until_time
            end

            dup_record(record)
          end
        end

        # Returns the recorded state for the file, or nil if nothing is known.
        def get(storage_key, id)
          synchronize do
            record = @records.dig(storage_key.to_sym, id)
            record && dup_record(record)
          end
        end

        # Returns an array of symbols explaining why physical deletion is not
        # currently allowed for the file:
        #
        #   :retain_until – the retention deadline has not passed
        #   :hold_<name>  – the named hold is still active
        #
        # Pending state is tracked separately (see #get); an empty array here
        # means no hold or retention rule currently blocks the file.
        def block_reasons(storage_key, id, at:)
          record = get(storage_key, id)
          return [] if record.nil?

          reasons = []
          reasons << :retain_until if record[:retain_until] && record[:retain_until] > at

          record[:holds].each do |name, until_time|
            reasons << "hold_#{name}".to_sym if until_time.nil? || until_time > at
          end

          reasons
        end

        # Physically deletes pending files whose protection has expired by
        # yielding their ids. Expired records that are not pending are simply
        # forgotten. The physical deletion happens before the state is
        # discarded, so a failed deletion can be retried on the next call.
        #
        # Returns the ids that were physically deleted.
        def cleanup(storage_key, at:)
          deleted = []

          synchronize do
            storage_records = @records[storage_key.to_sym]
            return [] if storage_records.nil? || storage_records.empty?

            storage_records.dup.each do |id, snapshot|
              record  = dup_record(snapshot)
              reasons = record[:pending] ? block_reasons_record(record, at) : [:not_pending]

              if record[:pending] && reasons.empty?
                yield id
                storage_records.delete(id)
                deleted << id
              elsif !record[:pending] && releasable?(record, at)
                storage_records.delete(id)
              end
            end
          end

          deleted
        end

        private

        def record_for(storage_key, id)
          @records[storage_key.to_sym] ||= {}
          @records[storage_key.to_sym][id] ||=
            { pending: false, holds: {}, retain_until: nil }
        end

        def block_reasons_record(record, at)
          return [] if record.nil?

          reasons = []
          reasons << :retain_until if record[:retain_until] && record[:retain_until] > at

          record[:holds].each do |name, until_time|
            reasons << "hold_#{name}".to_sym if until_time.nil? || until_time > at
          end

          reasons
        end

        # Whether a non-pending record carries any state that is still active.
        def releasable?(record, at)
          return false if record[:retain_until] && record[:retain_until] > at

          record[:holds].none? { |_, until_time| until_time.nil? || until_time > at }
        end

        def dup_record(record)
          {
            pending:      record[:pending],
            holds:        record[:holds].dup,
            retain_until: record[:retain_until],
          }
        end
      end

      def self.configure(uploader, **opts)
        uploader.opts[:deletion_protection] ||=
          { retention_period: nil, clock: nil }
        uploader.opts[:deletion_protection].merge!(opts)
        uploader.opts[:deletion_protection][:clock] ||= -> { Time.now }
      end

      module ClassMethods
        # The configured registry, or a per-uploader in-memory registry. Each
        # subclass gets its own default registry via its inherited ivar.
        def deletion_protection_registry
          opts[:deletion_protection][:registry] || @deletion_protection_registry ||=
            ProtectionRegistry.new
        end

        def inherited(subclass)
          super
          subclass.instance_variable_set(:@deletion_protection_registry, nil)
        end
      end

      module AttacherClassMethods
        # Registry shared by all attachers created by this uploader.
        def deletion_protection_registry
          shrine_class.deletion_protection_registry
        end

        # Synchronous cleanup entry points usable from rake tasks or admin
        # actions without instantiating an attacher.
        def cleanup_deletions(storage_key: :store, at: shrine_class.opts[:deletion_protection][:clock].call)
          new.cleanup_deletions(storage_key: storage_key, at: at)
        end

        def cleanup_all_deletions(at: shrine_class.opts[:deletion_protection][:clock].call)
          new.cleanup_all_deletions(at: at)
        end
      end

      module AttacherMethods
        # Adds an administrative hold on the given file (defaults to the
        # currently attached file). A nil until_time places an indefinite
        # hold; otherwise the hold expires automatically at the given time.
        def hold(name: :admin, until_time: nil, file: self.file)
          file ||= file!
          deletion_protection_registry.add_hold(
            file.storage_key, file.id, name, until_time: until_time
          )
          file
        end

        # Releases a previously added hold. This does not clear the pending
        # deletion flag and does not shorten the remaining retention period.
        def release_hold(name: :admin, file: self.file)
          file ||= file!
          deletion_protection_registry.release_hold(file.storage_key, file.id, name)
          file
        end

        # Records an absolute retention deadline for the given file. An
        # earlier deadline never shortens an already recorded deadline.
        def retain_until!(time, file: self.file)
          file ||= file!
          deletion_protection_registry.set_retain_until(file.storage_key, file.id, time)
          file
        end

        # Records a retention duration for the given file, measured from the
        # configured clock.
        def retain_for!(duration, file: self.file)
          retain_until!(current_time + duration, file: file)
        end

        # Separates "no longer referenced by the application" from "allowed to
        # be physically deleted". The file is marked pending, and is only
        # deleted right away when no hold or retention deadline blocks it.
        #
        # Returns true when the file was physically deleted and false when the
        # deletion was deferred. Does nothing and returns false when no file
        # is given.
        def request_destroy(file = self.file, retain_for: configured_retention_period)
          return false if file.nil?

          deletion_protection_registry.mark_pending(
            file.storage_key,
            file.id,
            at: current_time,
            retain_for: retain_for,
          )

          return false if deletion_blocked?(file)

          file.delete
          true
        end

        # Cancels a pending deletion for the given file. Remaining holds and
        # the retention deadline are left untouched.
        def cancel_destroy(file = self.file)
          file ||= file!
          deletion_protection_registry.unmark_pending(file.storage_key, file.id)
          file
        end

        # Returns the reasons for which physical deletion of the given file is
        # currently blocked: active holds or an unexpired retention deadline.
        # Returns an empty array when nothing blocks deletion. A file also has
        # to be marked pending (e.g. by replacement or record destruction)
        # before #cleanup_deletions will physically delete it.
        def deletion_block_reasons(file = self.file, at: current_time)
          file ||= file!
          deletion_protection_registry.block_reasons(
            file.storage_key, file.id, at: at
          )
        end

        # Whether any hold or retention deadline currently blocks the physical
        # deletion of the given pending file.
        def deletion_blocked?(file = self.file, at: current_time)
          !deletion_block_reasons(file, at: at).empty?
        end

        # Returns the recorded deletion state for the given file.
        def deletion_protection_state(file = self.file)
          file ||= file!
          deletion_protection_registry.get(file.storage_key, file.id)
        end

        # Whether the given file has been marked for deletion but is still
        # protected by a hold or retention period.
        def pending_deletion?(file = self.file)
          state = deletion_protection_state(file)
          !!state && state[:pending]
        end

        # Synchronously physically deletes pending files from the given
        # storage whose holds have been released and whose retention deadline
        # has passed. Returns the deleted file ids. No background service is
        # required; call this from a rake task, a cron job or an admin action.
        def cleanup_deletions(storage_key: store_key, at: current_time)
          deletion_protection_registry.cleanup(storage_key, at: at) do |id|
            uploaded_file(
              "id" => id,
              "storage" => storage_key.to_s,
              "metadata" => {},
            ).delete
          end
        end

        # Runs #cleanup_deletions for every storage registered on the
        # uploader. Returns the deleted file ids.
        def cleanup_all_deletions(at: current_time)
          shrine_class.storages.keys.flat_map do |storage_key|
            cleanup_deletions(storage_key: storage_key, at: at)
          end
        end

        # Replacement and record destruction both end up here, so old files
        # go through the same "mark pending, then delete if allowed" rules.
        # Temporary files are deleted immediately, as they are not subject to
        # the permanent-storage retention rules.
        def destroy
          return if file.nil?
          return super if cached?(file)

          request_destroy
        end

        # The core guard checks against the (already replaced) current file.
        # When an old attachment is destroyed the old file is still attached
        # to the previous attacher, so defer to the actual #destroy decision.
        def destroy?
          return true if file && cached?(file)
          super
        end

        private

        def deletion_protection_registry
          shrine_class.deletion_protection_registry
        end

        def current_time
          shrine_class.opts[:deletion_protection][:clock].call
        end

        def configured_retention_period
          shrine_class.opts[:deletion_protection][:retention_period]
        end
      end
    end

    register_plugin(:deletion_protection, DeletionProtection)
  end
end
