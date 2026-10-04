# frozen_string_literal: true

require "monitor"

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/deletion_protection
    #
    # The +deletion_protection+ plugin separates "the application no longer
    # references this file" from "this file may be physically deleted".
    #
    # When an attached file is replaced or the attachment is destroyed, the
    # file is marked as *pending deletion* instead of being removed right
    # away. A file becomes eligible for physical deletion only once all of
    # the following hold:
    #
    #   * it has been marked as pending deletion (nothing references it),
    #   * it has no active explicit holds,
    #   * its retention period has expired.
    #
    # Releasing a hold never bypasses the remaining retention period, and
    # replacement of an attachment goes through the exact same rules.
    module DeletionProtection
      def self.configure(uploader, retention: nil, clock: nil, store: nil)
        uploader.opts[:deletion_protection] ||= {}
        uploader.opts[:deletion_protection][:retention] = retention unless retention.nil?
        uploader.opts[:deletion_protection][:clock]     = clock     unless clock.nil?
        uploader.opts[:deletion_protection][:store]     = store     unless store.nil?
      end

      # Default in-memory protection state. It is thread-safe and intended
      # for single-process setups and tests. Multi-process deployments can
      # supply their own store via the +:store+ option.
      class MemoryStore
        include MonitorMixin

        def initialize
          super()
          @records = {}
        end

        def fetch(key)
          synchronize { @records[key]&.dup }
        end

        def update(key)
          synchronize do
            record = @records[key] ||= { holds: {} }
            yield record
            record.dup
          end
        end

        def delete(key)
          synchronize do
            record = @records.delete(key)
            record&.dup
          end
        end

        def each_pending
          return enum_for(__method__) unless block_given?

          pending = synchronize do
            @records.select { |_, record| record[:pending] }
                    .map { |key, record| [key, record.dup] }
          end

          pending.each { |key, record| yield key, record }
        end
      end

      module AttacherClassMethods
        # Returns the object that persists deletion protection state.
        def deletion_protection_store
          shrine_class.opts[:deletion_protection][:store] ||= DeletionProtection::MemoryStore.new
        end

        # Returns the current time used by retention checks. Overridable via
        # the +:clock+ option so that boundary conditions can be tested.
        def deletion_protection_now
          clock = shrine_class.opts[:deletion_protection][:clock]
          clock ? clock.call : Time.now
        end

        # Calculates the retention deadline for a file. Returns +nil+ when
        # no retention is configured. A callable receives the uploaded file
        # and the attacher context.
        def retention_deadline_for(file, context = {})
          retention = shrine_class.opts[:deletion_protection][:retention]
          retention = retention.call(file, context) if retention.respond_to?(:call)
          return nil unless retention

          deletion_protection_now + retention
        end

        # Adds an explicit hold to a file. An optional +until:+ time turns
        # the hold into one that expires automatically.
        def hold_deletion(file, reason = :hold, until: nil)
          expires_at = binding.local_variable_get(:until)
          update_protection(file) do |record|
            record[:holds][reason] = { expires_at: expires_at }
          end
        end

        # Removes an explicit hold from a file.
        def release_deletion_hold(file, reason = :hold)
          update_protection(file) do |record|
            record[:holds].delete(reason)
          end
        end

        # Returns true if the file currently has at least one active hold.
        def deletion_held?(file, at: nil)
          active_holds(protection_record(file), at || deletion_protection_now).any?
        end

        # Marks a file as pending deletion and records the retention
        # deadline. Nothing is deleted at this point.
        def mark_pending_deletion(file, context = {})
          update_protection(file) do |record|
            record[:pending] = true
            record[:marked_pending_at] ||= deletion_protection_now
            deadline = retention_deadline_for(file, context)
            record[:retain_until] = deadline
          end
        end

        # Reverts the pending deletion state, e.g. when an attachment is
        # restored. Holds and a previously set retention deadline remain.
        def undo_pending_deletion(file)
          update_protection(file) do |record|
            record[:pending] = false
            record.delete(:marked_pending_at)
          end
        end

        # Returns true when the file is marked as pending deletion.
        def pending_deletion?(file)
          !!protection_record(file)&.dig(:pending)
        end

        # Returns a list of reasons why the file cannot be physically
        # deleted right now:
        #
        #   * +:not_pending+ - the application still references the file
        #   * +:hold+         - an explicit hold is active
        #   * +:retention+    - the retention period has not expired yet
        #
        # An empty array means physical deletion is allowed.
        def deletion_blockers(file, at: nil)
          now     = at || deletion_protection_now
          record  = protection_record(file)
          reasons = []

          reasons << :not_pending unless record&.dig(:pending)

          if (retain_until = record&.dig(:retain_until)) && retain_until > now
            reasons << :retention
          end

          unless active_holds(record, now).empty?
            reasons << :hold
          end

          reasons
        end

        # Returns true when there is no reason to keep the file.
        def deletable?(file, **options)
          deletion_blockers(file, **options).empty?
        end

        # Physically deletes every pending file whose holds are released and
        # whose retention period has expired. Returns the deleted uploaded
        # files. No background service is required; call this from a rake
        # task, a cron job, or an admin action.
        def cleanup_pending_deletions(at: nil)
          deleted = []

          deletion_protection_store.each_pending do |key, record|
            now = at || deletion_protection_now
            file = shrine_class.uploaded_file(
              "id"      => key[1],
              "storage" => key[0].to_s,
              "metadata" => record[:metadata] || {},
            )

            next unless deletable?(file, at: now)

            file.delete
            deletion_protection_store.delete(key)
            deleted << file
          end

          deleted
        end

        # Returns the raw protection record for a file.
        def protection_record(file)
          deletion_protection_store.fetch(protection_key(file))
        end
        
        # Key used to identify protection state for a file.
        def protection_key(file)
          [file.storage_key.to_s, file.id]
        end

        private

        def update_protection(file)
          deletion_protection_store.update(protection_key(file)) do |record|
            yield record
            prune_holds(record, deletion_protection_now)
            record[:metadata] = file.metadata
          end
        end

        def active_holds(record, now)
          return {} unless record

          prune_holds(record, now)
          record[:holds].reject { |_, hold| (expires_at = hold[:expires_at]) && expires_at <= now }
        end

        def prune_holds(record, now)
          return false unless record

          changed = record[:holds].reject! do |_, hold|
            (expires_at = hold[:expires_at]) && expires_at <= now
          end
          !!changed
        end
      end

      module AttacherMethods
        # Marks the current file as pending deletion. If holds are released
        # and the retention period has expired, the file is physically
        # deleted; otherwise it stays in storage until #cleanup or another
        # deletion attempt.
        def destroy
          return unless file

          # Cached files were never promoted to permanent storage, so they
          # retain the core behaviour of being deleted unconditionally.
          return super if cached?

          attached_file = file
          self.class.mark_pending_deletion(attached_file, context)

          if self.class.deletable?(attached_file)
            attached_file.delete
            self.class.deletion_protection_store.delete(self.class.protection_key(attached_file))
          end
        end

        # Adds an explicit hold on the currently attached file.
        def hold_deletion(reason = :hold, **options)
          self.class.hold_deletion(file!, reason, **options)
        end

        # Releases an explicit hold from the currently attached file.
        def release_deletion_hold(reason = :hold)
          self.class.release_deletion_hold(file!, reason)
        end

        # Returns true if the currently attached file has an active hold.
        def deletion_held?(**options)
          self.class.deletion_held?(file!, **options)
        end

        # Reverts pending deletion for the currently attached file.
        def undo_pending_deletion
          self.class.undo_pending_deletion(file!)
        end

        # Returns the reasons that currently block physical deletion.
        def deletion_blockers(**options)
          self.class.deletion_blockers(file!, **options)
        end
      end
    end

    register_plugin(:deletion_protection, DeletionProtection)
  end
end
