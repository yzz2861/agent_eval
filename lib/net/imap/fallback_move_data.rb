# frozen_string_literal: true

module Net
  class IMAP < Protocol

    # FallbackMoveResult represents the state of a non-atomic fallback move
    # performed by Net::IMAP#uid_move_fallback.
    #
    # Because the fallback move is executed as separate +UID COPY+, +UID
    # STORE+, and +UID EXPUNGE+ commands, it cannot be atomic: a failure (or a
    # connection/state change) may leave the move partially completed.  Every
    # successful result or FallbackMoveIncomplete error carries a
    # FallbackMoveResult so the caller can determine exactly which stages have
    # already happened and avoid repeating them (e.g. copying messages a second
    # time).
    #
    #   result = imap.uid_move_fallback(uids, "Trash")
    #   result.completed?          #=> true
    #   result.stages              #=> [:copy, :store, :expunge]
    #   result.copy_uid            #=> Net::IMAP::CopyUIDData
    #   result.uid_mapping         #=> {3955=>3963, ...}
    #
    # If a later stage raises:
    #
    #   begin
    #     imap.uid_move_fallback(uids, "Trash")
    #   rescue Net::IMAP::FallbackMoveIncomplete => err
    #     err.result.stages          #=> e.g. [:copy]
    #     err.result.copy_uid        #=> the COPYUID response, never re-copy!
    #     err.result.uid_mapping     #=> source UID => destination UID
    #   end
    #
    # == Attributes
    #
    # destination:: the destination mailbox name
    # uids:: the source mailbox UIDs that were requested to be moved, as a
    #        SequenceSet
    # uidvalidity:: the source mailbox +UIDVALIDITY+ captured before the move
    # stages:: the ordered list of stages that have completed
    # copy_uid:: the CopyUIDData from the +COPYUID+ response code of the
    #            successful +UID COPY+ command, or +nil+
    # store:: the result of the successful +UID STORE+ command (an array of
    #         FetchData), or +nil+
    # expunged:: the result of the successful +UID EXPUNGE+ command, or +nil+
    class FallbackMoveResult < Data.define(
      :destination, :uids, :uidvalidity,
      :stages, :copy_uid, :store, :expunged
    )

      STAGES = %i[copy store expunge].freeze
      private_constant :STAGES
      STAGE_FIELDS =
        {copy: :copy_uid, store: :store, expunge: :expunged}.freeze
      private_constant :STAGE_FIELDS

      def initialize(destination:, uids:, uidvalidity:,
                     stages: [], copy_uid: nil, store: nil, expunged: nil)
        uids = SequenceSet[uids]
        super(
          destination: destination.to_str,
          uids: uids,
          uidvalidity: Integer(uidvalidity),
          stages: stages.dup.freeze,
          copy_uid: copy_uid,
          store: store,
          expunged: expunged,
        )
      end

      # Returns +true+ when all fallback stages have completed successfully.
      def completed?
        stages == STAGES || stages == [:move]
      end

      # Returns +true+ when the messages have been copied to #destination.
      def copied?
        stages.include?(:copy)
      end

      # Returns +true+ when the source messages have been flagged +\\Deleted+.
      def flagged?
        stages.include?(:store)
      end

      # Returns +true+ when the source messages have been expunged.
      def expunged?
        stages.include?(:expunge)
      end

      # Returns the CopyUIDData#uid_mapping of #copy_uid, or +nil+ when the
      # copy stage has not completed or the server did not send +COPYUID+.
      #
      # Maps each source UID to the UID assigned to it in #destination.
      def uid_mapping
        copy_uid&.uid_mapping
      end

      # Internal: returns a copy with +stage+ appended and +field+ assigned.
      def with_stage(stage, value = nil)
        field = STAGE_FIELDS.fetch(stage)
        attrs = {stages: stages + [stage], field => value}
        with(**attrs)
      end

    end

    # Superclass for errors raised by Net::IMAP#uid_move_fallback.
    class FallbackMoveError < Error

      # The FallbackMoveResult representing the state of the interrupted move.
      attr_reader :result

      def initialize(message, result: nil)
        @result = result
        super(message)
      end

    end

    # Raised by Net::IMAP#uid_move_fallback when one of the fallback commands
    # fails after an earlier stage has already completed.
    #
    # The move is _not_ atomic and the caller must inspect #result before
    # retrying.  In particular, when FallbackMoveResult#copied? is +true+, the
    # messages must not be copied again; use FallbackMoveResult#copy_uid or
    # FallbackMoveResult#uid_mapping to identify the copies, and resume the
    # remaining stages (flag and/or expunge) instead.
    class FallbackMoveIncomplete < FallbackMoveError
    end

    # Raised by Net::IMAP#uid_move_fallback when the source mailbox is no
    # longer selected (or its +UIDVALIDITY+ has changed) while the fallback
    # stages are in progress.
    #
    # When this is raised, the fallback stops immediately, without sending any
    # further commands.  The #result reports which stages had already
    # completed before the change was detected.
    class FallbackMailboxChanged < FallbackMoveError
    end

  end
end
