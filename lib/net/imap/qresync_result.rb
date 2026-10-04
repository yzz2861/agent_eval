# frozen_string_literal: true

module Net
  class IMAP < Protocol

    # Result of a SELECT or EXAMINE command sent with the +QRESYNC+
    # extension parameter.
    #
    # When a response is degraded (the server did not support QRESYNC), the
    # result includes only the regular mailbox selection data and empty
    # resynchronization sets.
    #
    # +vanished_earlier+ contains UIDs that were removed before the SELECT or
    # EXAMINE command was processed.  +vanished+ contains UIDs that were removed
    # while the command was being processed.  These values must never be merged.
    class QResyncResult < Data.define(
      :mailbox, :read_only, :response,
      :exists, :recent, :unseen,
      :uidnext, :uidvalidity, :highestmodseq, :nomodseq,
      :flags, :permanent_flags,
      :vanished_earlier, :vanished, :expunged, :fetches,
      :degraded
    )
      def initialize(mailbox:, response:, read_only:,
                     exists: nil, recent: nil, unseen: nil,
                     uidnext: nil, uidvalidity: nil, highestmodseq: nil,
                     nomodseq: false, flags: nil, permanent_flags: nil,
                     vanished_earlier: nil, vanished: nil, expunged: [],
                     fetches: [], degraded: false)
        super(
          mailbox: mailbox.to_str,
          response:,
          read_only: !!read_only,
          exists:, recent:, unseen:,
          uidnext:, uidvalidity:, highestmodseq:,
          nomodseq: !!nomodseq,
          flags: flags&.dup&.freeze,
          permanent_flags: permanent_flags&.dup&.freeze,
          vanished_earlier:, vanished:,
          expunged: expunged.dup.freeze,
          fetches: fetches.dup.freeze,
          degraded: !!degraded,
        )
      end

      # Returns +true+ for EXAMINE or another read-only selection.
      def read_only?; read_only end

      # Returns +true+ when QRESYNC was unavailable and the mailbox was opened
      # without quick resynchronization.
      def degraded?; degraded end

      # Returns +true+ when the mailbox was successfully opened with QRESYNC.
      def qresync?; !degraded end
    end
  end
end
