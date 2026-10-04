# frozen_string_literal: true

module Net
  class IMAP < Protocol

    # Net::IMAP::QResyncResult represents the structured result of selecting
    # a mailbox with the
    # {QRESYNC}[https://www.rfc-editor.org/rfc/rfc7162.html] extension
    # parameters, via Net::IMAP#select or Net::IMAP#examine with the
    # +qresync:+ keyword argument.
    #
    # It collects the server's +UIDVALIDITY+ and +HIGHESTMODSEQ+ response
    # codes, and separates the deletions reported while the mailbox was being
    # selected into <em>offline</em> deletions (<tt>VANISHED (EARLIER)</tt>,
    # which happened since the client's last synchronization) and
    # <em>online</em> deletions (+VANISHED+ without +EARLIER+, or +EXPUNGE+
    # when QRESYNC is not enabled).
    class QResyncResult < Data.define(
      :mailbox, :qresync, :uidvalidity, :highest_modseq,
      :vanished_earlier, :vanished, :expunged
    )

      # Returns a new QResyncResult object.
      #
      # * +vanished_earlier+ and +vanished+ will be converted by
      #   SequenceSet.[].
      # * +qresync+ will be converted to +true+ or +false+.
      def initialize(mailbox:, qresync:, uidvalidity:, highest_modseq:,
                     vanished_earlier:, vanished:, expunged:)
        mailbox          = -String(mailbox)
        qresync          = !!qresync
        uidvalidity      = uidvalidity   && Integer(uidvalidity)
        highest_modseq   = highest_modseq && Integer(highest_modseq)
        vanished_earlier = SequenceSet === vanished_earlier ? vanished_earlier
          : SequenceSet[vanished_earlier]
        vanished         = SequenceSet === vanished ? vanished
          : SequenceSet[vanished]
        expunged         = expunged.map { Integer(_1) }.freeze
        super
      end

      ##
      # :attr_reader: mailbox
      #
      # The name of the selected mailbox.

      ##
      # :attr_reader: qresync
      #
      # +true+ when the +QRESYNC+ select parameters were sent to and accepted
      # by the server.  +false+ when the server does not support +QRESYNC+ and
      # the caller chose to degrade to a plain select.
      #
      # When +false+, #vanished_earlier will be empty and deletions can only
      # be reported as #vanished or #expunged.

      # Returns +true+ when the +QRESYNC+ select parameters were used.
      #
      # Alias for #qresync.
      alias qresync? qresync

      ##
      # :attr_reader: uidvalidity
      #
      # The +UIDVALIDITY+ of the selected mailbox, as an Integer, or +nil+
      # when the server did not send a +UIDVALIDITY+ response code.

      ##
      # :attr_reader: highest_modseq
      #
      # The +HIGHESTMODSEQ+ of the selected mailbox, as an Integer, or +nil+
      # when the server sent +NOMODSEQ+ or no mod-sequence response code.

      # Returns +true+ when the mailbox does not support mod-sequences (the
      # server sent the +NOMODSEQ+ response code or no +HIGHESTMODSEQ+).
      def nomodseq? = highest_modseq.nil?

      ##
      # :attr_reader: vanished_earlier
      #
      # A SequenceSet of UIDs, merged from all <tt>VANISHED (EARLIER)</tt>
      # responses.  These messages were expunged <em>before</em> the mailbox
      # was selected, relative to the client's stored +UIDVALIDITY+ and
      # +HIGHESTMODSEQ+, and can be removed directly from the client's local
      # cache.
      #
      # This is empty when #qresync? is +false+.

      ##
      # :attr_reader: vanished
      #
      # A SequenceSet of UIDs, merged from all +VANISHED+ responses without
      # +EARLIER+.  These are <em>online</em> deletions, announced while the
      # mailbox was being selected.

      ##
      # :attr_reader: expunged
      #
      # An Array of message sequence numbers from +EXPUNGE+ responses
      # received while selecting.  +EXPUNGE+ is only sent when +QRESYNC+ (or
      # +UIDONLY+) has not been enabled; when #qresync? is +true+, online
      # deletions are reported by #vanished instead.

    end

  end
end
