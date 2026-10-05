# frozen_string_literal: true
require 'mail/smtp_envelope'

module Mail
  # Raised when a message cannot be prepared for transport within the
  # SMTP extensions the receiving server supports.
  class TransportError < StandardError
  end

  # A prepared, sendable form of a Mail::Message plus the SMTP extensions
  # the envelope requires, built for a server with a known set of
  # capabilities (SMTPUTF8, 8BITMIME, BINARYMIME).
  #
  #   envelope = mail.prepare_for_transport(eight_bit_mime: true)
  #   smtp.sendmail(envelope.message, envelope.from, envelope.to)
  #
  # The capability constraint is pushed down through every nested MIME
  # part and applied to internationalized header fields and envelope
  # addresses, not just the top-level body:
  #
  # * Content that can be safely rewritten is assigned a suitable
  #   Content-Transfer-Encoding for the transport (e.g. quoted-printable
  #   or base64 on a 7bit-only transport, 8bit when 8BITMIME is
  #   available, binary when BINARYMIME is available).
  # * Signed (multipart/signed) subtrees cannot be rewritten without
  #   invalidating their signatures, so they are verified as-is; if any
  #   part of such a subtree is incompatible with the transport,
  #   Mail::TransportError is raised and preparation is refused.
  # * Non-ASCII envelope addresses require the SMTPUTF8 extension.
  #
  # The original message is never modified: preparation works on a deep
  # copy, so a failed preparation cannot leave the message half-modified.
  class TransportEnvelope < SmtpEnvelope
    SMTPUTF8       = 'SMTPUTF8'
    EIGHT_BIT_MIME = '8BITMIME'
    BINARY_MIME    = 'BINARYMIME'

    # The SMTP extension keywords, drawn from SMTPUTF8, EIGHT_BIT_MIME,
    # and BINARY_MIME, that the server must support to accept this
    # envelope.  Always a subset of the capabilities preparation was
    # allowed to use.
    attr_reader :requirements

    def initialize(mail, smtputf8: false, eight_bit_mime: false, binary_mime: false)
      @smtputf8 = !!smtputf8
      @transport_encoding =
        if binary_mime
          Encodings::Binary
        elsif eight_bit_mime
          Encodings::EightBit
        else
          Encodings::SevenBit
        end

      prepared = prepare(mail)

      self.from = prepared.smtp_envelope_from
      self.to = prepared.smtp_envelope_to
      self.message = prepared.encoded
      @requirements = compute_requirements(prepared).freeze
    end

    # True if the envelope requires the given SMTP extension, e.g.
    #   envelope.requires?('8BITMIME')
    def requires?(capability)
      @requirements.include?(capability.to_s.upcase)
    end

    def requires_smtputf8?
      requires?(SMTPUTF8)
    end

    def requires_8bitmime?
      requires?(EIGHT_BIT_MIME)
    end

    def requires_binarymime?
      requires?(BINARY_MIME)
    end

    private

    # Returns a prepared deep copy of the message, leaving the original
    # untouched whether preparation succeeds or fails.
    def prepare(mail)
      mail.dup.tap do |prepared|
        prepared.transport_encoding = @transport_encoding
        check_envelope_addresses(prepared)
        check_transportable(prepared)
      end
    end

    def check_envelope_addresses(mail)
      addresses = [mail.smtp_envelope_from, *mail.smtp_envelope_to].compact
      @needs_smtputf8 = addresses.any? { |address| !address.ascii_only? }

      if @needs_smtputf8 && !@smtputf8
        raise TransportError,
          'envelope address contains non-ASCII characters, but the server does not support SMTPUTF8'
      end
    end

    # Recursively verifies that the message can be transported within the
    # negotiated transport encoding.  Rewritable content is checked for a
    # negotiable Content-Transfer-Encoding; signed subtrees are verified
    # as-is since they cannot be rewritten.
    def check_transportable(message, frozen = false)
      frozen ||= signed?(message)
      check_frozen_headers(message) if frozen

      if message.multipart?
        message.parts.each { |part| check_transportable(part, frozen) }
      else
        check_leaf(message, frozen)
      end
    end

    def check_leaf(message, frozen)
      body = message.body
      source = Encodings.get_encoding(body.encoding)
      raw = body.raw_source.to_s

      unless source
        raise TransportError,
          "cannot transport part with unrecognized content-transfer-encoding #{body.encoding.inspect}"
      end

      if frozen
        unless @transport_encoding.can_transport?(source) && source.compatible_input?(raw)
          raise TransportError,
            "signed content (#{describe(message)}) is #{source} encoded and cannot be transported as #{@transport_encoding} without rewriting it"
        end
      else
        unless Encodings::TransferEncoding.negotiate(@transport_encoding, body.encoding, raw, message.allowed_encodings)
          raise TransportError,
            "cannot find a compatible content-transfer-encoding for #{describe(message)} on a #{@transport_encoding} transport"
        end
      end
    end

    # A signed subtree's header fields cannot be re-encoded without
    # invalidating the signature, so they must already be ASCII-safe.
    def check_frozen_headers(message)
      header = message.header
      values = [header.raw_source] + header.fields.map { |field| field.value }

      if values.compact.any? { |value| !value.to_s.ascii_only? }
        raise TransportError,
          'signed content contains non-ASCII header fields that cannot be transported without rewriting them'
      end
    end

    def signed?(message)
      message.main_type.to_s.downcase == 'multipart' &&
        message.sub_type.to_s.downcase == 'signed'
    end

    def describe(message)
      message.mime_type || 'content'
    end

    def compute_requirements(message)
      found = []
      found << SMTPUTF8 if @needs_smtputf8

      each_message(message) do |part|
        case part.content_transfer_encoding.to_s.downcase
        when '8bit'   then found << EIGHT_BIT_MIME
        when 'binary' then found << BINARY_MIME
        end
      end

      [SMTPUTF8, EIGHT_BIT_MIME, BINARY_MIME] & found
    end

    def each_message(message, &block)
      yield message
      message.parts.each { |part| each_message(part, &block) } if message.multipart?
    end
  end
end
