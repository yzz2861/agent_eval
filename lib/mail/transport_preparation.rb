# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Raised when a message cannot be made compatible with the SMTP extensions
  # advertised by the receiving server.
  class IncompatibleTransportError < StandardError
  end

  # The result of preparing a Mail::Message for delivery over a single SMTP
  # hop: the wire-encoded message, the envelope addresses and the SMTP
  # service extensions the receiving server must provide for them.
  class PreparedMessage
    # SMTP service extension keywords, as advertised in response to EHLO.
    EIGHTBITMIME = '8BITMIME'
    BINARYMIME  = 'BINARYMIME'
    SMTPUTF8    = 'SMTPUTF8'

    attr_reader :message, :from, :to, :required_extensions

    def initialize(message, from, to, required_extensions)
      @message = message
      @from = from
      @to = to
      @required_extensions = required_extensions
    end

    # The RFC 6152 body type value to pass on MAIL FROM.
    def body_type
      case
      when @required_extensions.include?(BINARYMIME)  then 'BINARYMIME'
      when @required_extensions.include?(EIGHTBITMIME) then '8BIT-MIME'
      else '7BIT'
      end
    end

    def smtputf8?
      @required_extensions.include?(SMTPUTF8)
    end

    def to_s
      @message
    end
  end
end

module Mail
  # Prepares a Mail::Message for one SMTP delivery once the client knows
  # which of 8BITMIME (RFC 6152), BINARYMIME (RFC 3030) and SMTPUTF8
  # (RFC 6531) the receiving server supports.
  #
  # Preparation never mutates the source message: all transfer encoding
  # decisions are made on a deep copy. Rewritable MIME entities are given
  # the most efficient content transfer encoding the server can carry;
  # entities that must not be transformed (the signed subtrees under
  # multipart/signed) are validated as-is and cause an
  # IncompatibleTransportError when the server cannot carry them.
  class TransportPreparation
    KEYWORD_ALIASES = {
      '8bitmime'     => PreparedMessage::EIGHTBITMIME,
      'eightbitmime' => PreparedMessage::EIGHTBITMIME,
      '8bit'         => PreparedMessage::EIGHTBITMIME,
      'binarymime'   => PreparedMessage::BINARYMIME,
      'binary'       => PreparedMessage::BINARYMIME,
      'smtputf8'     => PreparedMessage::SMTPUTF8,
      'utf8'         => PreparedMessage::SMTPUTF8
    }.freeze

    # RFC 6533 internationalized message media types require SMTPUTF8.
    GLOBAL_CONTENT_TYPES = %w[ message/global message/global-headers
                               application/global ].freeze

    # Header fields that carry SMTP routing addresses; UTF-8 in an addr-spec
    # here cannot be hidden in an RFC 2047 encoded-word.
    ADDRESS_FIELD_NAMES = %w[ from sender reply-to to cc bcc
                              resent-from resent-sender resent-to
                              resent-cc resent-bcc ].freeze

    def initialize(message, eightbitmime: false, binarymime: false, smtputf8: false)
      @message = message
      @supported = []
      @supported << PreparedMessage::BINARYMIME if binarymime
      # BINARYMIME is always negotiated together with 8BITMIME (RFC 3030).
      @supported << PreparedMessage::EIGHTBITMIME if eightbitmime || binarymime
      @supported << PreparedMessage::SMTPUTF8 if smtputf8
    end

    # As ::new, but also accepts a plain mapping of EHLO keywords, e.g.
    # <tt>{ '8BITMIME' => true, 'SMTPUTF8' => [] }</tt>.
    def self.prepare(message, capabilities = nil)
      options = normalize_options(capabilities)
      new(message, **options).prepare
    end

    def self.normalize_options(capabilities)
      result = { :eightbitmime => false, :binarymime => false, :smtputf8 => false }
      capabilities.each do |keyword, value|
        next if value == false || value.nil?
        case normalize_keyword(keyword)
        when PreparedMessage::BINARYMIME
          result[:binarymime] = true
          result[:eightbitmime] = true
        when PreparedMessage::EIGHTBITMIME then result[:eightbitmime] = true
        when PreparedMessage::SMTPUTF8    then result[:smtputf8] = true
        end
      end if capabilities
      result
    end

    def self.normalize_keyword(keyword)
      KEYWORD_ALIASES.fetch(keyword.to_s.downcase, keyword.to_s.upcase)
    end

    def prepare
      from = @message.smtp_envelope_from
      to = Array(@message.smtp_envelope_to)
      validate_envelope_addresses!(from, to)

      # Validate what preparation cannot change before copying anything, so
      # a rejected preparation never leaves a partially modified message.
      check_global_media_types! unless supports?(PreparedMessage::SMTPUTF8)
      check_internationalized_addresses! unless supports?(PreparedMessage::SMTPUTF8)

      prepared = @message.deep_dup
      prepared.prepare_for_transport!(@supported)
      encoded = prepared.encoded

      required = collect_required_extensions(prepared)
      required << PreparedMessage::SMTPUTF8 if needs_smtputf8?(from, to, prepared)
      required.uniq!
      verify_supported!(required)

      PreparedMessage.new(encoded, from, to, required)
    end

    private

      def validate_envelope_addresses!(from, to)
        if Utilities.blank?(from)
          raise ArgumentError, "SMTP From address may not be blank: #{from.inspect}"
        end
        if to.empty? || to.any? { |address| Utilities.blank?(address) }
          raise ArgumentError, "SMTP To address may not be blank: #{to.inspect}"
        end
      end

      def check_global_media_types!
        each_entity(@message) do |entity, inside_rfc822|
          next if inside_rfc822
          if global_media_type?(entity)
            raise IncompatibleTransportError,
                  "#{entity.mime_type} parts require the SMTPUTF8 SMTP extension"
          end
        end
      end

      def check_internationalized_addresses!
        each_entity(@message) do |entity, inside_rfc822|
          next if inside_rfc822
          ADDRESS_FIELD_NAMES.each do |name|
            field = entity.header[name] rescue nil
            next if field.nil? || !field.respond_to?(:addresses)
            field.addresses.each do |address|
              if address && !address.ascii_only?
                raise IncompatibleTransportError,
                      "internationalized address #{address.inspect} in #{name} header requires the SMTPUTF8 SMTP extension"
              end
            end
          end
        end
      end

      def needs_smtputf8?(from, to, prepared)
        return true if ([from] + to).any? { |address| address && !address.ascii_only? }

        each_entity(prepared) do |entity, inside_rfc822|
          next if inside_rfc822
          unless entity.header.encoded.ascii_only?
            return true
          end
        end
        false
      end

      def collect_required_extensions(prepared)
        required = []
        each_entity(prepared) do |entity, inside_rfc822|
          # Entities inside message/rfc822 are opaque wire content; the
          # attachment's own transfer encoding is what carries them.
          next if inside_rfc822
          next if entity.body.multipart?

          case entity.effective_content_transfer_encoding
          when 'binary'
            required << PreparedMessage::BINARYMIME
            required << PreparedMessage::EIGHTBITMIME
          when '8bit'
            required << PreparedMessage::EIGHTBITMIME
          end
        end
        required
      end

      def verify_supported!(required)
        unsupported = required - @supported
        unless unsupported.empty?
          raise IncompatibleTransportError,
                "message requires unsupported SMTP extension(s): #{unsupported.join(', ')}"
        end
      end

      def supports?(extension)
        @supported.include?(extension)
      end

      def global_media_type?(entity)
        media_type = entity.mime_type.to_s.split(';').first.to_s.downcase
        GLOBAL_CONTENT_TYPES.include?(media_type)
      end

      # Yields [entity, inside_message_rfc822?] for the message itself and
      # every MIME entity beneath it. Messages attached via message/rfc822
      # are decoded and traversed too, but flagged so callers treat their
      # internals as opaque wire content.
      def each_entity(entity, inside_rfc822 = false, &block)
        yield entity, inside_rfc822
        return unless entity.body.multipart?

        entity.parts.each do |part|
          if message_rfc822?(part)
            inner = Mail.new(part.body.decoded)
            yield part, inside_rfc822
            each_entity(inner, true, &block)
          else
            each_entity(part, inside_rfc822, &block)
          end
        end
      end

      def message_rfc822?(part)
        media_type = part.mime_type.to_s.split(';').first.to_s.downcase
        !part.body.multipart? && media_type == 'message/rfc822'
      end
  end
end
