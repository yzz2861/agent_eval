# encoding: utf-8
# frozen_string_literal: true
require 'openssl'
require 'digest'
require 'mail/fields/dkim_signature_field'

module Mail
  # = DKIM signing (RFC 6376)
  #
  # Signs a Mail::Message with a DKIM-Signature header field using
  # rsa-sha256. Both "simple" and "relaxed" canonicalization are
  # supported, independently, for the header and the body.
  #
  # The application supplies the signing domain, the selector and the
  # private key:
  #
  #   mail.sign_with_dkim(
  #     :domain      => 'example.com',
  #     :selector    => 'mail',
  #     :private_key => OpenSSL::PKey::RSA.new(File.read('mail.private'))
  #   )
  #
  # The transfer encoding is finalized (via Message#ready_to_send!)
  # before anything is hashed, and the signature is computed over the
  # exact bytes that Message#encoded will emit afterwards, so normal
  # output of the message can no longer change the signed bytes.
  module Dkim
    CRLF = "\r\n".freeze

    # Header fields that are signed by default when present in the
    # message. Every occurrence of a repeated field is signed.
    DEFAULT_HEADERS = %w[
      from sender reply-to to cc bcc subject date message-id
      in-reply-to references keywords comments
      mime-version content-type content-transfer-encoding
      content-description content-id content-location
    ].freeze

    HEADER_LINE_LIMIT = 78
    SIGNATURE_CHUNK_LENGTH = 72

    module_function

    # Signs +message+ in place, prepending a DKIM-Signature header field.
    #
    # Options:
    # [:domain]            Signing domain (the d= tag). Required.
    # [:selector]          Selector (the s= tag). Required.
    # [:private_key]       An OpenSSL::PKey::RSA, or a PEM encoded private
    #                      key as a String. Required.
    # [:canonicalization]  "simple" or "relaxed" for header and body,
    #                      given as "header/body". Defaults to
    #                      "relaxed/relaxed".
    # [:headers]           Header field names to sign, in order. Repeat a
    #                      name to cover repeated fields. Pass :all to
    #                      sign every header field present. Defaults to
    #                      DEFAULT_HEADERS.
    # [:time]              Signature timestamp (the t= tag). Defaults to
    #                      the current time.
    # [:identity]          Agent or user identity (the i= tag). Optional.
    #
    # Returns the Mail::DkimSignatureField that was added.
    def sign(message, options = {})
      domain      = options.fetch(:domain)
      selector    = options.fetch(:selector)
      private_key = options.fetch(:private_key)
      time        = options[:time] || Time.now
      identity    = options[:identity]

      header_canon, body_canon = canonicalizations(options[:canonicalization])
      key = coerce_key(private_key)

      # Finalize the transfer encoding and add any missing required
      # fields before hashing, so that the bytes hashed here are the
      # same bytes Message#encoded will emit from now on.
      message.ready_to_send!

      body = message.body.encoded(message.content_transfer_encoding)
      bh = [Digest::SHA256.digest(canonicalize_body(body, body_canon))].pack('m0')

      fields = message.header.fields
      header_names = expand_header_names(fields, options[:headers])
      signed_fields = select_fields(fields, header_names)

      tags = [
        'v=1',
        'a=rsa-sha256',
        "c=#{header_canon}/#{body_canon}",
        "d=#{domain}",
        "s=#{selector}",
        ("i=#{identity}" if identity),
        "t=#{time.to_i}",
        "h=#{header_names.join(':')}",
        "bh=#{bh}",
        'b='
      ].compact.join('; ')

      # The DKIM-Signature header is hashed with an empty b= value. The
      # signature itself is appended afterwards as folding continuation
      # lines, so the hashed bytes stay a strict prefix of the emitted
      # header field.
      folded = fold_header_value(tags)

      hash_input = String.new
      signed_fields.each do |field|
        hash_input << canonicalize_header_field(field, header_canon)
      end
      hash_input << canonicalize_signature_header(folded, tags, header_canon)

      signature = key.sign(OpenSSL::Digest::SHA256.new, hash_input)
      encoded = folded + encode_signature(signature) + CRLF

      field = Mail::DkimSignatureField.new(encoded, tags)
      message.header.fields.unshift(field)
      field
    end

    # --- Canonicalization ---------------------------------------------

    # Returns [header_canonicalization, body_canonicalization].
    def canonicalizations(value)
      header_canon, body_canon = (value || 'relaxed/relaxed').to_s.downcase.split('/', 2)
      body_canon = header_canon if body_canon.nil? || body_canon.empty?
      unless %w[simple relaxed].include?(header_canon) && %w[simple relaxed].include?(body_canon)
        raise ArgumentError, "unknown DKIM canonicalization: #{value.inspect}"
      end
      [header_canon, body_canon]
    end

    # RFC 6376 3.4.3 / 3.4.4. Line endings are normalized to CRLF first,
    # which is how the body will be seen by verifiers after transport.
    def canonicalize_body(body, type)
      body = body.gsub(/\r\n|\r|\n/, CRLF)
      case type
      when 'simple'
        # Ignore all empty lines at the end of the body; a completely
        # empty body canonicalizes to a single CRLF.
        body.sub(/(\r\n)*\z/, '') + CRLF
      when 'relaxed'
        lines = body.split(CRLF, -1).map do |line|
          line.gsub(/[ \t]+\z/, '').gsub(/[ \t]+/, ' ')
        end
        lines.pop while lines.last == ''
        lines.empty? ? '' : lines.join(CRLF) + CRLF
      end
    end

    # Canonicalizes one header field as it will be emitted by
    # Header#encoded, including the terminating CRLF.
    def canonicalize_header_field(field, type)
      raw = field.encoded
      case type
      when 'simple'
        raw
      when 'relaxed'
        name, value = raw.split(':', 2)
        name = name.gsub(/[ \t]+\z/, '').downcase
        "#{name}:#{relaxed_header_value(value.sub(/#{CRLF}\z/, ''))}#{CRLF}"
      end
    end

    # Canonicalizes the DKIM-Signature header field itself with an empty
    # b= value. Unlike the fields named in h=, it is hashed without a
    # terminating CRLF.
    def canonicalize_signature_header(folded, tags, type)
      case type
      when 'simple'
        folded
      when 'relaxed'
        "dkim-signature:#{relaxed_header_value(tags)}"
      end
    end

    # RFC 6376 3.4.2 relaxed header value canonicalization: unfold,
    # compress WSP to a single SP, strip WSP at both ends.
    def relaxed_header_value(value)
      value.gsub(/\r\n(?=[ \t])/, '').gsub(/[ \t]+/, ' ').gsub(/\A[ \t]+|[ \t]+\z/, '')
    end

    # --- Header field selection ---------------------------------------

    # Expands the :headers option into the list of header field names
    # for the h= tag, in signing order.
    def expand_header_names(fields, headers)
      case headers
      when nil
        fields.map { |f| f.name.to_s.downcase }.select { |name| DEFAULT_HEADERS.include?(name) }
      when :all
        fields.map { |f| f.name.to_s.downcase } - %w[dkim-signature]
      else
        Array(headers).map { |name| name.to_s.downcase }
      end
    end

    # For each name in +header_names+, in order, selects the bottom-most
    # not yet selected occurrence, per RFC 6376 3.7.
    def select_fields(fields, header_names)
      names = fields.map { |f| f.name.to_s.downcase }
      used = {}
      header_names.each_with_object([]) do |name, selected|
        (names.length - 1).downto(0) do |i|
          if names[i] == name && !used[i]
            used[i] = true
            selected << fields[i]
            break
          end
        end
      end
    end

    # --- Output -------------------------------------------------------

    # Folds the DKIM tag list at "; " boundaries into a complete header
    # field (without the terminating CRLF and without the b= value).
    def fold_header_value(tags)
      lines = []
      current = String.new('DKIM-Signature: ')
      tags.split(/(?<=; )/).each do |token|
        if current.length + token.length > HEADER_LINE_LIMIT && current.strip != 'DKIM-Signature:'
          lines << current
          current = " #{token}"
        else
          current << token
        end
      end
      lines << current
      lines.join(CRLF)
    end

    # Emits the signature value on folding continuation lines, so the
    # hashed "empty b=" prefix of the header field is left untouched.
    def encode_signature(signature)
      [signature].pack('m0').scan(/.{1,#{SIGNATURE_CHUNK_LENGTH}}/).map { |chunk| "#{CRLF} #{chunk}" }.join
    end

    def coerce_key(private_key)
      case private_key
      when OpenSSL::PKey::RSA
        private_key
      when String
        OpenSSL::PKey.read(private_key)
      else
        raise ArgumentError, "private_key must be an OpenSSL::PKey::RSA or a PEM encoded String"
      end
    end
  end
end
