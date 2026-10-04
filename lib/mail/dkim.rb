# encoding: utf-8
# frozen_string_literal: true

require 'openssl'

module Mail
  # = DKIM signing (RFC 6376)
  #
  # Generates a DKIM-Signature header field for a Mail::Message using the
  # rsa-sha256 algorithm with either simple or relaxed header and body
  # canonicalization.
  #
  # The application supplies the signing domain, selector and private key;
  # the corresponding public key is expected to be published in DNS at
  # <selector>._domainkey.<domain>.
  #
  #   mail = Mail.new do
  #     from    "alice@example.com"
  #     to      "bob@example.net"
  #     subject "hello"
  #     body    "signed, sealed, delivered"
  #   end
  #   mail.dkim_sign(domain: "example.com", selector: "s1", private_key: key)
  #   mail.encoded # => includes a DKIM-Signature header
  #
  # Signing finalizes the message: the transfer encoding is negotiated and
  # required headers (Date, Message-ID, ...) are added before any bytes are
  # hashed, so subsequent calls to #encoded or #to_s do not modify the
  # signed bytes.
  module Dkim
    CRLF = "\r\n".freeze

    # Headers signed by default, in the order they appear in the h= tag.
    # Follows the SHOULD-sign list from RFC 6376 section 5.4.1.
    DEFAULT_SIGNED_HEADERS = %w[
      from sender reply-to to cc subject date message-id
      mime-version content-type content-transfer-encoding
      content-id content-description in-reply-to references
    ].freeze

    CANONICALIZATIONS = %i[simple relaxed].freeze

    # Lines are folded to stay within this many columns.
    FOLD_AT = 72

    module_function

    # Signs +message+ in place and returns it.
    #
    # Required options:
    # * :domain   - the SDID, published in DNS (d= tag)
    # * :selector - the selector used to look up the public key (s= tag)
    # * :private_key - an OpenSSL::PKey::RSA or a PEM-encoded RSA private key
    #
    # Optional:
    # * :canonicalization - :simple or :relaxed, sets both header and body
    #   canonicalization (default: :relaxed)
    # * :header_canonicalization / :body_canonicalization - override either
    #   side of :canonicalization
    # * :headers - array of header names to sign, in h= order. A name may
    #   be repeated to cover multiple instances of a repeated header field
    #   (instances are selected bottom-most first, per RFC 6376 5.4.2) or
    #   to oversign a name so no further instance can be added. Defaults to
    #   DEFAULT_SIGNED_HEADERS limited to headers present in the message.
    # * :time - signature timestamp (t= tag), Time or Integer
    # * :identity - the AUID (i= tag); omitted unless given
    def sign(message, options = {})
      domain      = option(options, :domain)
      selector    = option(options, :selector)
      private_key = option(options, :private_key)

      header_canon, body_canon = canonicalizations(options)

      # Determine the final transfer encoding and add required headers
      # before hashing so later output cannot change the signed bytes.
      message.ready_to_send!

      body = message.body.encoded(message.content_transfer_encoding)
      body_hash = base64(::OpenSSL::Digest::SHA256.digest(canonicalize_body(body, body_canon)))

      signed = select_signed_headers(message, options[:headers])
      h_tag = signed.map { |name, _field| name }.join(":")

      dkim_value = [
        "v=1",
        "a=rsa-sha256",
        "c=#{header_canon}/#{body_canon}",
        "d=#{domain}",
        "s=#{selector}",
        ("i=#{options[:identity]}" if options[:identity]),
        "t=#{(options[:time] || Time.now).to_i}",
        "h=#{h_tag}",
        "bh=#{body_hash}",
        "b="
      ].compact.join("; ")

      # The b= value stays empty while hashing; it is appended afterwards.
      unsigned_header = fold_header("DKIM-Signature: #{dkim_value}")

      hash_input = signed.select { |_name, field| field }.map { |_name, field|
        canonicalize_header(field.encoded, header_canon)
      }.join
      hash_input << canonicalize_header("#{unsigned_header}#{CRLF}", header_canon)

      key = private_key.is_a?(String) ? ::OpenSSL::PKey::RSA.new(private_key) : private_key
      signature = key.sign(::OpenSSL::Digest::SHA256.new, hash_input)

      message.header.fields << build_field(append_signature(unsigned_header, base64(signature)))
      message
    end

    # Canonicalizes a header field given in its transmitted form
    # ("Name: value\r\n", possibly folded) per RFC 6376 3.4.1/3.4.2.
    def canonicalize_header(encoded_field, method)
      case method
      when :simple
        encoded_field
      when :relaxed
        name, value = encoded_field.split(":", 2)
        value = value.sub(/\r\n\z/, "")
        value = value.gsub(/\r\n(?=[ \t])/, "")
        value = value.gsub(/[ \t]+/, " ")
        value = value.sub(/\A /, "").sub(/ \z/, "")
        "#{name.downcase}:#{value}#{CRLF}"
      else
        raise ArgumentError, "unknown canonicalization: #{method.inspect}"
      end
    end

    # Canonicalizes the message body per RFC 6376 3.4.3/3.4.4.
    def canonicalize_body(body, method)
      case method
      when :simple
        body = body.sub(/(\r\n)*\z/, "")
        body.empty? ? "" : "#{body}#{CRLF}"
      when :relaxed
        lines = body.split("\r\n", -1)
        lines.pop if lines.last == ""
        lines = lines.map { |line| line.gsub(/[ \t]+/, " ").sub(/ \z/, "") }
        lines.pop while lines.last == ""
        lines.empty? ? "" : "#{lines.join(CRLF)}#{CRLF}"
      else
        raise ArgumentError, "unknown canonicalization: #{method.inspect}"
      end
    end

    class << self
      private

      # Strict RFC 4648 base64 without pulling in the base64 library.
      def base64(data)
        [data].pack("m0")
      end

      def option(options, name)
        options.fetch(name) { raise ArgumentError, "missing required option: #{name.inspect}" }
      end

      def canonicalizations(options)
        both = options[:canonicalization]
        header = (options[:header_canonicalization] || both || :relaxed).to_sym
        body   = (options[:body_canonicalization]   || both || :relaxed).to_sym
        [header, body].each do |method|
          unless CANONICALIZATIONS.include?(method)
            raise ArgumentError, "unknown canonicalization: #{method.inspect} (expected :simple or :relaxed)"
          end
        end
        [header, body]
      end

      # Pairs each header name to sign with the bottom-most not-yet-selected
      # instance of that field, as a verifier would (RFC 6376 5.4.2). Names
      # without a matching instance stay in the h= list with a nil field so
      # they are oversigned and hash nothing.
      def select_signed_headers(message, headers_option)
        fields = message.header.fields
        names =
          if headers_option
            headers_option.map { |name| name.to_s.downcase }
          else
            present = fields.map { |field| field.name.to_s.downcase }
            DEFAULT_SIGNED_HEADERS.select { |name| present.include?(name) }
          end

        used = []
        names.map do |name|
          field = fields.each_with_index.reverse_each.find { |candidate, index|
            !used.include?(index) && candidate.name.to_s.casecmp(name).zero?
          }
          if field
            used << field[1]
            [name, field[0]]
          else
            [name, nil]
          end
        end
      end

      # Folds a header field so lines stay within FOLD_AT columns, breaking
      # at "; " tag boundaries or, inside the h= list, after a ":". A tag
      # with no break point is left on its own long line.
      def fold_header(header)
        lines = []
        while header.length > FOLD_AT
          if (index = header.rindex("; ", FOLD_AT))
            lines << header[0..index]
            header = " #{header[(index + 2)..-1]}"
          elsif (index = header.rindex(":", FOLD_AT - 1))
            lines << header[0..index]
            header = " #{header[(index + 1)..-1]}"
          else
            break
          end
        end
        lines << header
        lines.join(CRLF)
      end

      # Appends the base64 signature to the folded header whose b= tag is
      # empty and last, folding the value with CRLF + WSP continuations.
      def append_signature(folded_header, signature)
        header = folded_header.dup
        until signature.empty?
          line_start = header.rindex(CRLF) ? header.rindex(CRLF) + 2 : 0
          room = FOLD_AT - (header.length - line_start)
          if room < 1
            header << CRLF << " "
            room = FOLD_AT - 1
          end
          header << signature.slice!(0, room)
        end
        header
      end

      def build_field(folded_header)
        name, value = folded_header.split(":", 2)
        field = Mail::Field.new(name)
        field.field = Mail::DkimField.new(value.sub(/\A /, ""))
        field
      end
    end
  end
end
