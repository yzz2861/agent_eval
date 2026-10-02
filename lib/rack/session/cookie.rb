# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.
# Copyright, 2022, by Jeremy Evans.
# Copyright, 2022, by Jon Dufresne.

require 'openssl'
require 'zlib'
require 'json'
require 'base64'
require 'delegate'

require 'rack/constants'
require 'rack/utils'

require_relative 'abstract/id'
require_relative 'encryptor'
require_relative 'constants'

module Rack

  module Session

    # Rack::Session::Cookie provides simple cookie based session management.
    # By default, the session is a Ruby Hash that is serialized and encoded as
    # a cookie set to :key (default: rack.session).
    #
    # This middleware accepts a :secrets option which enables encryption of
    # session cookies. This option should be one or more random "secret keys"
    # that are each at least 64 bytes in length. Multiple secret keys can be
    # supplied in an Array, which is useful when rotating secrets.
    #
    # Several options are also accepted that are passed to Rack::Session::Encryptor.
    # These options include:
    # * :serialize_json
    #     Use JSON for message serialization instead of Marshal. This can be
    #     viewed as a security enhancement.
    # * :gzip_over
    #     For message data over this many bytes, compress it with the deflate
    #     algorithm.
    # * :audience
    #     An explicit identifier of the application this session cookie belongs
    #     to, such as its mount path (e.g. "/admin"). The audience participates
    #     in the authenticated encryption of the cookie, so a cookie issued for
    #     one audience can never be replayed against another audience, even when
    #     the same :secrets are shared. It is recommended to set this whenever
    #     multiple applications share a secret or issue cookies under the same
    #     cookie name.
    # * :legacy_cookies_until
    #     Optional Time. Cookies issued before the :audience option was
    #     introduced are not bound to an audience. Supplying a future Time here
    #     explicitly and temporarily allows such legacy cookies to be accepted
    #     and immediately re-issued in the new, audience-bound format. After
    #     the given Time, legacy cookies are rejected unconditionally.
    #
# Refer to Rack::Session::Encryptor for more details on these options.
    #
    # Prior to version TODO, the session hash was stored as base64 encoded
    # marshalled data. When a :secret option was supplied, the integrity of the
    # encoded data was protected with HMAC-SHA1. This functionality is still
    # supported using a set of a legacy options.
    #
    # Lastly, a :coder option is also accepted. When used, both encryption and
    # the legacy HMAC will be skipped. This option could create security issues
    # in your application!
    #
    # Example:
    #
    #   use Rack::Session::Cookie, {
    #     key: 'rack.session',
    #     domain: 'foo.com',
    #     path: '/',
    #     expire_after: 2592000,
    #     secrets: 'a randomly generated, raw binary string 64 bytes in size',
    #   }
    #
    # Example using legacy HMAC options:
    #
    #   Rack::Session:Cookie.new(application, {
    #     # The secret used for legacy HMAC cookies, this enables the functionality
    #     legacy_hmac_secret: 'legacy secret',
    #     # legacy_hmac_coder will default to Rack::Session::Cookie::Base64::Marshal
    #     legacy_hmac_coder: Rack::Session::Cookie::Identity.new,
    #     # legacy_hmac will default to OpenSSL::Digest::SHA1
    #     legacy_hmac: OpenSSL::Digest::SHA256
    #   })
    #
    # Example of a cookie with no encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Rack::Session::Cookie::Identity.new
    #   })
    #
    # Example of a cookie with custom encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Class.new {
    #       def encode(str); str.reverse; end
    #       def decode(str); str.reverse; end
    #     }.new
    #   })
    #

    class Cookie < Abstract::PersistedSecure
      # Encode session cookies as Base64
      class Base64
        def encode(str)
          ::Base64.strict_encode64(str)
        end

        def decode(str)
          ::Base64.decode64(str)
        end

        # Encode session cookies as Marshaled Base64 data
        class Marshal < Base64
          def encode(str)
            super(::Marshal.dump(str))
          end

          def decode(str)
            return unless str
            ::Marshal.load(super(str)) rescue nil
          end
        end

        # N.B. Unlike other encoding methods, the contained objects must be a
        # valid JSON composite type, either a Hash or an Array.
        class JSON < Base64
          def encode(obj)
            super(::JSON.dump(obj))
          end

          def decode(str)
            return unless str
            ::JSON.parse(super(str)) rescue nil
          end
        end

        class ZipJSON < Base64
          def encode(obj)
            super(Zlib::Deflate.deflate(::JSON.dump(obj)))
          end

          def decode(str)
            return unless str
            ::JSON.parse(Zlib::Inflate.inflate(super(str)))
          rescue
            nil
          end
        end
      end

      # Use no encoding for session cookies
      class Identity
        def encode(str); str; end
        def decode(str); str; end
      end

      class Marshal
        def encode(str)
          ::Marshal.dump(str)
        end

        def decode(str)
          ::Marshal.load(str) if str
        end
      end

      # The separator is a US (unit separator) control character that cannot
      # appear in a cookie name and is extremely unlikely to appear in an
      # audience identifier, which avoids ambiguity between the two parts.
      AUDIENCE_SEPARATOR = "\x1f".freeze

      attr_reader :coder, :encryptors, :audience, :legacy_cookies_until

      def initialize(app, options = {})
        # support both :secrets and :secret for backwards compatibility
        secrets = [*(options[:secrets] || options[:secret])]

        @audience = options[:audience]

        if @audience && !@audience.is_a?(String)
          raise ArgumentError, ":audience must be a String, got #{@audience.class}"
        end

        @legacy_cookies_until = options[:legacy_cookies_until]

        if @legacy_cookies_until && !@legacy_cookies_until.is_a?(Time)
          raise ArgumentError, ":legacy_cookies_until must be a Time"
        end

        # The default cookie name is applied by Persisted#initialize (called
        # below), so resolve it here for purpose construction.
        cookie_key = options[:key] || RACK_SESSION

        encryptor_opts = {
          purpose: cookie_purpose(cookie_key),
          serialize_json: options[:serialize_json]
        }

        # For each secret, create an Encryptor. We iterate this Array at
        # decryption time to achieve key rotation.
        @encryptors = secrets.map do |secret|
          Rack::Session::Encryptor.new secret, encryptor_opts
        end

        # During the explicit, time-limited migration window, keep a separate
        # set of encryptors that verify audience-less legacy cookies. These
        # cookies were signed/encrypted with only the cookie name as their
        # purpose, and therefore can only be accepted while the window is open.
        if @audience && accept_legacy_cookies?
          legacy_encryptor_opts = {
            purpose: cookie_key,
            serialize_json: options[:serialize_json]
          }

          @legacy_encryptors = secrets.map do |secret|
            Rack::Session::Encryptor.new secret, legacy_encryptor_opts
          end
        else
          @legacy_encryptors = []
        end

        # If a legacy HMAC secret is present, initialize those features.
        # Fallback to :secret for backwards compatibility.
        if options.has_key?(:legacy_hmac_secret) || options.has_key?(:secret)
          @legacy_hmac = options.fetch(:legacy_hmac, 'SHA1')

          @legacy_hmac_secret = options[:legacy_hmac_secret] || options[:secret]
          @legacy_hmac_coder  = options.fetch(:legacy_hmac_coder, Base64::Marshal.new)
        else
          @legacy_hmac = false
        end

        warn <<-MSG unless secure?(options)
        SECURITY WARNING: No secret option provided to Rack::Session::Cookie.
        This poses a security threat. It is strongly recommended that you
        provide a secret to prevent exploits that may be possible from crafted
        cookies. This will not be supported in future versions of Rack, and
        future versions will even invalidate your existing user cookies.

        Called from: #{caller[0]}.
        MSG

        # Potential danger ahead! Marshal without verification and/or
        # encryption could present a major security issue.
        @coder = options[:coder] ||= Base64::Marshal.new

        super(app, options.merge!(cookie_only: true))
      end

      private

      def find_session(req, sid)
        data = unpacked_cookie_data(req)
        data = persistent_session_id!(data)
        [data["session_id"], data]
      end

      def extract_session_id(request)
        unpacked_cookie_data(request)&.[]("session_id")
      end

      def unpacked_cookie_data(request)
        request.fetch_header(RACK_SESSION_UNPACKED_COOKIE_DATA) do |k|
          cookies = cookie_values(request)

          valid_data = nil

          # A browser may send more than one cookie with the same name (e.g.
          # cookies scoped to different paths or domains). We must never choose
          # one based on its position in the header, since an attacker could
          # put an arbitrary value first. Instead, authenticate every value
          # and apply a deterministic rule: if exactly one distinct value is
          # valid, use it; if more than one distinct value is valid, the input
          # is ambiguous and must be rejected.
          cookies.uniq.each do |cookie_data|
            session_data = unpack_cookie(request, cookie_data)
            next unless session_data

            if valid_data
              # Multiple distinct values authenticate successfully. Refuse to
              # guess which one belongs to this application.
              request.get_header(Rack::RACK_ERRORS).puts(
                "Session cookie error: multiple valid cookies with the same name (#{@key.inspect}) were sent; ignoring all of them"
              )
              valid_data = nil
              break
            end

            valid_data = session_data
          end

          request.set_header(k, valid_data || {})
        end
      end

      # Extract every cookie value sent for the configured cookie name. Unlike
      # Request#cookies, this keeps duplicate names instead of keeping only the
      # first one. Parsing matches Rack::Utils.parse_cookies_header.
      def cookie_values(request)
        header = request.get_header(Rack::HTTP_COOKIE)

        return [] unless header

        values = []

        header.split(/; */n).each do |cookie|
          next if cookie.empty?

          name, value = cookie.split('=', 2)
          next unless name == @key

          values << begin
            Rack::Utils.unescape(value)
          rescue ArgumentError
            value
          end
        end

        values
      end

      # Authenticate and decode a single cookie value. Returns the session
      # Hash on success or nil when the value does not authenticate for this
      # application.
      def unpack_cookie(request, cookie_data)
        session_data = decrypt_with(request, cookie_data, encryptors)

        # During the migration window, also accept audience-less legacy cookies.
        if !session_data && accept_legacy_cookies?
          session_data = decrypt_with(request, cookie_data, @legacy_encryptors)
        end

        # If session decryption fails but there is a legacy HMAC secret
        # defined, attempt legacy HMAC verification.
        if !session_data && @legacy_hmac_secret
          # Parse and verify legacy HMAC session cookie
          session_data, _, digest = cookie_data.rpartition('--')
          session_data = nil unless legacy_digest_match?(session_data, digest)

          # Decode using legacy HMAC decoder
          session_data = @legacy_hmac_coder.decode(session_data)

        elsif !session_data && encryptors.empty? && coder
          # Use the coder option, which has the potential to be very unsafe.
          # This path is only reached when no encryptors (secrets:) are configured;
          # if encryptors are present but decryption failed, the cookie is rejected.
          session_data = coder.decode(cookie_data)
        end

        session_data
      end

      def decrypt_with(request, cookie_data, cookie_encryptors)
        session_data = nil
        logged_errors = {}

        cookie_encryptors.each do |encryptor|
          begin
            session_data = encryptor.decrypt(cookie_data)
            break
          rescue Rack::Session::Encryptor::Error => error
            # Avoid logging the same failure once per key-rotation encryptor.
            unless logged_errors[error.message]
              request.env[Rack::RACK_ERRORS].puts "Session cookie encryptor error: #{error.message}"
              logged_errors[error.message] = true
            end

            next
          end
        end

        session_data
      end

      def accept_legacy_cookies?
        legacy_cookies_until && Time.now < legacy_cookies_until
      end

      # The purpose binds the authenticated cookie to the cookie name and,
      # when configured, to the explicit application audience. A cookie issued
      # by another application under the same name but a different audience
      # fails verification and is rejected even when secrets are shared.
      def cookie_purpose(key)
        return key unless audience

        "#{key}#{AUDIENCE_SEPARATOR}#{audience}"
      end

      def persistent_session_id!(data, sid = nil)
        data ||= {}
        data["session_id"] ||= sid || generate_sid
        data
      end

      class SessionId < DelegateClass(Session::SessionId)
        attr_reader :cookie_value

        def initialize(session_id, cookie_value)
          super(session_id)
          @cookie_value = cookie_value
        end
      end

      def write_session(req, session_id, session, options)
        session = session.merge("session_id" => session_id)
        session_data = encode_session_data(session)

        if session_data.size > (4096 - @key.size)
          req.get_header(RACK_ERRORS).puts("Warning! Rack::Session::Cookie data size exceeds 4K.")
          nil
        else
          SessionId.new(session_id, session_data)
        end
      end

      def delete_session(req, session_id, options)
        # Nothing to do here, data is in the client
        generate_sid unless options[:drop]
      end

      def legacy_digest_match?(data, digest)
        return false unless data && digest

        Rack::Utils.secure_compare(digest, legacy_generate_hmac(data))
      end

      def legacy_generate_hmac(data)
        OpenSSL::HMAC.hexdigest(@legacy_hmac, @legacy_hmac_secret, data)
      end

      def encode_session_data(session)
        if encryptors.empty?
          coder.encode(session)
        else
          encryptors.first.encrypt(session)
        end
      end

      # Were consider "secure" if:
      # * Encrypted cookies are enabled and one or more encryptor is
      #   initialized
      # * The legacy HMAC option is enabled
      # * Customer :coder is used, with :let_coder_handle_secure_encoding
      #   set to true
      def secure?(options)
        !@encryptors.empty? ||
          @legacy_hmac ||
          (options[:coder] && options[:let_coder_handle_secure_encoding])
      end
    end
  end
end
