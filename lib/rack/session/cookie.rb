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
    # * :audience
    #     A String identifying the application that is allowed to consume the
    #     cookie, for example a mount path. The audience is cryptographically
    #     bound into the cookie's authenticated envelope, so two applications
    #     that share the same :secrets but use different audiences cannot
    #     accept each other's cookies.
    # * :serialize_json
    #     Use JSON for message serialization instead of Marshal. This can be
    #     viewed as a security enhancement.
    #
    # Refer to Rack::Session::Encryptor for more details on these options.
    #
    # Old format cookies (cookies emitted without an audience, including
    # legacy HMAC cookies) are not accepted merely because the audience is
    # configured. They are only accepted when :accept_legacy_cookies_until is
    # provided and the current time is still before that deadline. The option
    # accepts a Time (an absolute deadline) or a Numeric number of seconds
    # from middleware initialization. Once an old format cookie is accepted
    # it is transparently reissued in the audience-bound format on the next
    # response, so the window only has to cover the migration period.
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

      attr_reader :coder, :encryptors

      def initialize(app, options = {})
        # support both :secrets and :secret for backwards compatibility
        secrets = [*(options[:secrets] || options[:secret])]

        # Defaults (including :key) are applied by the superclass, so resolve
        # the effective cookie name here before building the encryptors.
        cookie_key = options.fetch(:key, RACK_SESSION)

        encryptor_opts = {
          purpose: cookie_key,
          audience: options[:audience],
          mode: options[:mode],
          serialize_json: options[:serialize_json]
        }

        # For each secret, create an Encryptor. We have iterate this Array at
        # decryption time to achieve key rotation.
        @encryptors = secrets.map do |secret|
          Rack::Session::Encryptor.new secret, encryptor_opts
        end

        # When an :audience is configured, every emitted cookie is bound to
        # that audience. Cookies emitted before the audience existed (or by
        # another audience) can only be accepted during an explicit, time
        # limited migration window.
        @audience = options[:audience]

        if @audience
          unless @audience.is_a?(String)
            raise ArgumentError, ':audience must be a String'
          end

          @accept_legacy_cookies_until =
            parse_legacy_cookie_deadline(options[:accept_legacy_cookies_until])

          # Additional encryptors without an audience, used only to verify
          # old format cookies while the migration window is open.
          @legacy_audience_encryptors = if accept_legacy_cookies?
            legacy_opts = encryptor_opts.merge(audience: nil)
            secrets.map { |secret| Rack::Session::Encryptor.new(secret, legacy_opts) }
          else
            []
          end
        else
          @accept_legacy_cookies_until = nil
          @legacy_audience_encryptors = []
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

      # :accept_legacy_cookies_until may be a Time/DateTime (an absolute
      # deadline) or a Numeric number of seconds from initialization.
      def parse_legacy_cookie_deadline(value)
        case value
        when nil
          nil
        when Numeric
          Time.now + value
        when Time
          value
        else
          if value.respond_to?(:to_time)
            value.to_time
          else
            raise ArgumentError, ':accept_legacy_cookies_until must be a Time or a Numeric number of seconds'
          end
        end
      end

      def accept_legacy_cookies?
        @audience &&
          @accept_legacy_cookies_until &&
          Time.now <= @accept_legacy_cookies_until
      end

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
          session_data =
            if @audience
              unpack_audience_cookie_data(request)
            else
              unpack_cookie_data(request, request.cookies[@key])
            end

          request.set_header(k, session_data || {})
        end
      end

      # Extracts every raw value sent for the session cookie name. Browsers
      # may send multiple cookies sharing a name (e.g. one scoped to each of
      # several mount paths); Rack itself keeps only the first occurrence, so
      # the raw Cookie header is parsed here without de-duplicating.
      def cookie_candidates(request)
        header = request.get_header(Rack::HTTP_COOKIE)
        return [] unless header

        header.split(/; */n).each_with_object([]) do |pair, values|
          next if pair.empty?

          name, value = pair.split('=', 2)
          next unless name == @key
          next if value.nil?

          values << begin
            Rack::Utils.unescape(value)
          rescue ArgumentError
            value
          end
        end
      end

      def try_encryptors(cookie_data, encryptors, request)
        encryptors.each do |encryptor|
          begin
            return encryptor.decrypt(cookie_data)
          rescue Rack::Session::Encryptor::Error => error
            request.env[Rack::RACK_ERRORS].puts "Session cookie encryptor error: #{error.message}"
          end
        end

        nil
      end

      def legacy_hmac_session_data(cookie_data)
        # In audience mode, legacy HMAC cookies are old format cookies and
        # are only accepted during an explicit, non-expired migration window.
        return if @audience && !accept_legacy_cookies?
        return unless @legacy_hmac_secret

        data, _, digest = cookie_data.rpartition('--')
        return unless legacy_digest_match?(data, digest)

        @legacy_hmac_coder.decode(data)
      end

      # Handles cookies for an audience-bound application.
      #
      # Every supplied value is authenticated independently. The request is
      # only accepted when exactly one distinct value authenticates to this
      # audience; two or more distinct valid values are rejected outright
      # rather than relying on cookie ordering. Old format values are
      # considered only while the explicit, time limited migration window is
      # open and are migrated to the new format on the next response.
      def unpack_audience_cookie_data(request)
        candidates = cookie_candidates(request)
        return if candidates.empty?

        # Authenticate every supplied value independently and keep the raw
        # values that succeed: duplicate identical bytes (the same cookie
        # sent more than once) collapse to one, while distinct valid values
        # make the request ambiguous.
        authenticated_current = {}
        candidates.uniq.each do |candidate|
          session_data = try_encryptors(candidate, encryptors, request)
          authenticated_current[candidate] = session_data if session_data
        end

        if authenticated_current.length > 1
          request.env[Rack::RACK_ERRORS].puts(
            "Session cookie rejected: multiple distinct valid cookies for #{@audience.inspect}"
          )
          return
        end

        if authenticated_current.length == 1
          authenticated_current.values.first
        elsif accept_legacy_cookies?
          migrate_legacy_cookie_data(request, candidates)
        end
      end

      def migrate_legacy_cookie_data(request, candidates)
        # A candidate qualifies as an old format value if it authenticates
        # without an audience (old encrypted cookie) or as a legacy HMAC
        # cookie. Duplicate identical bytes are harmless; distinct valid old
        # values are ambiguous and rejected.
        authenticated_legacy = {}
        candidates.uniq.each do |candidate|
          session_data =
            if @legacy_audience_encryptors.any?
              try_encryptors(candidate, @legacy_audience_encryptors, request)
            end

          session_data ||= legacy_hmac_session_data(candidate)
          authenticated_legacy[candidate] = session_data if session_data
        end

        if authenticated_legacy.length > 1
          request.env[Rack::RACK_ERRORS].puts(
            "Session cookie rejected: multiple distinct valid legacy cookies for #{@audience.inspect}"
          )
          return
        end

        return unless authenticated_legacy.length == 1

        # Mark the request so the session is re-emitted in the new,
        # audience-bound format even if the application does not modify it.
        request.set_header(RACK_SESSION_COOKIE_MIGRATED, true)

        authenticated_legacy.values.first
      end

      # Preserves the historical behaviour for applications that do not
      # configure an :audience.
      def unpack_cookie_data(request, cookie_data)
        return unless cookie_data

        session_data = try_encryptors(cookie_data, encryptors, request)

        # If session decryption fails but there is a legacy HMAC secret
        # defined, attempt legacy HMAC verification.
        if !session_data && @legacy_hmac_secret
          session_data = legacy_hmac_session_data(cookie_data)
        elsif !session_data && encryptors.empty? && coder
          # Use the coder option, which has the potential to be very unsafe.
          # This path is only reached when no encryptors (secrets:) are configured;
          # if encryptors are present but decryption failed, the cookie is rejected.
          session_data = coder.decode(cookie_data)
        end

        session_data
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

      def set_cookie(request, response, cookie)
        # A session read from an old format cookie is always rewritten to
        # the new audience-bound format on the next response, even if the
        # application itself did not touch the session.
        if request.get_header(RACK_SESSION_COOKIE_MIGRATED)
          response.set_cookie(@key, cookie)
        else
          super
        end
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
