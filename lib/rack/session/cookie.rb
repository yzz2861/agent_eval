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
      CREATED_AT_KEY = "__rack_session.created_at"
      LAST_ACCESSED_AT_KEY = "__rack_session.last_accessed_at"

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

        encryptor_opts = {
          purpose: options[:key], serialize_json: options[:serialize_json]
        }

        # For each secret, create an Encryptor. We have iterate this Array at
        # decryption time to achieve key rotation.
        @encryptors = secrets.map do |secret|
          Rack::Session::Encryptor.new secret, encryptor_opts
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
        @clock_high_water = Hash.new
      end

      private

      def find_session(req, sid)
        data = unpacked_cookie_data(req)
        unless data.is_a?(::Hash) && fresh_session?(req, data)
          forget_cookie_clock(req, data["session_id"]) if data.is_a?(::Hash)
          data = {}
          req.set_header(RACK_SESSION_UNPACKED_COOKIE_DATA, data)
        end
        remember_cookie_clock(req, data["session_id"], now) if data.is_a?(::Hash) && data["session_id"]
        data = persistent_session_id!(data)
        [data["session_id"], application_session_data(data)]
      end

      def extract_session_id(request)
        unpacked_cookie_data(request)&.[]("session_id")
      end

      def unpacked_cookie_data(request)
        request.fetch_header(RACK_SESSION_UNPACKED_COOKIE_DATA) do |k|
          if cookie_data = request.cookies[@key]
            session_data = nil

            # Try to decrypt the session data with our encryptors
            encryptors.each do |encryptor|
              begin
                session_data = encryptor.decrypt(cookie_data)
                request.set_header(RACK_SESSION_VERIFIED_COOKIE_DATA, true) if session_data
                break
              rescue Rack::Session::Encryptor::Error => error
                request.env[Rack::RACK_ERRORS].puts "Session cookie encryptor error: #{error.message}"

                next
              end
            end

            # If session decryption fails but there is @legacy_hmac_secret
            # defined, attempt legacy HMAC verification
            if !session_data && @legacy_hmac_secret
              # Parse and verify legacy HMAC session cookie
              session_data, _, digest = cookie_data.rpartition('--')
              session_data = nil unless legacy_digest_match?(session_data, digest)

              # Decode using legacy HMAC decoder
              session_data = @legacy_hmac_coder.decode(session_data)
              request.set_header(RACK_SESSION_VERIFIED_COOKIE_DATA, true) if session_data

            elsif !session_data && encryptors.empty? && coder
              # Use the coder option, which has the potential to be very unsafe.
              # This path is only reached when no encryptors (secrets:) are configured;
              # if encryptors are present but decryption failed, the cookie is rejected.
              session_data = coder.decode(cookie_data)
            end
          end

          request.set_header(k, session_data || {})
        end
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
        previous_data = unpacked_cookie_data(req)
        timestamps = refreshed_cookie_timestamps(req, session_id, previous_data, options)
        session = session.merge("session_id" => session_id)

        if manages_session_time?(options)
          session = session.merge(
            CREATED_AT_KEY => timestamps[0],
            LAST_ACCESSED_AT_KEY => timestamps[1]
          )
        end

        session_data = encode_session_data(session)

        if session_data.size > (4096 - @key.size)
          req.get_header(RACK_ERRORS).puts("Warning! Rack::Session::Cookie data size exceeds 4K.")
          nil
        elsif reusable_cookie?(req, session_id, session, previous_data, timestamps, options)
          Cookie::SessionId.new(session_id, req.cookies[@key])
        else
          Cookie::SessionId.new(session_id, session_data)
        end
      end

      def delete_session(req, session_id, options)
        # Nothing to do here, data is in the client
        @clock_high_water.delete(cookie_session_id(session_id)) if session_id
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

      def timestamps_for(req, sid, data, current_time)
        [data[CREATED_AT_KEY], data[LAST_ACCESSED_AT_KEY]]
      end

      def session_expired?(req, sid, session, options, current_time = now)
        return false unless manages_session_time?(options)

        created_at, last_accessed_at = timestamps_for(req, sid, session, current_time)
        return true unless recorded_time_valid?(created_at, current_time, req)
        return true unless recorded_time_valid?(last_accessed_at, current_time, req)
        return true if created_at > last_accessed_at

        if sid && req.get_header(RACK_SESSION_VERIFIED_COOKIE_DATA)
          sid_key = cookie_session_id(sid)
          observed_time = @clock_high_water[sid_key] || current_time
        else
          observed_time = current_time
        end

        if (idle_timeout = options[:idle_timeout])
          return true if current_time >= last_accessed_at + idle_timeout
          return true if observed_time > last_accessed_at + idle_timeout
        end

        if (absolute_timeout = options[:absolute_timeout])
          return true if current_time - created_at >= absolute_timeout
        end

        false
      end

      def future_recorded_time_allowed?(req, value, current_time)
        !!req.get_header(RACK_SESSION_VERIFIED_COOKIE_DATA)
      end

      def fresh_session?(req, data)
        sid = data["session_id"]
        return true unless sid
        !session_expired?(req, sid, data, @default_options)
      end

      def application_session_data(data)
        data.reject do |key, _|
          key == CREATED_AT_KEY || key == LAST_ACCESSED_AT_KEY
        end
      end

      def refreshed_cookie_timestamps(req, sid, data, options)
        current_time = now
        timestamps = timestamps_for(req, sid, data, current_time)

        if skip_idle_renewal?(req, options)
          unless valid_session_time?(timestamps[0]) && valid_session_time?(timestamps[1])
            timestamps = [current_time, current_time]
          end
          timestamps
        else
          unless valid_session_time?(timestamps[0]) && valid_session_time?(timestamps[1])
            timestamps = [current_time, current_time]
          else
            timestamps = [timestamps[0], current_time]
          end
          remember_cookie_clock(req, sid, current_time)
          timestamps
        end
      end

      def reusable_cookie?(req, session_id, session, previous_data, timestamps, options)
        raw_cookie = req.cookies[@key]
        return false unless raw_cookie
        return false unless cookie_session_id(previous_data["session_id"]) == cookie_session_id(session_id)
        return true if skip_idle_renewal?(req, options)
        return false unless manages_session_time?(options)

        previous_timestamps = timestamps_for(req, session_id, previous_data, now)
        return false unless application_session_data(previous_data) == application_session_data(session)
        return false unless valid_session_time?(previous_timestamps[0])
        return false unless previous_timestamps[0] == timestamps[0]

        if timestamps[1] == previous_timestamps[1]
          true
        elsif (throttle = options[:renew_cookie_after])
          now - previous_timestamps[1] <= throttle
        else
          false
        end
      end

      def manages_session_time?(options)
        !!options[:idle_timeout] || !!options[:absolute_timeout]
      end

      def cookie_session_id(session_id)
        session_id.respond_to?(:public_id) ? session_id.public_id : session_id.to_s
      end

      def remember_cookie_clock(req, sid, current_time)
        return unless req.get_header(RACK_SESSION_VERIFIED_COOKIE_DATA)
        key = cookie_session_id(sid)
        previous_seen = @clock_high_water[key]
        @clock_high_water[key] = previous_seen ? [current_time, previous_seen].max : current_time
      end

      def forget_cookie_clock(req, sid)
        @clock_high_water.delete(cookie_session_id(sid)) if sid
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
