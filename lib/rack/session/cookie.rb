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
require_relative 'revocation'

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
    # == Per-subject revocation
    #
    # A :revocation_store option (see Rack::Session::Revocation::Store) enables
    # per-subject session revocation, so that e.g. a password change can sign
    # out every existing session of a single user without rotating the global
    # secrets (which would sign out all users at once):
    #
    #   store = Rack::Session::Revocation::Memory.new
    #   Rack::Session::Cookie.new(application, {
    #     secrets: 'a randomly generated, raw binary string 64 bytes in size',
    #     revocation_store: store,
    #     subject_key: 'user_id', # default
    #   })
    #
    #   # Later, e.g. after a password change:
    #   store.revoke!(user_id)
    #
    # When enabled, each issued session records the generation of its subject
    # (the value of the session's :subject_key entry) inside the encrypted
    # cookie payload. On every request the recorded generation is compared
    # against the store; sessions issued before the subject's current
    # generation are discarded and the request continues with a fresh,
    # anonymous session. The exact semantics are:
    #
    # * Anonymous sessions (no subject in the session data) are never stamped
    #   and never checked; they pass through untouched.
    # * Ordinary renewal of a session keeps the generation recorded at
    #   issuance. It is never re-stamped, so a revoked session cannot regain
    #   validity simply by being used.
    # * A new login, or any request that changes the session's subject, is
    #   stamped with the subject's *current* generation.
    # * Sessions issued before the feature was enabled (or before a subject
    #   was ever stamped) are treated as generation 0.
    # * If the revocation store fails while checking a session, the session is
    #   rejected (fail closed): a revocation that cannot be verified is never
    #   silently skipped. If the store fails while stamping a new login, the
    #   session is not saved. Both failures are logged to rack.errors.
    #

    class Cookie < Abstract::PersistedSecure
      # Session payload key holding the subject generation recorded at
      # issuance. This is session metadata and is removed from the session
      # data exposed to the application.
      GENERATION_KEY = "session_generation"

      # Request environment key holding the validated [subject, generation]
      # pair of the loaded session, used to keep the generation stable across
      # ordinary renewals.
      RACK_SESSION_REVOCATION = "rack.session.revocation"

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

        @revocation_store = options[:revocation_store]
        @subject_key = (options[:subject_key] || "user_id").to_s

        super(app, options.merge!(cookie_only: true))
      end

      private

      def find_session(req, sid)
        data = unpacked_cookie_data(req)
        data = persistent_session_id!(data)
        data = validate_session_generation(req, data)
        [data["session_id"], data]
      end

      # Compare the generation recorded in the session against the revocation
      # store. Returns the session data to use: either the original data, or a
      # fresh anonymous session if the loaded one was revoked (or could not be
      # verified). The validated [subject, generation] pair is kept in the
      # request environment so that write_session can keep the generation
      # stable across ordinary renewals.
      def validate_session_generation(req, data)
        return data unless @revocation_store

        # The generation is session metadata, not application data.
        generation = data.delete(GENERATION_KEY) || 0
        subject = data[@subject_key]

        # Anonymous sessions are not tied to a subject and cannot be revoked
        # by generation.
        unless subject
          req.set_header(RACK_SESSION_REVOCATION, false)
          return data
        end

        current = fetch_current_generation(req, subject)

        if current && current <= generation
          req.set_header(RACK_SESSION_REVOCATION, [subject, generation])
          data
        else
          # The session was revoked, or the store is unavailable and we fail
          # closed: discard it and start fresh.
          req.set_header(RACK_SESSION_REVOCATION, false)
          persistent_session_id!({})
        end
      end

      # Record the subject's generation in the session payload about to be
      # written. Returns false if the generation could not be determined due
      # to a storage failure, in which case the session must not be saved.
      def stamp_session_generation(req, session)
        subject = session[@subject_key]

        # Anonymous sessions are never stamped.
        return true unless subject

        revocation = req.get_header(RACK_SESSION_REVOCATION)

        if revocation && revocation.first == subject
          # The subject is unchanged since the session was loaded: keep the
          # generation recorded at issuance. Renewal must never upgrade the
          # generation, otherwise a revoked session could launder itself back
          # to validity simply by being used.
          session[GENERATION_KEY] = revocation.last
          return true
        end

        # A new login or a subject switch: stamp the subject's current
        # generation.
        if generation = fetch_current_generation(req, subject)
          session[GENERATION_KEY] = generation
          true
        else
          false
        end
      end

      # Read the subject's current generation from the revocation store.
      # Storage failures are logged and reported as nil, so callers fail
      # closed.
      def fetch_current_generation(req, subject)
        @revocation_store.current_generation(subject)
      rescue StandardError => error
        req.get_header(RACK_ERRORS).puts("Session revocation store error: #{error.message}")
        nil
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
        session = session.merge("session_id" => session_id)

        if @revocation_store && !stamp_session_generation(req, session)
          req.get_header(RACK_ERRORS).puts("Warning! #{self.class.name} could not verify the session generation. Content dropped.")
          return false
        end

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
