require 'openssl'
require 'net/ssh/transport/openssl'
require 'net/ssh/authentication/ed25519_loader'
require 'net/ssh/authentication/pub_key_fingerprint'

module Net
  module SSH
    module Authentication
      # Implements the public key and signature formats for FIDO/U2F
      # security keys ("sk-ssh-ed25519@openssh.com" and
      # "sk-ecdsa-sha2-nistp256@openssh.com"), as described in OpenSSH's
      # PROTOCOL.u2f. Hardware tokens are always driven by an ssh-agent;
      # this module only handles the wire formats: it never talks to a
      # device itself.
      module SecurityKey
        # Authenticator data flags, as defined by FIDO2 and referenced by
        # PROTOCOL.u2f.
        FLAG_USER_PRESENCE = 0x01
        FLAG_USER_VERIFICATION = 0x04
        FLAG_RESIDENT_KEY = 0x20

        # Raised when a security key signature blob cannot be parsed.
        class MalformedSignatureError < ArgumentError; end

        # A parsed security key signature blob:
        #
        #   string  algorithm
        #   string  signature
        #   byte    flags
        #   uint32  counter
        class Signature
          attr_reader :algorithm, :signature, :flags, :counter

          def initialize(algorithm:, signature:, flags:, counter:)
            @algorithm = algorithm
            @signature = signature
            @flags = flags
            @counter = counter
          end

          # Parses a signature blob as returned by an agent for a
          # security key. Raises MalformedSignatureError if the blob is
          # truncated or has trailing garbage.
          def self.read(blob)
            buffer = Net::SSH::Buffer.new(blob)
            algorithm = buffer.read_string
            signature = buffer.read_string
            flags = buffer.read_byte
            counter = buffer.read_long
            unless algorithm && signature && flags && counter && buffer.eof?
              raise MalformedSignatureError, "malformed security key signature blob"
            end

            new(algorithm: algorithm, signature: signature, flags: flags, counter: counter)
          end

          def to_blob
            Net::SSH::Buffer.from(:string, algorithm, :string, signature,
                                  :byte, flags, :long, counter).to_s
          end

          def user_present?
            (flags & FLAG_USER_PRESENCE) != 0
          end

          def user_verified?
            (flags & FLAG_USER_VERIFICATION) != 0
          end
        end

        # Reconstructs the payload the authenticator actually signed:
        #
        #   byte[32]  SHA256(application)
        #   byte      flags
        #   uint32    counter
        #   byte[32]  SHA256(message)
        def self.signed_data(application, flags, counter, message)
          Net::SSH::Buffer.from(
            :raw, OpenSSL::Digest::SHA256.digest(application),
            :byte, flags,
            :long, counter,
            :raw, OpenSSL::Digest::SHA256.digest(message)
          ).to_s
        end

        # Shared verification logic for security key public keys. Parses
        # the signature blob, enforces the caller's flag policy and yields
        # the reconstructed signed payload so the key-specific raw
        # signature check can run. Returns a boolean like the other
        # ssh_do_verify implementations.
        #
        # Options:
        #   :sk_require_user_presence     require the user-presence flag
        #                                 (default true)
        #   :sk_require_user_verification require the user-verification
        #                                 flag (default false)
        #   :sk_signature_details         optional object supporting #[]=
        #                                 (e.g. a Hash) that receives the
        #                                 parsed :flags, :counter,
        #                                 :user_present and :user_verified
        #                                 values, so the caller can apply
        #                                 its own counter policy. Nothing
        #                                 is persisted by the library.
        def self.verify(pub_key, sig, data, options = {})
          parsed = sig.is_a?(Signature) ? sig : Signature.read(sig)
          return false unless parsed.algorithm == pub_key.ssh_signature_type

          if (details = options[:sk_signature_details])
            details[:flags] = parsed.flags
            details[:counter] = parsed.counter
            details[:user_present] = parsed.user_present?
            details[:user_verified] = parsed.user_verified?
          end

          return false if options.fetch(:sk_require_user_presence, true) && !parsed.user_present?
          return false if options.fetch(:sk_require_user_verification, false) && !parsed.user_verified?

          yield parsed, signed_data(pub_key.application, parsed.flags, parsed.counter, data)
        rescue MalformedSignatureError, OpenSSL::PKey::PKeyError
          false
        end

        # Support for "sk-ssh-ed25519@openssh.com" security keys.
        module ED25519
          ALGORITHM = "sk-ssh-ed25519@openssh.com"

          # A public "sk-ssh-ed25519@openssh.com" key: an Ed25519 public
          # key bound to an application string (typically "ssh:").
          class PubKey
            include Net::SSH::Authentication::PubKeyFingerprint

            attr_reader :application

            def initialize(public_key_bytes, application)
              Net::SSH::Authentication::ED25519.validate_key_bytes!(
                public_key_bytes, "public key", Net::SSH::Authentication::ED25519::KEY_BYTES
              )
              @public_key_bytes = public_key_bytes.dup.force_encoding('BINARY')
              @application = application.to_s.dup.freeze
            end

            def self.read_keyblob(buffer)
              new(buffer.read_string, buffer.read_string)
            end

            def to_blob
              Net::SSH::Buffer.from(:mstring, ALGORITHM.dup, :string, public_key_bytes,
                                    :string, application).to_s
            end

            def ssh_type
              ALGORITHM
            end

            def ssh_signature_type
              ssh_type
            end

            # Verifies a security key signature blob (see
            # SecurityKey.verify for the supported options). The blob is
            # never stripped down to a plain Ed25519 signature: the
            # application, authenticator flags and counter are part of
            # the verified payload.
            def ssh_do_verify(sig, data, options = {})
              SecurityKey.verify(self, sig, data, options) do |parsed, payload|
                Net::SSH::Authentication::ED25519.verify(verify_key, parsed.signature, payload)
              end
            end

            def public_key_bytes
              @public_key_bytes.dup
            end

            def verify_key
              @verify_key ||= Net::SSH::Authentication::ED25519.new_public_key(@public_key_bytes)
            end
          end
        end

        # Support for "sk-ecdsa-sha2-nistp256@openssh.com" security keys.
        module ECDSA
          ALGORITHM = "sk-ecdsa-sha2-nistp256@openssh.com"
          CURVE_NAME = "nistp256"

          # A public "sk-ecdsa-sha2-nistp256@openssh.com" key: a NIST
          # P-256 ECDSA public key bound to an application string
          # (typically "ssh:").
          class PubKey
            include Net::SSH::Authentication::PubKeyFingerprint

            attr_reader :application

            def initialize(ec_public_key, application)
              @public_key = ec_public_key
              @application = application.to_s.dup.freeze
            end

            def self.read_keyblob(buffer)
              new(OpenSSL::PKey::EC.read_keyblob(CURVE_NAME, buffer), buffer.read_string)
            end

            def to_blob
              Net::SSH::Buffer.from(:mstring, ALGORITHM.dup, :string, CURVE_NAME,
                                    :mstring, @public_key.public_key.to_bn.to_s(2),
                                    :string, application).to_s
            end

            def ssh_type
              ALGORITHM
            end

            def ssh_signature_type
              ssh_type
            end

            # Verifies a security key signature blob (see
            # SecurityKey.verify for the supported options). The inner
            # ECDSA signature (mpint r, mpint s) is verified over the
            # reconstructed payload, never over the raw message alone.
            def ssh_do_verify(sig, data, options = {})
              SecurityKey.verify(self, sig, data, options) do |parsed, payload|
                @public_key.ssh_do_verify(parsed.signature, payload)
              end
            end
          end
        end
      end
    end
  end
end
