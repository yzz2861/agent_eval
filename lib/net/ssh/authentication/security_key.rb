require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/transport/openssl'
require 'net/ssh/authentication/pub_key_fingerprint'
require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH
    module Authentication
      # Support for OpenSSH security keys backed by FIDO/U2F authenticators
      # ("sk-ssh-ed25519@openssh.com" and "sk-ecdsa-sha2-nistp256@openssh.com").
      #
      # This module only knows how to read, encode and verify the wire
      # structures OpenSSH wraps around the authenticator's raw signature:
      # the relying-party application string, the authenticator flags and the
      # signature counter. It never talks to a hardware device; producing a
      # signature is left to an ssh-agent (or any caller-supplied agent) that
      # owns the token.
      #
      # The signed blob is never unwrapped and fed to plain Ed25519/ECDSA
      # verification. Instead the authenticator data (application, flags,
      # counter) is reconstructed and checked before the underlying primitive
      # verifies the inner signature, following the layout described in the
      # OpenSSH PROTOCOL.u2f document.
      module SecurityKey
        ED25519_TYPE = 'sk-ssh-ed25519@openssh.com'
        ECDSA_TYPE_PREFIX = 'sk-ecdsa-sha2-'
        ECDSA_TYPE_SUFFIX = '@openssh.com'
        ECDSA_CURVE = 'nistp256'
        ECDSA_TYPE = "#{ECDSA_TYPE_PREFIX}#{ECDSA_CURVE}#{ECDSA_TYPE_SUFFIX}"

        # Default application (relying party id) used by OpenSSH for SSH
        # security keys when the key was generated without an override.
        DEFAULT_APPLICATION = 'ssh:'

        # U2F/authenticator flag bits, as defined by the FIDO U2F raw message
        # specification and PROTOCOL.u2f.
        FLAG_USER_PRESENT = 0x01
        FLAG_USER_VERIFIED = 0x04

        # Raised when a security key signature envelope is malformed, refers
        # to a different application/key type, or fails the caller's
        # authenticator-flag policy. A failed cryptographic verification
        # returns a falsey result instead.
        class SecurityKeyError < Net::SSH::Exception; end

        # Outcome of verifying a security key signature. The counter is exposed
        # here so the caller can apply its own replay/monotonicity policy; this
        # library deliberately keeps no global counter state.
        class Result
          attr_reader :flags, :counter, :application, :signature

          def initialize(flags, counter, application, signature)
            @flags = flags
            @counter = counter
            @application = application
            @signature = signature
          end

          def user_present?
            (@flags & FLAG_USER_PRESENT) != 0
          end

          def user_verified?
            (@flags & FLAG_USER_VERIFIED) != 0
          end
        end

        # Parse a security key signature blob:
        #
        #   string application
        #   byte   flags
        #   uint32 counter
        #   string inner_signature
        #
        # Returns [application, flags, counter, inner_signature]. Raises
        # SecurityKeyError if the blob is truncated or carries trailing data.
        def self.read_signature_blob(blob)
          buffer = Net::SSH::Buffer.new(blob.to_s)
          application = read_exact_string(buffer)
          flags = buffer.read_byte
          counter = buffer.read_long
          signature = read_exact_string(buffer)

          if application.nil? || flags.nil? || counter.nil? || signature.nil? || !buffer.eof?
            raise SecurityKeyError, 'malformed security key signature'
          end

          [application, flags, counter, signature]
        end

        # Read an SSH string while rejecting a declared length that runs past
        # the end of the buffer (Buffer#read_string silently truncates).
        def self.read_exact_string(buffer)
          length = buffer.read_long
          return nil if length.nil? || buffer.available < length

          buffer.read(length)
        end

        # Validate the relying-party application string. OpenSSH requires a
        # non-empty UTF-8 string without embedded NUL bytes.
        def self.validate_application!(application)
          decoded = application.to_s
          if decoded.empty? || decoded.include?("\0") ||
             !decoded.dup.force_encoding('UTF-8').valid_encoding?
            raise SecurityKeyError, 'invalid security key application string'
          end
        end

        # Encode a security key signature blob from its parts. See
        # #read_signature_blob for the layout.
        def self.encode_signature_blob(application, flags, counter, signature)
          Net::SSH::Buffer.from(:string, application,
                                :byte, flags,
                                :long, counter,
                                :string, signature).to_s
        end

        # Rebuild the byte string that the authenticator actually signed.
        # Ed25519 signs this directly; ECDSA signs a SHA-256 digest of it.
        def self.authenticator_message(application, flags, counter, data)
          application.b + [flags].pack('C') + [counter].pack('N') + data.to_s
        end

        # Verify a security key signature against +public_key+ (an instance of
        # SecurityKey::PubKey). +blob+ is the inner contents of the SSH
        # signature string (i.e. without the outer algorithm-name string), and
        # +data+ is the data that was signed.
        #
        # Options:
        #
        # * :user_presence_required - default true; the UP (user present)
        #   flag must be set.
        # * :user_verification_required - default false; when true the UV
        #   (user verified) flag must be set. This is the caller's policy
        #   declaration. When UV is not required, the bit is accepted as-is,
        #   matching OpenSSH semantics.
        #
        # Returns a Result on a valid signature that satisfies the policy,
        # nil on a failed cryptographic verification, and raises
        # SecurityKeyError on a malformed envelope, application/type mismatch
        # or policy violation.
        def self.verify(public_key, blob, data,
                        user_presence_required: true,
                        user_verification_required: false)
          application, flags, counter, signature = read_signature_blob(blob)

          validate_application!(application)

          unless application == public_key.application
            raise SecurityKeyError,
                  "security key application mismatch: #{application.inspect} != #{public_key.application.inspect}"
          end

          message = authenticator_message(application, flags, counter, data)
          return nil unless public_key.verify_inner_signature(signature, message)

          if user_presence_required && (flags & FLAG_USER_PRESENT).zero?
            raise SecurityKeyError, 'security key signature lacks required user presence'
          end

          if user_verification_required && (flags & FLAG_USER_VERIFIED).zero?
            raise SecurityKeyError, 'security key signature lacks required user verification'
          end

          Result.new(flags, counter, application, signature)
        end

        # Base class for security key public keys. Subclasses supply the wire
        # type, the key fields following it and the primitive verifier.
        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          attr_reader :application

          def initialize(application = SecurityKey::DEFAULT_APPLICATION)
            application = application.to_s.dup.force_encoding('BINARY')
            SecurityKey.validate_application!(application)
            @application = application
          end

          def to_blob
            Net::SSH::Buffer.from(:string, ssh_type,
                                  :raw, keyblob_without_type,
                                  :string, application).to_s
          end

          def to_pem
            ssh_type + ' ' + [to_blob].pack('m').gsub("\n", '')
          end

          # Wire portion of the public key following the algorithm-name
          # string. Subclasses must implement.
          def keyblob_without_type
            raise NotImplementedError, 'subclass must implement keyblob_without_type'
          end

          # Verify the authenticator's inner signature over +message+.
          # Subclasses must implement and return a boolean.
          def verify_inner_signature(signature, message)
            raise NotImplementedError, 'subclass must implement verify_inner_signature'
          end

          # Verify the wrapped signature. By default the OpenSSH policy of
          # requiring user presence (UP) and not requiring user verification
          # (UV) is applied; callers override through +options+:
          #
          # * :user_presence_required - require the UP flag (default true)
          # * :user_verification_required - require the UV flag (default false)
          #
          # The verification result (including the counter) is stored in
          # options[:security_key_result] when a Hash is supplied, so the
          # caller can inspect it without any global state being kept. The
          # method remains boolean for compatibility with the rest of
          # Net::SSH.
          def ssh_do_verify(blob, data, options = {})
            result =
              SecurityKey.verify(
                self, blob, data,
                user_presence_required: options.fetch(:user_presence_required, true),
                user_verification_required: options.fetch(:user_verification_required, false)
              )
            options[:security_key_result] = result if result && options.respond_to?(:frozen?) && !options.frozen?
            !result.nil?
          rescue SecurityKeyError
            false
          end
        end

        # "sk-ssh-ed25519@openssh.com" public key:
        #
        #   string "sk-ssh-ed25519@openssh.com"
        #   string 32-byte Ed25519 public key
        #   string application (e.g. "ssh:")
        class Ed25519PubKey < PubKey
          KEY_BYTES = 32

          attr_reader :public_key_bytes

          def initialize(public_key_bytes, application = SecurityKey::DEFAULT_APPLICATION)
            Net::SSH::Authentication::ED25519.validate_key_bytes!(public_key_bytes, 'public key', KEY_BYTES)
            @public_key_bytes = public_key_bytes.to_s.dup.force_encoding('BINARY')
            super(application)
          end

          def self.read_keyblob(buffer)
            public_key_bytes = SecurityKey.read_exact_string(buffer)
            application = SecurityKey.read_exact_string(buffer)
            if public_key_bytes.nil? || application.nil? || !buffer.eof?
              raise SecurityKeyError, 'malformed sk-ssh-ed25519 public key'
            end

            new(public_key_bytes, application)
          end

          def ssh_type
            SecurityKey::ED25519_TYPE
          end

          alias ssh_signature_type ssh_type

          def keyblob_without_type
            Net::SSH::Buffer.from(:string, public_key_bytes).to_s
          end

          def verify_inner_signature(signature, message)
            Net::SSH::Authentication::ED25519.verify(verify_key, signature, message)
          rescue OpenSSL::PKey::PKeyError
            false
          end

          def verify_key
            @verify_key ||= Net::SSH::Authentication::ED25519.new_public_key(public_key_bytes)
          end
        end

        # "sk-ecdsa-sha2-nistp256@openssh.com" public key:
        #
        #   string "sk-ecdsa-sha2-nistp256@openssh.com"
        #   string "nistp256"
        #   string uncompressed EC point (65 bytes)
        #   string application (e.g. "ssh:")
        class ECDSAPubKey < PubKey
          attr_reader :curve_name

          def initialize(curve_name, point, application = SecurityKey::DEFAULT_APPLICATION)
            unless curve_name == SecurityKey::ECDSA_CURVE
              raise SecurityKeyError, "unsupported security key curve #{curve_name.inspect}"
            end

            point = point.to_s
            unless point.bytesize == 65 && point.getbyte(0) == 0x04
              raise SecurityKeyError, 'invalid sk-ecdsa public key point (expected 65-byte uncompressed point)'
            end

            @curve_name = curve_name
            @point_octet = point.dup.force_encoding('BINARY')
            super(application)
          end

          def self.read_keyblob(buffer)
            curve_name = SecurityKey.read_exact_string(buffer)
            point = SecurityKey.read_exact_string(buffer)
            application = SecurityKey.read_exact_string(buffer)
            if curve_name.nil? || point.nil? || application.nil? || !buffer.eof?
              raise SecurityKeyError, 'malformed sk-ecdsa public key'
            end

            new(curve_name, point, application)
          end

          def ssh_type
            SecurityKey::ECDSA_TYPE
          end

          alias ssh_signature_type ssh_type

          def keyblob_without_type
            Net::SSH::Buffer.from(:string, curve_name, :string, @point_octet).to_s
          end

          # ECDSA authenticators sign SHA-256 over the reconstructed
          # authenticator message; the inner signature is encoded as the
          # usual SSH mpint pair (r, s). OpenSSL::PKey::EC#ssh_do_verify
          # hashes its input itself, so verify the precomputed digest
          # directly here instead of going through it.
          def verify_inner_signature(signature, message)
            signature_buffer = Net::SSH::Buffer.new(signature.to_s)
            r = signature_buffer.read_bignum
            s = signature_buffer.read_bignum
            return false if r.nil? || s.nil? || !signature_buffer.eof?

            asn1_signature = OpenSSL::ASN1::Sequence([
                                                        OpenSSL::ASN1::Integer(r),
                                                        OpenSSL::ASN1::Integer(s)
                                                      ]).to_der
            openssl_key.dsa_verify_asn1(OpenSSL::Digest::SHA256.digest(message), asn1_signature)
          rescue OpenSSL::PKey::ECError, OpenSSL::ASN1::ASN1Error
            false
          end

          def openssl_key
            @openssl_key ||= OpenSSL::PKey::EC.read_keyblob(curve_name,
                                                           Net::SSH::Buffer.from(:string, curve_name,
                                                                                 :string, @point_octet))
          end
        end
      end
    end
  end
end
