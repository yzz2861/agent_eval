require_relative '../common'
require 'net/ssh/authentication/security_key'
require 'net/ssh/key_factory'
require 'base64'

module Authentication
  # Shared helpers for the security key tests. All samples are fixed and
  # were generated locally; no hardware token is involved.
  module SecurityKeyTestHelpers
    SK = Net::SSH::Authentication::SecurityKey

    MESSAGE_B64 = "c2VjdXJpdHkga2V5IHRlc3QgbWVzc2FnZQo="

    def signed_message
      Base64.strict_decode64(MESSAGE_B64)
    end

    def sig_blob(b64)
      Base64.strict_decode64(b64)
    end

    def tampered_blob(b64, flags: nil, counter: nil, algorithm: nil)
      parsed = SK::Signature.read(sig_blob(b64))
      SK::Signature.new(
        algorithm: algorithm || parsed.algorithm,
        signature: parsed.signature,
        flags: flags || parsed.flags,
        counter: counter || parsed.counter
      ).to_blob
    end
  end

  # Tests for the security key signature blob itself. Parsing does not
  # depend on any crypto backend.
  class TestSecurityKeySignature < NetSSHTest
    include SecurityKeyTestHelpers

    SIG_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQOb3rWMM52PlnWWrf7uCuYwzSxKhb+5giiOgKjd6SXi27spI/TYxo0pDTE+91ZFGDd6bWBZZeAGpjmtb80AoewUBAAAAKg=="

    def test_read_roundtrip
      blob = sig_blob(SIG_B64)
      parsed = SK::Signature.read(blob)

      assert_equal "sk-ssh-ed25519@openssh.com", parsed.algorithm
      assert_equal 64, parsed.signature.bytesize
      assert_equal 0x01, parsed.flags
      assert_equal 42, parsed.counter
      assert parsed.user_present?
      refute parsed.user_verified?
      assert_equal blob, parsed.to_blob
    end

    def test_read_rejects_truncated_blob
      blob = sig_blob(SIG_B64)
      assert_raises(SK::MalformedSignatureError) do
        SK::Signature.read(blob.byteslice(0, blob.bytesize - 1))
      end
      assert_raises(SK::MalformedSignatureError) do
        SK::Signature.read(blob.byteslice(0, 10))
      end
    end

    def test_read_rejects_trailing_garbage
      blob = sig_blob(SIG_B64)
      assert_raises(SK::MalformedSignatureError) do
        SK::Signature.read(blob + "\x00")
      end
    end
  end

  # Tests for "sk-ssh-ed25519@openssh.com" public keys and signatures.
  class TestSecurityKeyED25519 < NetSSHTest
    include SecurityKeyTestHelpers

    ED_PUBLIC_KEY_B64 = "dVxMuSVsp83ErP3Gz+7ahJAX5bn5UU6ZGRvWfgsNQnY="
    ED_KEY_BLOB_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIHVcTLklbKfNxKz9xs/u2oSQF+W5+VFOmRkb1n4LDUJ2AAAABHNzaDo="
    ED_SIG_UP_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQOb3rWMM52PlnWWrf7uCuYwzSxKhb+5giiOgKjd6SXi27spI/TYxo0pDTE+91ZFGDd6bWBZZeAGpjmtb80AoewUBAAAAKg=="
    ED_SIG_UP_UV_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQIY69HWsCOVw+Xj79xB0PXRAOwS1qZDe220YVPpManwZ5Gdiw2XqZcG3PipmQr/TkrwIpxL3XjHAlna9HTXC6AIFAAAAKw=="
    ED_SIG_UV_ONLY_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQJ3GZt+iihT14y0bOcPHsrGS8+pZIaHEFVu2I4BcUE9pxCPANia7Y+qrTLCTd0n/HPDe8RJfE1aSWxqDPLdh5QAEAAAALA=="

    def setup
      skip "Ed25519 is not available" unless Net::SSH::Authentication::ED25519Loader::LOADED
    end

    def pub_key(application = "ssh:")
      SK::ED25519::PubKey.new(Base64.strict_decode64(ED_PUBLIC_KEY_B64), application)
    end

    def test_key_blob_read_and_encode
      blob = Base64.strict_decode64(ED_KEY_BLOB_B64)
      key = Net::SSH::Buffer.new(blob).read_key

      assert_instance_of SK::ED25519::PubKey, key
      assert_equal "sk-ssh-ed25519@openssh.com", key.ssh_type
      assert_equal "sk-ssh-ed25519@openssh.com", key.ssh_signature_type
      assert_equal "ssh:", key.application
      assert_equal Base64.strict_decode64(ED_PUBLIC_KEY_B64), key.public_key_bytes
      assert_equal blob, key.to_blob
    end

    def test_load_data_public_key
      line = "sk-ssh-ed25519@openssh.com #{ED_KEY_BLOB_B64} token@example"
      key = Net::SSH::KeyFactory.load_data_public_key(line)

      assert_instance_of SK::ED25519::PubKey, key
      assert_equal "ssh:", key.application
    end

    def test_verify_valid_signature
      assert_equal true, pub_key.ssh_do_verify(sig_blob(ED_SIG_UP_B64), signed_message)
    end

    def test_verify_exposes_flags_and_counter
      details = {}
      assert_equal true, pub_key.ssh_do_verify(sig_blob(ED_SIG_UP_UV_B64), signed_message,
                                               sk_signature_details: details)
      assert_equal 0x05, details[:flags]
      assert_equal 43, details[:counter]
      assert_equal true, details[:user_present]
      assert_equal true, details[:user_verified]
    end

    def test_verify_rejects_changed_application
      assert_equal false, pub_key("other:").ssh_do_verify(sig_blob(ED_SIG_UP_B64), signed_message)
    end

    def test_verify_rejects_changed_flags
      assert_equal false, pub_key.ssh_do_verify(tampered_blob(ED_SIG_UP_B64, flags: 0x03), signed_message)
    end

    def test_verify_rejects_changed_counter
      assert_equal false, pub_key.ssh_do_verify(tampered_blob(ED_SIG_UP_B64, counter: 43), signed_message)
    end

    def test_verify_rejects_changed_message
      assert_equal false, pub_key.ssh_do_verify(sig_blob(ED_SIG_UP_B64), "forged signed_message")
    end

    def test_verify_rejects_changed_algorithm
      blob = tampered_blob(ED_SIG_UP_B64, algorithm: "sk-ecdsa-sha2-nistp256@openssh.com")
      assert_equal false, pub_key.ssh_do_verify(blob, signed_message)
    end

    def test_verify_rejects_truncated_signature
      blob = sig_blob(ED_SIG_UP_B64)
      assert_equal false, pub_key.ssh_do_verify(blob.byteslice(0, blob.bytesize - 3), signed_message)
      assert_equal false, pub_key.ssh_do_verify(blob.byteslice(0, 10), signed_message)
    end

    def test_verify_rejects_bare_signature_without_blob
      inner = SK::Signature.read(sig_blob(ED_SIG_UP_B64)).signature
      assert_equal false, pub_key.ssh_do_verify(inner, signed_message)
    end

    def test_user_presence_required_by_default
      assert_equal false, pub_key.ssh_do_verify(sig_blob(ED_SIG_UV_ONLY_B64), signed_message)
    end

    def test_user_presence_policy_can_be_relaxed_by_caller
      assert_equal true, pub_key.ssh_do_verify(sig_blob(ED_SIG_UV_ONLY_B64), signed_message,
                                               sk_require_user_presence: false)
    end

    def test_user_verification_policy_declared_by_caller
      assert_equal false, pub_key.ssh_do_verify(sig_blob(ED_SIG_UP_B64), signed_message,
                                                sk_require_user_verification: true)
      assert_equal true, pub_key.ssh_do_verify(sig_blob(ED_SIG_UP_UV_B64), signed_message,
                                               sk_require_user_verification: true)
    end
  end

  # Tests for "sk-ecdsa-sha2-nistp256@openssh.com" public keys and
  # signatures.
  class TestSecurityKeyECDSA < NetSSHTest
    include SecurityKeyTestHelpers

    EC_KEY_BLOB_B64 = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBPupNDPFasI15D+Cf+/d6yg9kPdW/kndqbNHxAwA0+qD6mfFPrnnnVmd9Af36E709BzCAIYvXTEzylYgPxEEqykAAAAEc3NoOg=="
    EC_SIG_UP_B64 = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABKAAAAIQD0hjnSSKfzhtFBEjE+dWyKzKySgOskDS6hhqNFxhAJRQAAACEAxentpjf+WIHzdoiO+ElXVN8sSUQeVx8jFho28UTxcCgBAAAAKg=="
    EC_SIG_UP_UV_B64 = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABJAAAAIQC4TZ84S2cdXpvHFctD2j3A+KOjbG6HL5Y6428FZ72tXwAAACArRzmFgjyQCOjffyEcYUMTrmP0IOye85yoSog1ugL7awUAAAAr"
    EC_SIG_UV_ONLY_B64 = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABJAAAAIHA1dbkcNoVBqghMuvJ/4FPI/SVE+xXDYJwm3Auk3vAyAAAAIQDAd2rC/SiQzRf3L4eivKLudYXoeVchmCwy8HBBMb5JegQAAAAs"

    def pub_key(application = "ssh:")
      blob = Net::SSH::Buffer.new(Base64.strict_decode64(EC_KEY_BLOB_B64))
      blob.read_string # key type
      curve = blob.read_string
      octets = blob.read_string
      blob.read_string # application
      rebuilt = Net::SSH::Buffer.from(:string, SK::ECDSA::ALGORITHM, :string, curve,
                                      :string, octets, :string, application).to_s
      Net::SSH::Buffer.new(rebuilt).read_key
    end

    def test_key_blob_read_and_encode
      blob = Base64.strict_decode64(EC_KEY_BLOB_B64)
      key = Net::SSH::Buffer.new(blob).read_key

      assert_instance_of SK::ECDSA::PubKey, key
      assert_equal "sk-ecdsa-sha2-nistp256@openssh.com", key.ssh_type
      assert_equal "sk-ecdsa-sha2-nistp256@openssh.com", key.ssh_signature_type
      assert_equal "ssh:", key.application
      assert_equal blob, key.to_blob
    end

    def test_load_data_public_key
      line = "sk-ecdsa-sha2-nistp256@openssh.com #{EC_KEY_BLOB_B64} token@example"
      key = Net::SSH::KeyFactory.load_data_public_key(line)

      assert_instance_of SK::ECDSA::PubKey, key
      assert_equal "ssh:", key.application
    end

    def test_verify_valid_signature
      assert_equal true, pub_key.ssh_do_verify(sig_blob(EC_SIG_UP_B64), signed_message)
    end

    def test_verify_exposes_flags_and_counter
      details = {}
      assert_equal true, pub_key.ssh_do_verify(sig_blob(EC_SIG_UP_UV_B64), signed_message,
                                               sk_signature_details: details)
      assert_equal 0x05, details[:flags]
      assert_equal 43, details[:counter]
      assert_equal true, details[:user_present]
      assert_equal true, details[:user_verified]
    end

    def test_verify_rejects_changed_application
      assert_equal false, pub_key("other:").ssh_do_verify(sig_blob(EC_SIG_UP_B64), signed_message)
    end

    def test_verify_rejects_changed_flags
      assert_equal false, pub_key.ssh_do_verify(tampered_blob(EC_SIG_UP_B64, flags: 0x03), signed_message)
    end

    def test_verify_rejects_changed_counter
      assert_equal false, pub_key.ssh_do_verify(tampered_blob(EC_SIG_UP_B64, counter: 43), signed_message)
    end

    def test_verify_rejects_changed_message
      assert_equal false, pub_key.ssh_do_verify(sig_blob(EC_SIG_UP_B64), "forged signed_message")
    end

    def test_verify_rejects_changed_algorithm
      blob = tampered_blob(EC_SIG_UP_B64, algorithm: "sk-ssh-ed25519@openssh.com")
      assert_equal false, pub_key.ssh_do_verify(blob, signed_message)
    end

    def test_verify_rejects_truncated_signature
      blob = sig_blob(EC_SIG_UP_B64)
      assert_equal false, pub_key.ssh_do_verify(blob.byteslice(0, blob.bytesize - 3), signed_message)
      assert_equal false, pub_key.ssh_do_verify(blob.byteslice(0, 10), signed_message)
    end

    def test_user_presence_required_by_default
      assert_equal false, pub_key.ssh_do_verify(sig_blob(EC_SIG_UV_ONLY_B64), signed_message)
    end

    def test_user_presence_policy_can_be_relaxed_by_caller
      assert_equal true, pub_key.ssh_do_verify(sig_blob(EC_SIG_UV_ONLY_B64), signed_message,
                                               sk_require_user_presence: false)
    end

    def test_user_verification_policy_declared_by_caller
      assert_equal false, pub_key.ssh_do_verify(sig_blob(EC_SIG_UP_B64), signed_message,
                                                sk_require_user_verification: true)
      assert_equal true, pub_key.ssh_do_verify(sig_blob(EC_SIG_UP_UV_B64), signed_message,
                                               sk_require_user_verification: true)
    end
  end
end
