# encoding: binary
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::SMIME do
  def detached_signature(cert, key, signed_bytes, extra_certs)
    flags = OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY
    OpenSSL::PKCS7.sign(cert, key, signed_bytes, extra_certs, flags).to_der
  end

  # Wraps an inner MIME entity and a detached signature in a multipart/signed
  # message using the raw bytes exactly as given (CRLF separators only).
  def signed_mail(inner, signature, boundary: 'signed-boundary-42', signature_encoding: 'base64')
    if signature_encoding == 'base64'
      encoded_signature = [signature].pack('m0').scan(/.{1,64}/).join("\r\n")
    else
      encoded_signature = signature
    end
    "To: bob@example.com\r\n" \
      "From: alice@example.com\r\n" \
      "Subject: A signed message\r\n" \
      "MIME-Version: 1.0\r\n" \
      "Content-Type: multipart/signed;\r\n" \
      "\tprotocol=\"application/pkcs7-signature\"; micalg=sha-256;\r\n" \
      "\tboundary=\"#{boundary}\"\r\n" \
      "\r\n" \
      "--#{boundary}\r\n" \
      "#{inner}\r\n" \
      "--#{boundary}\r\n" \
      "Content-Type: application/pkcs7-signature; name=smime.p7s\r\n" \
      "Content-Disposition: attachment; filename=smime.p7s\r\n" \
      "Content-Transfer-Encoding: #{signature_encoding}\r\n" \
      "\r\n" \
      "#{encoded_signature}\r\n" \
      "--#{boundary}--\r\n"
  end

  let(:ca_cert) { @ca_cert }
  let(:ca_key) { @ca_key }
  let(:signer_cert) { @signer_cert }
  let(:signer_key) { @signer_key }

  before(:context) do
    @ca_cert, @ca_key = begin
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.new([['CN', 'S/MIME Test CA']])
      cert.issuer = cert.subject
      cert.public_key = key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = cert
      cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
      cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign', true))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      [cert, key]
    end
    @signer_cert, @signer_key = begin
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      cert.subject = OpenSSL::X509::Name.new([['CN', 'alice@example.com']])
      cert.issuer = @ca_cert.subject
      cert.public_key = key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = @ca_cert
      cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
      cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature', true))
      cert.add_extension(factory.create_extension('extendedKeyUsage', 'emailProtection'))
      cert.sign(@ca_key, OpenSSL::Digest.new('SHA256'))
      [cert, key]
    end
  end

  let(:store) do
    OpenSSL::X509::Store.new.tap { |trust| trust.add_cert(ca_cert) }
  end

  # Inner entity with a folded (wrapped) header field and a body ending in
  # CRLF. These are the exact bytes that get signed.
  let(:inner) do
    "Content-Type: text/plain\r\n" \
      "Subject: This subject header is folded across\r\n" \
      "\ttwo physical lines\r\n" \
      "\r\n" \
      "Hello signed world.\r\n" \
      "Second body line.\r\n"
  end

  let(:signature) { detached_signature(signer_cert, signer_key, inner, [ca_cert, signer_cert]) }
  let(:raw_mail) { signed_mail(inner, signature) }

  describe '.verifier' do
    it 'accepts an X509 store' do
      expect(described_class.verifier(store)).to be_a(described_class::Verifier)
    end

    it 'accepts a single trusted certificate' do
      expect(described_class.verifier(ca_cert)).to be_a(described_class::Verifier)
    end

    it 'accepts an array of trusted certificates' do
      expect(described_class.verifier([ca_cert])).to be_a(described_class::Verifier)
    end

    it 'rejects other trust inputs' do
      expect { described_class.verifier('not a certificate') }.to raise_error(ArgumentError)
    end
  end

  describe '#verify' do
    subject(:verifier) { described_class.verifier(store) }

    it 'verifies a well-formed multipart/signed message and returns the signed message' do
      signed = verifier.verify(Mail.new(raw_mail))
      expect(signed).to be_a(Mail::Message)
      expect(signed.decoded).to eq("Hello signed world.\nSecond body line.\n")
    end

    it 'preserves folded header fields verbatim' do
      signed = verifier.verify(Mail.new(raw_mail))
      expect(signed.subject.to_s).to eq("This subject header is folded across\ttwo physical lines")
    end

    it 'uses the exact signed MIME bytes rather than re-encoding the part' do
      message = Mail.new(raw_mail)
      reencoded = message.parts.first.encoded
      expect(reencoded).not_to eq(inner)
      expect { verifier.verify(message) }.not_to raise_error
    end

    it 'does not mutate the original message' do
      message = Mail.new(raw_mail)
      original = message.raw_source.dup
      verifier.verify(message)
      expect(message.raw_source).to eq(original)
    end

    it 'verifies an inner body that does not end with a trailing newline' do
      no_trailing = inner.sub(/\r\n\z/, '')
      sig = detached_signature(signer_cert, signer_key, no_trailing, [ca_cert, signer_cert])
      signed = verifier.verify(Mail.new(signed_mail(no_trailing, sig)))
      expect(signed.decoded).to eq("Hello signed world.\nSecond body line.")
    end

    it 'detects one added trailing byte after the signed body' do
      no_trailing = inner.sub(/\r\n\z/, '')
      sig = detached_signature(signer_cert, signer_key, no_trailing, [ca_cert, signer_cert])
      tampered = signed_mail(no_trailing + "\r", sig)
      expect { verifier.verify(Mail.new(tampered)) }.to raise_error(described_class::ContentTamperedError)
    end

    it 'detects a single changed byte in the body' do
      tampered_inner = inner.dup
      tampered_inner[inner.index('Hello')] = 'J'
      expect { verifier.verify(Mail.new(signed_mail(tampered_inner, signature))) }
        .to raise_error(described_class::ContentTamperedError)
    end

    it 'detects a single changed byte inside a folded header' do
      tampered_inner = inner.dup
      tampered_inner[inner.index('This')] = 'X'
      expect { verifier.verify(Mail.new(signed_mail(tampered_inner, signature))) }
        .to raise_error(described_class::ContentTamperedError)
    end

    it 'raises CertificateUntrustedError when the signer is not in the trust store' do
      untrusted = described_class.verifier(OpenSSL::X509::Store.new)
      expect { untrusted.verify(Mail.new(raw_mail)) }
        .to raise_error(described_class::CertificateUntrustedError)
    end

    it 'raises SignatureCorruptError when signature bytes are damaged' do
      damaged = signature.dup
      damaged[damaged.bytesize - 50] = (damaged[damaged.bytesize - 50].ord ^ 0xff).chr
      expect { verifier.verify(Mail.new(signed_mail(inner, damaged))) }
        .to raise_error(described_class::SignatureCorruptError)
    end

    it 'raises SignatureCorruptError when the signature is not PKCS#7' do
      expect { verifier.verify(Mail.new(signed_mail(inner, 'not a signature' * 20))) }
        .to raise_error(described_class::SignatureCorruptError)
    end

    it 'raises UnsupportedAlgorithmError for an unknown digest algorithm' do
      top = OpenSSL::ASN1.decode(signature)
      signed_data = top.value[1].value[0]
      signer_info = signed_data.value[4].value[0]
      signer_info.value[2] = OpenSSL::ASN1::Sequence.new(
        [OpenSSL::ASN1::ObjectId.new('1.3.9999.42.7')]
      )
      expect { verifier.verify(Mail.new(signed_mail(inner, top.to_der))) }
        .to raise_error(described_class::UnsupportedAlgorithmError)
    end

    it 'raises NotSignedError for a plain message' do
      expect { verifier.verify(Mail.new("Subject: hi\r\n\r\nhello")) }
        .to raise_error(described_class::NotSignedError)
    end

    it 'raises NotSignedError for a non-signed multipart message' do
      mail = Mail.new do
        subject 'mixed'
        text_part { body 'hi' }
      end
      expect { verifier.verify(mail) }.to raise_error(described_class::NotSignedError)
    end

    it 'works without an embedded signer certificate when the store trusts it' do
      sig = detached_signature(signer_cert, signer_key, inner, [])
      signed = verifier.verify(Mail.new(signed_mail(inner, sig)))
      expect(signed.decoded).to include('Hello signed world.')
    end

    it 'verifies a signature part transported with binary content transfer encoding' do
      signed = verifier.verify(Mail.new(signed_mail(inner, signature, signature_encoding: 'binary')))
      expect(signed.decoded).to include('Hello signed world.')
    end
  end
end
