# frozen_string_literal: true
require 'mail'
require 'openssl'

RSpec.describe Mail::SMIME do
  let(:key) { generate_key }
  let(:certificate) { generate_certificate(key) }
  let(:trust_store) { store_for(certificate) }

  describe '.verify' do
    it 'verifies detached S/MIME using the actual signed MIME bytes' do
      signed_entity = folded_header_entity
      message = signed_message(signed_entity, certificate, key)
      original_message = message.raw_source.dup

      expect(Mail::SMIME.verify(message, trust_store)).to eq(signed_entity)
      expect(message.raw_source).to eq(original_message)
    end

    it 'does not verify a re-encoded part as a substitute for the signed MIME bytes' do
      signed_entity = folded_header_entity
      message = signed_message(signed_entity, certificate, key)
      raw_source = message.parts.first.raw_source.dup.sub(/\A(?:\r\n|\n)/, '')

      expect(message.parts.first.encoded).not_to eq(raw_source)
      expect(Mail::SMIME.verify(message, trust_store)).to eq(raw_source)
    end

    it 'preserves a folded signed header without re-encoding the part' do
      signed_entity = folded_header_entity
      message = signed_message(signed_entity, certificate, key)

      expect(message.verify_smime(trust_store)).to eq(signed_entity)
      expect(message.verify_smime(trust_store)).to include("X-Custom: folded\r\n\theader\r\n")
    end

    it 'preserves the exact trailing newline in signed MIME bytes' do
      signed_entity = simple_entity("one byte boundary\r\n\r\n")
      message = signed_message(signed_entity, certificate, key)

      expect(message.verify_smime(trust_store)).to eq(signed_entity)
      expect(message.verify_smime(trust_store).end_with?("\r\n\r\n")).to be(true)
    end

    it 'detects a one-byte body change as content tampering' do
      signed_entity = simple_entity("one byte boundary\r\n")
      message = signed_message(signed_entity, certificate, key)
      original_message = message.raw_source.dup

      signed_part = message.parts.first
      signed_part.raw_source.sub!('o', 'x')

      expect {
        Mail::SMIME.verify(message, trust_store)
      }.to raise_error(Mail::SMIME::ContentTamperedError)
      expect(message.raw_source).to eq(original_message)
    end

    it 'raises signature error when signature bytes are corrupt' do
      signed_entity = simple_entity("valid body\r\n")
      signature = sign_entity(signed_entity, certificate, key)
      corrupted_message = Mail.new(signed_letter(signed_entity, encode_signature(with_corrupt_signature(signature))))

      expect {
        Mail::SMIME.verify(corrupted_message, trust_store)
      }.to raise_error(Mail::SMIME::SignatureError)
    end

    it 'raises signature error when signature data is not valid ASN.1' do
      message = signed_message(simple_entity("valid body\r\n"), certificate, key)
      message.parts.last.body = 'not a signature'

      expect {
        message.verify_smime(trust_store)
      }.to raise_error(Mail::SMIME::SignatureError)
    end

    it 'raises certificate error when the supplied store does not trust the signer' do
      message = signed_message(simple_entity("valid body\r\n"), certificate, key)

      expect {
        message.verify_smime(OpenSSL::X509::Store.new)
      }.to raise_error(Mail::SMIME::CertificateNotTrustedError)
    end

    it 'raises unsupported algorithm error for an unknown digest OID' do
      signed_entity = simple_entity("unknown algorithm\r\n")
      signature = sign_entity(signed_entity, certificate, key)
      message = Mail.new(signed_letter(signed_entity, encode_signature(with_unknown_algorithm(signature))))

      expect {
        message.verify_smime(trust_store)
      }.to raise_error(Mail::SMIME::UnsupportedAlgorithmError)
    end

    it 'does not download certificates or add the signer to the trust store' do
      message = signed_message(simple_entity("valid body\r\n"), certificate, key)
      store = OpenSSL::X509::Store.new

      expect(store).not_to receive(:add_cert)
      expect {
        message.verify_smime(store)
      }.to raise_error(Mail::SMIME::CertificateNotTrustedError)
    end

    it 'raises for messages that are not multipart/signed' do
      message = Mail.new("Content-Type: text/plain\r\n\r\nhello\r\n")

      expect {
        message.verify_smime(trust_store)
      }.to raise_error(Mail::SMIME::SignatureError)
    end

    it 'requires an OpenSSL X509 trust store' do
      message = signed_message(simple_entity("valid body\r\n"), certificate, key)

      expect {
        message.verify_smime(nil)
      }.to raise_error(ArgumentError)
    end
  end

  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def generate_certificate(key)
    certificate = OpenSSL::X509::Certificate.new
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.new([
      ['C', 'US'],
      ['O', 'Mail Test'],
      ['CN', 'mail-smime-test']
    ])
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    certificate.public_key = key.public_key
    certificate.serial = 1
    certificate.version = 2
    certificate.sign(key, OpenSSL::Digest.new('SHA256'))
    certificate
  end

  def store_for(certificate)
    store = OpenSSL::X509::Store.new
    store.add_cert(certificate)
    store
  end

  def folded_header_entity
    "Content-Type: text/plain\r\n" \
      "X-Custom: folded\r\n" \
      "\theader\r\n" \
      "\r\n" \
      "folded header body\r\n"
  end

  def simple_entity(body)
    "Content-Type: text/plain\r\n\r\n#{body.b}"
  end

  def signed_message(entity, certificate, key)
    Mail.new(signed_letter(entity, encode_signature(sign_entity(entity, certificate, key))))
  end

  def sign_entity(entity, certificate, key)
    OpenSSL::PKCS7.sign(
      certificate,
      key,
      entity.b,
      [],
      OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY
    ).to_der
  end

  def encode_signature(signature)
    [signature].pack('m').gsub(/\r?\n/, "\r\n")
  end

  def signed_letter(entity, encoded_signature)
    "From: sender@example.com\r\n" \
      "To: recipient@example.com\r\n" \
      "Subject: S/MIME test\r\n" \
      "MIME-Version: 1.0\r\n" \
      "Content-Type: multipart/signed;\r\n" \
      " protocol=\"application/pkcs7-signature\";\r\n" \
      " micalg=sha-256;\r\n" \
      " boundary=\"mail-boundary\"\r\n" \
      "\r\n" \
      "--mail-boundary\r\n" \
      "#{entity}\r\n" \
      "--mail-boundary\r\n" \
      "Content-Type: application/pkcs7-signature; name=smime.p7s\r\n" \
      "Content-Transfer-Encoding: base64\r\n" \
      "Content-Disposition: attachment; filename=smime.p7s\r\n" \
      "\r\n" \
      "#{encoded_signature}" \
      "--mail-boundary--\r\n"
  end

  def with_unknown_algorithm(der)
    root = OpenSSL::ASN1.decode(der)
    signed_data = root.value[1].value[0]
    unknown_oid = OpenSSL::ASN1::ObjectId.new('1.2.3.4.999.1')

    signed_data.value[1].value[0].value[0] = unknown_oid
    signer_info = signed_data.value[4].value[0]
    signer_info.value[2].value[0] = unknown_oid
    signer_info.value[4].value[0] = unknown_oid

    root.to_der
  end

  def with_corrupt_signature(der)
    root = OpenSSL::ASN1.decode(der)
    signer_info = root.value[1].value[0].value[4].value[0]
    signature = signer_info.value[5]
    signature.value.setbyte(0, signature.value.getbyte(0) ^ 0xff)
    root.to_der
  end
end
