# frozen_string_literal: true

RSpec.describe JWT::JWA::Rsa do
  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:public_key) { test_pkey('rsa-2048-public.pem') }
  let(:instance) { described_class.new('RS256') }
  let(:data) { 'rsa streaming data ' * 100 }

  describe '#stream_signer' do
    it 'produces the same signature as #sign when chunks are streamed' do
      signer = instance.stream_signer(signing_key: rsa_key)
      data.bytes.each_slice(7) { |bytes| signer.update(bytes.pack('C*')) }

      expect(signer.sign).to eq(instance.sign(data: data, signing_key: rsa_key))
    end

    it 'signs empty data identically to #sign' do
      expect(instance.stream_signer(signing_key: rsa_key).sign).to eq(instance.sign(data: '', signing_key: rsa_key))
    end

    it 'rejects a public key' do
      expect { instance.stream_signer(signing_key: public_key) }.to raise_error(JWT::EncodeError, /not a private key/)
    end

    it 'rejects a non RSA key' do
      expect { instance.stream_signer(signing_key: 'nope') }.to raise_error(JWT::EncodeError)
    end

    it 'rejects small keys before reading the body' do
      key = OpenSSL::PKey::RSA.generate(1024)
      expect { instance.stream_signer(signing_key: key) }.to raise_error(JWT::EncodeError, /2048 bits/)
    end
  end

  describe '#stream_verifier' do
    let(:signature) { instance.sign(data: data, signing_key: rsa_key) }

    it 'verifies data streamed in arbitrary chunks' do
      verifier = instance.stream_verifier(signature: signature, verification_key: public_key)
      offset = 0
      [1, 4, 256, 9, 4096].each do |length|
        piece = data.byteslice(offset, length)
        break unless piece

        verifier.update(piece)
        offset += piece.bytesize
      end
      expect(verifier.valid?).to be(true)
    end

    context 'with bindings without sign_raw/verify_raw' do
      it 'signs and verifies through the portable PKCS#1 v1.5 fallback' do
        allow(rsa_key).to receive(:respond_to?).and_call_original
        allow(rsa_key).to receive(:respond_to?).with(:sign_raw).and_return(false)
        allow(public_key).to receive(:respond_to?).and_call_original
        allow(public_key).to receive(:respond_to?).with(:verify_raw).and_return(false)

        signer = instance.stream_signer(signing_key: rsa_key)
        signature = signer.update(data).sign

        expect(signature).to eq(instance.sign(data: data, signing_key: rsa_key))

        verifier = instance.stream_verifier(signature: signature, verification_key: public_key)
        expect(verifier.update(data).valid?).to be(true)

        tampered = instance.stream_verifier(signature: signature, verification_key: public_key)
        expect(tampered.update(data + '!').valid?).to be(false)

        garbage = instance.stream_verifier(signature: 'garbage-signature', verification_key: public_key)
        expect(garbage.update(data).valid?).to be(false)

        allow(public_key).to receive(:public_decrypt).and_raise(OpenSSL::PKey::PKeyError, 'invalid padding')
        broken = instance.stream_verifier(signature: signature, verification_key: public_key)
        expect(broken.update(data).valid?).to be(false)
      end
    end

    it 'verifies with the private key too' do
      verifier = instance.stream_verifier(signature: signature, verification_key: rsa_key)
      expect(verifier.update(data).valid?).to be(true)
    end

    it 'does not verify tampered data' do
      verifier = instance.stream_verifier(signature: signature, verification_key: public_key)
      expect(verifier.update(data + 'x').valid?).to be(false)
    end

    it 'rejects a non RSA key' do
      expect { instance.stream_verifier(signature: signature, verification_key: 'key') }.to raise_error(JWT::VerificationKeyError)
    end

    it 'wraps OpenSSL errors raised while verifying a malformed signature' do
      allow(public_key).to receive(:verify_raw).and_raise(OpenSSL::PKey::PKeyError, 'boom')
      verifier = instance.stream_verifier(signature: signature, verification_key: public_key)
      expect { verifier.update(data).valid? }.to raise_error(JWT::VerificationError, 'Signature verification raised')
    end
  end
end
