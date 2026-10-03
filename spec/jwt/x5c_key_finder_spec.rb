# frozen_string_literal: true

RSpec.describe JWT::X5cKeyFinder do
  let(:root_key) { test_pkey('rsa-2048-private.pem') }
  let(:root_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake CA') }
  let(:root_certificate) { generate_root_cert(root_dn, root_key) }
  let(:leaf_key) { generate_key }
  let(:leaf_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake/CN=Fake') }
  let(:leaf_serial) { 2 }
  let(:leaf_not_after) { Time.now + 3600 }
  let(:leaf_signing_key) { root_key }
  let(:leaf_certificate) do
    cert = generate_cert(
      leaf_dn,
      leaf_key.public_key,
      leaf_serial,
      issuer: root_certificate,
      not_after: leaf_not_after
    )
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.config = OpenSSL::Config.parse(leaf_cdp)
    ef.subject_certificate = cert
    cert.add_extension(ef.create_extension('crlDistributionPoints', '@crlDistPts'))
    cert.sign(leaf_signing_key, 'sha256')
    cert
  end
  let(:leaf_cdp) { <<-_CNF_ }
    [crlDistPts]
    URI.1 = http://www.example.com/crl
  _CNF_

  let(:crl) { issue_crl([], issuer: root_certificate, issuer_key: root_key) }

  let(:x5c_header) { [Base64.strict_encode64(leaf_certificate.to_der)] }
  subject(:keyfinder) { described_class.new([root_certificate], [crl]).from(x5c_header) }

  it 'returns the public key from a certificate that is signed by trusted roots and not revoked' do
    expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
    expect(keyfinder.public_key.to_der).to eq(leaf_certificate.public_key.to_der)
  end

  context 'already parsed certificates' do
    let(:x5c_header) { [leaf_certificate] }

    it 'returns the public key from a certificate that is signed by trusted roots and not revoked' do
      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      expect(keyfinder.public_key.to_der).to eq(leaf_certificate.public_key.to_der)
    end
  end

  context '::JWT.decode' do
    let(:token_payload) { { 'data' => 'something' } }
    let(:encoded_token) { JWT.encode(token_payload, leaf_key, 'RS256', { 'x5c' => x5c_header }) }
    let(:decoded_payload) do
      JWT.decode(encoded_token, nil, true, algorithms: ['RS256'], x5c: { root_certificates: [root_certificate], crls: [crl] }).first
    end

    it 'returns the encoded payload after successful certificate path verification' do
      expect(decoded_payload).to eq(token_payload)
    end
  end

  context 'certificate usage policy' do
    let(:reference_time) { Time.at(Time.now.to_i - 86_400) }
    let(:root_certificate) do
      certificate = generate_cert(
        root_dn,
        root_key.public_key,
        1,
        not_before: reference_time - 86_400,
        not_after: reference_time + 86_400
      )
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = certificate
      certificate.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
      certificate.sign(root_key, 'sha256')
      certificate
    end
    let(:intermediate_key) { generate_key }
    let(:intermediate_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Intermediate CA') }
    let(:intermediate_not_after) { reference_time + 3600 }
    let(:intermediate_certificate) do
      certificate = generate_cert(
        intermediate_dn,
        intermediate_key.public_key,
        2,
        issuer: root_certificate,
        not_before: reference_time - 3600,
        not_after: intermediate_not_after
      )
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = certificate
      factory.issuer_certificate = root_certificate
      certificate.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
      certificate.sign(root_key, 'sha256')
      certificate
    end

    let(:leaf_key) { generate_key }
    let(:leaf_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake/CN=Policy Leaf') }
    let(:leaf_not_after) { reference_time + 3600 }
    let(:leaf_key_usages) { ['digitalSignature'] }
    let(:leaf_extended_key_usages) { ['clientAuth'] }
    let(:leaf_certificate) do
      certificate = generate_cert(
        leaf_dn,
        leaf_key.public_key,
        3,
        issuer: intermediate_certificate,
        not_before: reference_time - 3600,
        not_after: leaf_not_after
      )
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = certificate
      factory.issuer_certificate = intermediate_certificate
      certificate.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
      unless leaf_key_usages.empty?
        certificate.add_extension(
          factory.create_extension('keyUsage', leaf_key_usages.join(','), true)
        )
      end
      unless leaf_extended_key_usages.empty?
        certificate.add_extension(
          factory.create_extension('extendedKeyUsage', leaf_extended_key_usages.join(','), false)
        )
      end
      certificate.sign(intermediate_key, 'sha256')
      certificate
    end

    let(:root_crl) do
      issue_crl([], issuer: root_certificate, issuer_key: root_key,
                        last_update: reference_time - 86_400, next_update: reference_time + 86_400)
    end
    let(:intermediate_crl) do
      issue_crl([], issuer: intermediate_certificate, issuer_key: intermediate_key,
                        last_update: reference_time - 86_400, next_update: reference_time + 86_400)
    end
    let(:x5c_header) do
      [
        Base64.strict_encode64(leaf_certificate.to_der),
        Base64.strict_encode64(intermediate_certificate.to_der)
      ]
    end
    let(:required_eku) { nil }
    let(:allow_missing_eku) { false }
    let(:require_digital_signature) { false }
    let(:allow_missing_digital_signature) { false }
    let(:max_chain_depth) { nil }
    subject(:keyfinder) do
      described_class.new(
        [root_certificate],
        [root_crl, intermediate_crl],
        eku: required_eku,
        allow_missing_eku: allow_missing_eku,
        require_digital_signature: require_digital_signature,
        allow_missing_digital_signature: allow_missing_digital_signature,
        max_chain_depth: max_chain_depth,
        verification_time: reference_time
      ).from(x5c_header)
    end

    it 'validates a short chain using the supplied time and trusted root' do
      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      expect(keyfinder.to_der).to eq(leaf_certificate.public_key.to_der)
    end

    it 'accepts the trusted root when it is also present in the x5c header' do
      x5c_header << Base64.strict_encode64(root_certificate.to_der)
      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
    end

    it 'applies the complete usage policy when invoked through JWT.decode' do
      token = JWT.encode({ 'data' => 'policy' }, leaf_key, 'RS256', { 'x5c' => x5c_header })
      payload, = JWT.decode(
        token,
        nil,
        true,
        algorithms: ['RS256'],
        x5c: {
          root_certificates: [root_certificate],
          crls: [root_crl, intermediate_crl],
          eku: 'clientAuth',
          require_digital_signature: true,
          max_chain_depth: 1,
          verification_time: reference_time
        }
      )

      expect(payload).to eq('data' => 'policy')
    end

    it 'accepts the policy as an options hash' do
      keyfinder = described_class.new(
        [root_certificate],
        [root_crl, intermediate_crl],
        {
          eku: 'clientAuth',
          require_digital_signature: true,
          max_chain_depth: 1,
          verification_time: reference_time
        }
      ).from(x5c_header)

      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
    end

    it 'rejects an invalid required EKU OID' do
      expect do
        described_class.new([root_certificate], [root_crl], eku: 'not-an-oid')
      end.to raise_error(ArgumentError, 'Invalid extended key usage OID: not-an-oid')
    end

    it 'rejects a negative maximum chain depth' do
      expect do
        described_class.new([root_certificate], [root_crl], max_chain_depth: -1)
      end.to raise_error(ArgumentError, 'Maximum chain depth must be a non-negative integer')
    end

    context 'when the header contains an untrusted self-signed root' do
      let(:other_root_key) { generate_key }
      let(:other_root_certificate) do
        generate_root_cert(
          root_dn,
          other_root_key,
          not_before: reference_time - 86_400,
          not_after: reference_time + 86_400
        )
      end

      subject(:keyfinder) do
        described_class.new(
          [other_root_certificate],
          [root_crl, intermediate_crl],
          verification_time: reference_time
        )
                       .from(x5c_header + [Base64.strict_encode64(root_certificate.to_der)])
      end

      it 'does not trust the root from the header' do
        expect { keyfinder }.to raise_error(JWT::CertificateChainError, /Self-signed certificates in the x5c chain/)
      end
    end

    context 'chain depth' do
      context 'when the chain is within the configured depth' do
        let(:max_chain_depth) { 1 }

        it 'returns the leaf public key' do
          expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
        end
      end

      context 'when the chain exceeds the configured depth' do
        let(:max_chain_depth) { 0 }

        it 'raises a chain depth error' do
          expect { keyfinder }.to raise_error(JWT::CertificateChainDepthError,
                                             'Certificate chain depth 1 exceeds maximum 0')
        end
      end
    end

    context 'digitalSignature key usage' do
      let(:require_digital_signature) { true }

      it 'accepts a leaf that permits digitalSignature' do
        expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      end

      context 'when the extension is present but does not permit digitalSignature' do
        let(:leaf_key_usages) { ['keyCertSign'] }

        it 'raises an invalid key usage error' do
          expect { keyfinder }.to raise_error(JWT::InvalidKeyUsageError,
                                             'Signing certificate does not permit digitalSignature')
        end
      end

      context 'when the extension is missing' do
        let(:leaf_key_usages) { [] }

        it 'raises a missing key usage error' do
          expect { keyfinder }.to raise_error(JWT::MissingKeyUsageError,
                                             'Signing certificate is missing the key usage extension')
        end

        context 'when a missing extension is allowed' do
          let(:allow_missing_digital_signature) { true }

          it 'accepts the leaf' do
            expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
          end
        end
      end

      context 'when a present mismatch could be treated as missing' do
        let(:leaf_key_usages) { ['keyCertSign'] }
        let(:allow_missing_digital_signature) { true }

        it 'still rejects the mismatch' do
          expect { keyfinder }.to raise_error(JWT::InvalidKeyUsageError)
        end
      end
    end

    context 'extended key usage' do
      let(:required_eku) { 'clientAuth' }

      it 'accepts a leaf containing the required EKU' do
        expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      end

      context 'when the extension is present but does not include the required EKU' do
        let(:leaf_extended_key_usages) { ['serverAuth'] }

        it 'raises an invalid extended key usage error' do
          expect { keyfinder }.to raise_error(JWT::InvalidExtendedKeyUsageError)
        end
      end

      context 'when the extension is missing' do
        let(:leaf_extended_key_usages) { [] }

        it 'raises a missing extended key usage error' do
          expect { keyfinder }.to raise_error(JWT::MissingExtendedKeyUsageError)
        end

        context 'when a missing extension is allowed' do
          let(:allow_missing_eku) { true }

          it 'accepts the leaf' do
            expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
          end
        end
      end

      context 'when a present mismatch could be treated as missing' do
        let(:leaf_extended_key_usages) { ['serverAuth'] }
        let(:allow_missing_eku) { true }

        it 'still rejects the mismatch' do
          expect { keyfinder }.to raise_error(JWT::InvalidExtendedKeyUsageError)
        end
      end
    end

    context 'chain structure' do
      context 'when certificates are not ordered leaf first' do
        let(:x5c_header) do
          [
            Base64.strict_encode64(intermediate_certificate.to_der),
            Base64.strict_encode64(leaf_certificate.to_der)
          ]
        end

        it 'raises a chain order error' do
          expect { keyfinder }.to raise_error(
            JWT::CertificateChainOrderError,
            'Certificate chain must be ordered from the signing certificate toward its issuer'
          )
        end
      end

      context 'when a certificate is duplicated' do
        let(:x5c_header) do
          [
            Base64.strict_encode64(leaf_certificate.to_der),
            Base64.strict_encode64(intermediate_certificate.to_der),
            Base64.strict_encode64(intermediate_certificate.to_der)
          ]
        end

        it 'raises a duplicate certificate error' do
          expect { keyfinder }.to raise_error(
            JWT::DuplicateCertificateError,
            'Certificate chain contains duplicate certificates'
          )
        end
      end

      context 'when an intermediate certificate is expired at the verification time' do
        let(:intermediate_not_after) { reference_time - 60 }

        it 'raises a certificate expired error for the intermediate certificate' do
          expect { keyfinder }.to raise_error do |error|
            expect(error).to be_a(JWT::CertificateTimeError)
            expect(error.message).to include('certificate has expired')
            expect(error.message).to include(intermediate_dn.to_s)
          end
        end
      end

      context 'when a certificate has an unsupported critical extension' do
        before do
          intermediate_certificate.add_extension(
            OpenSSL::X509::Extension.new('1.2.3.4.5', 'unsupported'.b, true)
          )
          intermediate_certificate.sign(root_key, 'sha256')
        end

        it 'raises an unsupported critical extension error' do
          expect { keyfinder }.to raise_error(
            JWT::UnsupportedCriticalExtensionError,
            /unhandled critical extension/
          )
        end
      end
    end
  end

  context 'certificate' do
    context 'expired' do
      let(:leaf_not_after) { Time.now - 3600 }

      it 'raises an error' do
        error = 'Certificate verification failed: certificate has expired. Certificate subject: /DC=org/DC=fake/CN=Fake.'
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context 'signature could not be verified with the given trusted roots' do
      let(:leaf_signing_key) { generate_key }

      it 'raises an error' do
        error = 'Certificate verification failed: certificate signature failure. Certificate subject: /DC=org/DC=fake/CN=Fake.'
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context 'could not be chained to a trusted root certificate' do
      context 'given an array' do
        subject(:keyfinder) { described_class.new([], [crl]).from(x5c_header) }

        it 'raises a verification error' do
          error = 'Certificate verification failed: unable to get local issuer certificate. Certificate subject: /DC=org/DC=fake/CN=Fake.'
          expect { keyfinder }.to raise_error(JWT::VerificationError, error)
        end
      end

      context 'given nil' do
        subject(:keyfinder) { described_class.new(nil, [crl]).from(x5c_header) }

        it 'raises a decode error' do
          error = 'Root certificates must be specified'
          expect { keyfinder }.to raise_error(ArgumentError, error)
        end
      end
    end

    context 'revoked' do
      let(:revocation) { [leaf_serial, Time.now - 60, 1] }
      let(:crl) { issue_crl([revocation], issuer: root_certificate, issuer_key: root_key) }

      it 'raises an error' do
        error = 'Certificate verification failed: certificate revoked. Certificate subject: /DC=org/DC=fake/CN=Fake.'
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end
  end

  context 'CRL' do
    context 'expired' do
      let(:next_up) { Time.now - 60 }
      let(:crl) { issue_crl([], next_update: next_up, issuer: root_certificate, issuer_key: root_key) }

      it 'raises an error' do
        error = 'Certificate verification failed: CRL has expired. Certificate subject: /DC=org/DC=fake/CN=Fake.'
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context 'signature could not be verified with the given trusted roots' do
      let(:crl) { issue_crl([], issuer: root_certificate, issuer_key: generate_key) }

      it 'raises an error' do
        error = 'Certificate verification failed: CRL signature failure. Certificate subject: /DC=org/DC=fake/CN=Fake.'
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context 'not given' do
      subject(:keyfinder) { described_class.new([root_certificate], nil).from(x5c_header) }

      it 'raises an error' do
        error = 'Certificate verification failed: unable to get certificate CRL. Certificate subject: /DC=org/DC=fake/CN=Fake.'
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end
  end

  private

  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def generate_root_cert(root_dn, root_key, not_before: nil, not_after: nil)
    cert = generate_cert(root_dn, root_key, 1, not_before: not_before, not_after: not_after)
    ef = OpenSSL::X509::ExtensionFactory.new
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.sign(root_key, 'sha256')
    cert
  end

  def generate_cert(subject, key, serial, issuer: nil, not_before: nil, not_after: nil)
    cert = OpenSSL::X509::Certificate.new
    issuer ||= cert
    cert.version = 2
    cert.serial = serial
    cert.subject = subject
    cert.issuer = issuer.subject
    cert.public_key = key
    now = Time.now
    cert.not_before = not_before || (now - 3600)
    cert.not_after = not_after || (now + 3600)
    cert
  end

  def issue_crl(revocations, issuer:, issuer_key:, last_update: nil, next_update: nil)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    now = Time.now
    crl.last_update = last_update || (now - 3600)
    crl.next_update = next_update || (now + 3600)

    revocations.each do |rserial, time, reason_code|
      revoked = build_revoked(rserial, time, reason_code)
      crl.add_revoked(revoked)
    end

    crlnum = OpenSSL::ASN1::Integer(1)
    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', crlnum))

    crl.sign(issuer_key, 'sha256')
    crl
  end

  def build_revoked(rserial, time, reason_code)
    revoked = OpenSSL::X509::Revoked.new
    revoked.serial = rserial
    revoked.time = time
    enum = OpenSSL::ASN1::Enumerated(reason_code)
    ext = OpenSSL::X509::Extension.new('CRLReason', enum)
    revoked.add_extension(ext)
    revoked
  end
end
