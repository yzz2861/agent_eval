# frozen_string_literal: true

RSpec.describe JWT::X5cKeyFinder do
  let(:verification_time) { Time.now }
  let(:root_key) { generate_key }
  let(:intermediate_key) { generate_key }
  let(:leaf_key) { generate_key }
  let(:root_certificate) do
    generate_certificate(1, '/CN=Fake Root', root_key,
                         ca: true, not_before: verification_time - 3600, not_after: verification_time + 3600)
  end
  let(:intermediate_certificate) do
    generate_certificate(2, '/CN=Fake Intermediate', intermediate_key,
                         issuer: root_certificate, issuer_key: root_key,
                         ca: true, not_before: verification_time - 3600, not_after: verification_time + 3600)
  end
  let(:leaf_eku) { nil }
  let(:leaf_key_usage) { nil }
  let(:leaf_critical_extension) { nil }
  let(:leaf_not_before) { verification_time - 3600 }
  let(:leaf_not_after) { verification_time + 3600 }
  let(:leaf_certificate) do
    generate_certificate(
      3,
      '/CN=Fake Leaf',
      leaf_key,
      issuer: intermediate_certificate,
      issuer_key: intermediate_key,
      eku: leaf_eku,
      key_usage: leaf_key_usage,
      critical_extension: leaf_critical_extension,
      not_before: leaf_not_before,
      not_after: leaf_not_after
    )
  end
  let(:root_crl) { issue_crl(root_certificate, root_key) }
  let(:revoked_leaf) { false }
  let(:intermediate_crl) do
    revocations = revoked_leaf ? [[3, verification_time - 60, 1]] : []
    issue_crl(intermediate_certificate, intermediate_key, revocations: revocations)
  end

  let(:chain_certificates) { [leaf_certificate, intermediate_certificate] }
  let(:x5c_header) { chain_certificates.map { |certificate| JWT::Base64.url_encode(certificate.to_der) } }
  let(:crls) { [root_crl, intermediate_crl] }
  let(:trusted_roots) { [root_certificate] }
  let(:finder_options) { {} }

  subject(:key_finder) do
    described_class
      .new(trusted_roots, crls, verification_time: verification_time, **finder_options)
      .from(x5c_header)
  end

  it 'returns the leaf public key after trusted chain verification' do
    expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    expect(key_finder.to_der).to eq(leaf_key.public_key.to_der)
  end

  context 'with already parsed certificates' do
    let(:x5c_header) { chain_certificates }

    it 'accepts a local certificate chain' do
      expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    end
  end

  context 'when the trusted root is included in x5c' do
    let(:chain_certificates) { [leaf_certificate, intermediate_certificate, root_certificate] }

    it 'does not count the trusted root towards the chain depth' do
      finder_options[:max_chain_depth] = 1

      expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    end
  end

  context 'with a self-signed root in the header' do
    let(:untrusted_root_key) { generate_key }
    let(:untrusted_root_certificate) do
      generate_certificate(10, '/CN=Untrusted Root', untrusted_root_key,
                           ca: true, not_before: verification_time - 3600,
                           not_after: verification_time + 3600)
    end
    let(:untrusted_leaf_certificate) do
      generate_certificate(11, '/CN=Untrusted Leaf', leaf_key,
                           issuer: untrusted_root_certificate, issuer_key: untrusted_root_key,
                           not_before: verification_time - 3600,
                           not_after: verification_time + 3600)
    end
    let(:x5c_header) { [untrusted_leaf_certificate, untrusted_root_certificate] }

    it 'does not trust it just because it is present in x5c' do
      expect { key_finder }.to raise_error(
        JWT::VerificationError,
        /self-signed certificate in certificate chain|unable to get local issuer certificate/
      )
    end
  end

  context 'with a direct leaf signed by the trusted root' do
    let(:direct_leaf_certificate) do
      generate_certificate(4, '/CN=Direct Leaf', leaf_key,
                           issuer: root_certificate, issuer_key: root_key,
                           not_before: verification_time - 3600,
                           not_after: verification_time + 3600)
    end
    let(:x5c_header) { [direct_leaf_certificate] }

    it 'allows zero intermediates when the maximum depth is zero' do
      finder_options[:max_chain_depth] = 0

      expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe 'verification time' do
    let(:direct_leaf_certificate) do
      generate_certificate(4, '/CN=Historical Leaf', leaf_key,
                           issuer: historical_root_certificate, issuer_key: root_key,
                           not_before: verification_time - 200,
                           not_after: verification_time + 100)
    end
    let(:historical_root_certificate) do
      generate_certificate(1, '/CN=Historical Root', root_key, ca: true,
                           not_before: verification_time - 300,
                           not_after: verification_time + 200)
    end
    let(:x5c_header) { [direct_leaf_certificate] }
    let(:historical_root_crl) { issue_historical_crl(historical_root_certificate, root_key) }
    let(:trusted_roots) { [historical_root_certificate] }
    let(:crls) { [historical_root_crl] }

    before { finder_options[:time] = verification_time.to_i }

    it 'accepts a numeric timestamp alias' do
      expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe 'extended key usage' do
    let(:leaf_eku) { ['clientAuth'] }

    before { finder_options[:eku] = ['clientAuth'] }

    it 'accepts a matching EKU OID' do
      expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    end

    context 'when the extension contains anyExtendedKeyUsage' do
      let(:leaf_eku) { ['anyExtendedKeyUsage'] }

      it 'accepts the wildcard EKU' do
        expect(key_finder).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when the extension exists but does not match' do
      let(:leaf_eku) { ['serverAuth'] }

      it 'raises an invalid EKU error' do
        expect { key_finder }.to raise_error(JWT::InvalidEkuError, /does not match/)
      end

      context 'when mismatches are allowed' do
        before { finder_options[:allow_mismatched_eku] = true }

        it 'returns the leaf public key' do
          expect(key_finder).to be_a(OpenSSL::PKey::RSA)
        end
      end

      it 'does not treat allowing mismatches as allowing a missing extension' do
        missing_eku_leaf = generate_certificate(
          5,
          '/CN=Missing EKU Leaf',
          leaf_key,
          issuer: intermediate_certificate,
          issuer_key: intermediate_key,
          not_before: verification_time - 3600,
          not_after: verification_time + 3600
        )

        expect do
          described_class.new(
            [root_certificate],
            crls,
            verification_time: verification_time,
            eku: ['clientAuth'],
            allow_mismatched_eku: true
          ).from([missing_eku_leaf, intermediate_certificate])
        end.to raise_error(JWT::MissingEkuError)
      end
    end

    context 'when the extension is missing' do
      let(:leaf_eku) { nil }

      it 'raises a missing EKU error' do
        expect { key_finder }.to raise_error(JWT::MissingEkuError, /missing the required Extended key usage/)
      end

      context 'when a missing extension is allowed' do
        before { finder_options[:allow_missing_eku] = true }

        it 'returns the leaf public key' do
          expect(key_finder).to be_a(OpenSSL::PKey::RSA)
        end

        it 'still rejects an extension that does not match' do
          mismatched_leaf = generate_certificate(
            5,
            '/CN=Server Auth Leaf',
            leaf_key,
            issuer: intermediate_certificate,
            issuer_key: intermediate_key,
            eku: ['serverAuth'],
            not_before: verification_time - 3600,
            not_after: verification_time + 3600
          )

          expect do
            described_class.new(
              [root_certificate],
              crls,
              verification_time: verification_time,
              eku: ['clientAuth'],
              allow_missing_eku: true
            ).from([mismatched_leaf, intermediate_certificate])
          end.to raise_error(JWT::InvalidEkuError)
        end
      end
    end
  end

  describe 'digital signature key usage' do
    before { finder_options[:digital_signature] = true }

    context 'when digitalSignature is present' do
      let(:leaf_key_usage) { 'digitalSignature' }

      it 'returns the leaf public key' do
        expect(key_finder).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when the extension exists but does not allow digitalSignature' do
      let(:leaf_key_usage) { 'keyEncipherment' }

      it 'raises an invalid key usage error' do
        expect { key_finder }.to raise_error(JWT::InvalidKeyUsageError, /does not allow digital signature/)
      end

      context 'when mismatches are allowed' do
        before { finder_options[:allow_mismatched_key_usage] = true }

        it 'returns the leaf public key' do
          expect(key_finder).to be_a(OpenSSL::PKey::RSA)
        end
      end

      it 'does not treat allowing mismatches as allowing a missing extension' do
        missing_key_usage_leaf = generate_certificate(
          6,
          '/CN=Missing Key Usage Leaf',
          leaf_key,
          issuer: intermediate_certificate,
          issuer_key: intermediate_key,
          not_before: verification_time - 3600,
          not_after: verification_time + 3600
        )

        expect do
          described_class.new(
            [root_certificate],
            crls,
            verification_time: verification_time,
            digital_signature: true,
            allow_mismatched_key_usage: true
          ).from([missing_key_usage_leaf, intermediate_certificate])
        end.to raise_error(JWT::MissingKeyUsageError)
      end
    end

    context 'when the extension is missing' do
      it 'raises a missing key usage error' do
        expect { key_finder }.to raise_error(JWT::MissingKeyUsageError, /missing the required Key usage/)
      end

      context 'when a missing extension is allowed' do
        before { finder_options[:allow_missing_key_usage] = true }

        it 'returns the leaf public key' do
          expect(key_finder).to be_a(OpenSSL::PKey::RSA)
        end

        it 'still rejects an extension that does not allow digital signature' do
          mismatched_leaf = generate_certificate(
            6,
            '/CN=Non Signing Leaf',
            leaf_key,
            issuer: intermediate_certificate,
            issuer_key: intermediate_key,
            key_usage: 'keyEncipherment',
            not_before: verification_time - 3600,
            not_after: verification_time + 3600
          )

          expect do
            described_class.new(
              [root_certificate],
              crls,
              verification_time: verification_time,
              digital_signature: true,
              allow_missing_key_usage: true
            ).from([mismatched_leaf, intermediate_certificate])
          end.to raise_error(JWT::InvalidKeyUsageError)
        end
      end
    end
  end

  describe 'maximum chain depth' do
    it 'accepts a chain at the configured depth' do
      finder_options[:max_chain_depth] = 1

      expect(key_finder).to be_a(OpenSSL::PKey::RSA)
    end

    it 'rejects a chain deeper than the configured depth' do
      finder_options[:max_chain_depth] = 0

      expect { key_finder }.to raise_error(JWT::InvalidCertificateChainError, /exceeds maximum 0/)
    end
  end

  describe 'finder configuration' do
    it 'requires a non-negative maximum chain depth' do
      expect do
        described_class.new([root_certificate], max_chain_depth: -1)
      end.to raise_error(ArgumentError, /non-negative integer/)
    end

    it 'requires a time-like verification time' do
      expect do
        described_class.new([root_certificate], verification_time: 'now')
      end.to raise_error(ArgumentError, /Time or numeric timestamp/)
    end
  end

  describe 'certificate chain structure' do
    context 'when certificates are not in leaf-to-root order' do
      let(:x5c_header) { [intermediate_certificate, leaf_certificate] }

      it 'raises a chain order error' do
        expect { key_finder }.to raise_error(JWT::CertificateChainOrderError, /not in leaf-to-root order/)
      end
    end

    context 'when a certificate is duplicated' do
      let(:x5c_header) { [leaf_certificate, intermediate_certificate, intermediate_certificate] }

      it 'raises a duplicate certificate error' do
        expect { key_finder }.to raise_error(JWT::DuplicateCertificateError, /Duplicate certificate/)
      end
    end
  end

  describe 'certificate validity at the caller-supplied time' do
    let(:leaf_not_before) { verification_time - 3600 }
    let(:leaf_not_after) { verification_time - 60 }

    it 'uses the supplied time for leaf expiry' do
      expect { key_finder }.to raise_error(JWT::VerificationError, /certificate has expired/)
    end

    context 'with an expired intermediate' do
      let(:leaf_not_after) { verification_time + 3600 }
      let(:intermediate_certificate) do
        generate_certificate(2, '/CN=Expired Intermediate', intermediate_key,
                             issuer: root_certificate, issuer_key: root_key,
                             ca: true, not_before: verification_time - 7200,
                             not_after: verification_time - 60)
      end

      it 'raises a distinct expired intermediate error' do
        expect { key_finder }.to raise_error(
          JWT::ExpiredIntermediateCertificateError,
          /certificate has expired.*Expired Intermediate/m
        )
      end
    end
  end

  describe 'unsupported critical extensions' do
    let(:leaf_critical_extension) do
      OpenSSL::X509::Extension.new(
        '1.2.3.4.5.6',
        OpenSSL::ASN1::UTF8String.new('unsupported').to_der,
        true
      )
    end

    it 'raises an unsupported critical extension error' do
      expect { key_finder }.to raise_error(JWT::UnsupportedCriticalExtensionError, /unhandled critical extension/)
    end
  end

  describe 'certificate revocation' do
    let(:revoked_leaf) { true }

    it 'rejects a leaf listed in the local CRL' do
      expect { key_finder }.to raise_error(JWT::VerificationError, /certificate revoked/)
    end
  end

  describe '::JWT.decode' do
    let(:encoded_token) do
      JWT.encode({ 'data' => 'something' }, leaf_key, 'RS256', 'x5c' => x5c_header)
    end
    let(:options) do
      {
        algorithms: ['RS256'],
        x5c: {
          root_certificates: [root_certificate],
          crls: crls,
          eku: ['clientAuth'],
          digital_signature: true,
          max_chain_depth: 1,
          verification_time: verification_time
        }
      }
    end

    context 'with a policy-compliant leaf' do
      let(:leaf_eku) { ['clientAuth'] }
      let(:leaf_key_usage) { 'digitalSignature' }

      it 'returns the encoded payload' do
        expect(JWT.decode(encoded_token, nil, true, options).first).to eq('data' => 'something')
      end
    end

    context 'with a non-compliant leaf' do
      it 'passes the policy options through to the x5c key finder' do
        expect { JWT.decode(encoded_token, nil, true, options) }.to raise_error(JWT::MissingEkuError)
      end
    end
  end

  private

  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def generate_certificate(serial, subject_name, public_key,
                           issuer: nil, issuer_key: nil, ca: false,
                           eku: nil, key_usage: nil, critical_extension: nil,
                           not_before: Time.now - 3600, not_after: Time.now + 3600)
    certificate = OpenSSL::X509::Certificate.new
    issuer ||= certificate
    issuer_key ||= public_key
    certificate.version = 2
    certificate.serial = serial
    certificate.subject = OpenSSL::X509::Name.parse(subject_name)
    certificate.issuer = issuer.subject
    certificate.public_key = public_key
    certificate.not_before = not_before
    certificate.not_after = not_after

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = certificate
    factory.issuer_certificate = issuer

    certificate.add_extension(factory.create_extension('basicConstraints', ca ? 'CA:TRUE' : 'CA:FALSE', true))
    certificate.add_extension(factory.create_extension('extendedKeyUsage', Array(eku).join(','), false)) if eku
    certificate.add_extension(factory.create_extension('keyUsage', key_usage, true)) if key_usage
    certificate.add_extension(critical_extension) if critical_extension
    certificate.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    certificate
  end

  def issue_crl(issuer, issuer_key, revocations: [])
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = verification_time - 3600
    crl.next_update = verification_time + 3600
    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(1)))
    revocations.each do |serial, time, reason|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = serial
      revoked.time = time
      revoked.add_extension(OpenSSL::X509::Extension.new('CRLReason', OpenSSL::ASN1::Enumerated(reason)))
      crl.add_revoked(revoked)
    end
    crl.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    crl
  end

  def issue_historical_crl(issuer, issuer_key)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = verification_time - 200
    crl.next_update = verification_time + 100
    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(1)))
    crl.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    crl
  end
end
