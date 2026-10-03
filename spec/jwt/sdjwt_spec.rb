# frozen_string_literal: true

RSpec.describe JWT::SDJWT do
  let(:key) { 'secret' }
  let(:payload) do
    {
      'sub'     => 'user-1',
      'email'   => 'user@example.com',
      'address' => { 'street' => 'Main St 1', 'city' => 'Berlin' },
      'tags'    => %w[admin beta]
    }
  end
  let(:disclose) { [[:email], [:address, :street], [:tags, 1]] }
  let(:issued) do
    described_class.issue(payload, key, algorithm: 'HS256', disclose: disclose)
  end

  describe '.issue' do
    it 'hides the selected claims behind digests' do
      decoded, = JWT.decode(issued.token, key, true, algorithm: 'HS256')

      expect(decoded['sub']).to eq('user-1')
      expect(decoded).not_to have_key('email')
      expect(decoded['_sd']).to be_an(Array)
      expect(decoded['_sd_alg']).to eq('sha-256')
      expect(decoded['address'].keys).to contain_exactly('city', '_sd')
      expect(decoded['address']['city']).to eq('Berlin')
      expect(decoded['tags'][0]).to eq('admin')
      expect(decoded['tags'][1].keys).to eq(['...'])
    end

    it 'creates one disclosure per path' do
      expect(issued.disclosures.length).to eq(3)
    end

    it 'produces different salts for each issuance' do
      other = described_class.issue(payload, key, algorithm: 'HS256', disclose: disclose)
      expect(other.token).not_to eq(issued.token)
    end

    it 'uses the injected random source for salts' do
      random = ->(_n) { 'deterministic-salt' }
      cred   = described_class.issue(payload, key, algorithm: 'HS256', disclose: [[:email]], random: random)

      expect(cred.disclosures.first.salt).to eq(JWT::Base64.url_encode('deterministic-salt'))
    end

    it 'raises for unknown paths' do
      expect do
        described_class.issue(payload, key, algorithm: 'HS256', disclose: [[:unknown]])
      end.to raise_error(JWT::SDJWT::IssuanceError)
    end

    it 'raises for duplicate paths' do
      expect do
        described_class.issue(payload, key, algorithm: 'HS256', disclose: [[:email], ['email']])
      end.to raise_error(JWT::SDJWT::IssuanceError)
    end

    it 'raises for invalid array indices' do
      expect do
        described_class.issue(payload, key, algorithm: 'HS256', disclose: [[:tags, 9]])
      end.to raise_error(JWT::SDJWT::IssuanceError)
    end
  end

  describe '.verify' do
    it 'reconstructs all claims when every disclosure is presented' do
      claims = described_class.verify(issued.presentation, key, algorithm: 'HS256')

      expect(claims).to eq(payload)
    end

    it 'reconstructs only the presented claims on partial disclosure' do
      email_disclosure = issued.disclosures.find { |d| d.name == 'email' }
      claims = described_class.verify(issued.presentation([email_disclosure]), key, algorithm: 'HS256')

      expect(claims['email']).to eq('user@example.com')
      expect(claims['sub']).to eq('user-1')
      expect(claims).not_to have_key('_sd')
      expect(claims).not_to have_key('_sd_alg')
      expect(claims['address']).to eq('city' => 'Berlin')
      expect(claims['tags']).to eq(['admin'])
    end

    it 'keeps everything hidden when no disclosure is presented' do
      claims = described_class.verify(issued.presentation([]), key, algorithm: 'HS256')

      expect(claims.keys).to eq(%w[sub address tags])
      expect(claims['address']).to eq('city' => 'Berlin')
      expect(claims['tags']).to eq(['admin'])
    end

    it 'resolves nested disclosures in order' do
      nested = described_class.issue(payload, key,
                                     algorithm: 'HS256',
                                     disclose: [[:address], [:address, :street]])
      outer = nested.disclosures.find { |d| d.name == 'address' }
      inner = nested.disclosures.find { |d| d.name == 'street' }

      claims = described_class.verify(nested.presentation([outer, inner]), key, algorithm: 'HS256')
      expect(claims['address']).to eq('street' => 'Main St 1', 'city' => 'Berlin')

      claims = described_class.verify(nested.presentation([outer]), key, algorithm: 'HS256')
      expect(claims['address']).to eq('city' => 'Berlin')
    end

    it 'treats an inner disclosure as orphaned when the outer one is missing' do
      nested = described_class.issue(payload, key,
                                     algorithm: 'HS256',
                                     disclose: [[:address], [:address, :street]])
      inner = nested.disclosures.find { |d| d.name == 'street' }

      expect do
        described_class.verify(nested.presentation([inner]), key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::OrphanDisclosureError)
    end

    it 'fails signature verification with the wrong key' do
      expect do
        described_class.verify(issued.presentation, 'wrong', algorithm: 'HS256')
      end.to raise_error(JWT::VerificationError)
    end

    it 'rejects duplicate disclosures' do
      disclosure = issued.disclosures.first
      presentation = issued.presentation([disclosure, disclosure])

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::DuplicateDigestError)
    end

    it 'rejects orphaned disclosures' do
      other = described_class.issue({ 'a' => 1 }, key, algorithm: 'HS256', disclose: [[:a]])
      presentation = ([issued.token] + other.disclosures.map(&:encode)).join('~')

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::OrphanDisclosureError)
    end

    it 'rejects disclosures colliding with plaintext claims' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 'salt', name: 'sub', value: 'attacker')
      presentation = ([issued.token, disclosure.encode]).join('~')

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::OrphanDisclosureError)
    end

    it 'rejects a disclosure whose digest is planted next to a plaintext twin' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 'salt', name: 'sub', value: 'attacker')
      decoded, header = JWT.decode(issued.token, key, true, algorithm: 'HS256')
      decoded['_sd'] = (decoded['_sd'] || []) + [disclosure.digest]
      token = JWT.encode(decoded, key, 'HS256', header)
      presentation = ([token, disclosure.encode]).join('~')

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::ClaimCollisionError)
    end

    it 'rejects duplicate digests in the token' do
      disclosure = issued.disclosures.find { |d| d.name == 'email' }
      decoded, header = JWT.decode(issued.token, key, true, algorithm: 'HS256')
      decoded['_sd'] << disclosure.digest
      token = JWT.encode(decoded, key, 'HS256', header)
      presentation = ([token, disclosure.encode]).join('~')

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::DuplicateDigestError)
    end

    it 'rejects malformed disclosures' do
      presentation = ([issued.token, '!!!not-base64!!!']).join('~')

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::MalformedDisclosureError)
    end

    it 'rejects an object disclosure used for an array element' do
      decoded, header = JWT.decode(issued.token, key, true, algorithm: 'HS256')
      disclosure = JWT::SDJWT::Disclosure.new(salt: 'salt', name: 'evil', value: 'x')
      decoded['tags'][1] = { '...' => disclosure.digest }
      token = JWT.encode(decoded, key, 'HS256', header)
      presentation = ([token, disclosure.encode]).join('~')

      expect do
        described_class.verify(presentation, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::MalformedDisclosureError)
    end

    it 'rejects unsupported digest algorithms' do
      decoded, header = JWT.decode(issued.token, key, true, algorithm: 'HS256')
      decoded['_sd_alg'] = 'sha-512'
      token = JWT.encode(decoded, key, 'HS256', header)

      expect do
        described_class.verify(token, key, algorithm: 'HS256')
      end.to raise_error(JWT::SDJWT::UnsupportedSdAlgError)
    end
  end

  describe 'plain JWT decoding' do
    it 'does not resolve digests or accept the presentation format' do
      decoded, = JWT.decode(issued.token, key, true, algorithm: 'HS256')
      expect(decoded).to have_key('_sd')
      expect(decoded).not_to have_key('email')

      expect do
        JWT.decode(issued.presentation, key, true, algorithm: 'HS256')
      end.to raise_error(JWT::DecodeError)
    end
  end

  describe JWT::SDJWT::Disclosure do
    it 'round-trips through encode and parse' do
      disclosure = described_class.new(salt: 'abc', name: 'email', value: 'a@b.c')
      parsed = described_class.parse(disclosure.encode)

      expect(parsed.salt).to eq('abc')
      expect(parsed.name).to eq('email')
      expect(parsed.value).to eq('a@b.c')
      expect(parsed.digest).to eq(disclosure.digest)
    end

    it 'parses array element disclosures' do
      disclosure = described_class.new(salt: 'abc', value: 'beta')
      parsed = described_class.parse(disclosure.encode)

      expect(parsed).to be_array_element
      expect(parsed.value).to eq('beta')
    end

    it 'rejects structurally invalid disclosures' do
      encoded = JWT::Base64.url_encode(JWT::JSON.generate(%w[only-salt]))
      expect { described_class.parse(encoded) }.to raise_error(JWT::SDJWT::MalformedDisclosureError)
    end
  end
end
