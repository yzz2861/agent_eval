# frozen_string_literal: true

RSpec.describe JWT::SelectiveDisclosure do
  let(:secret) { 'sd-secret' }

  # Deterministic, injectable salt source instead of SecureRandom.
  let(:salts) { %w[salta saltb saltc saltd salte saltf saltg salth].each }
  let(:salt_source) { -> { salts.next } }

  let(:payload) do
    {
      'iss' => 'issuer',
      'name' => 'Ada',
      'email' => 'ada@example.test',
      'address' => { 'city' => 'Shanghai', 'country' => 'CN' },
      'nationalities' => ['CN', 'FR']
    }
  end

  let(:paths) do
    [
      ['name'],
      ['email'],
      ['address', 'city'],
      ['nationalities', 0],
      ['nationalities', 1]
    ]
  end

  let(:issued) do
    described_class.issue(
      payload,
      secret,
      'HS256',
      disclosable_paths: paths,
      salt_source: salt_source
    )
  end

  def signed_payload(issued)
    JWT::JSON.parse(JWT::Base64.url_decode(issued.jwt.split('.')[1]))
  end

  def disclosure_for(issued, key: nil, value: nil)
    issued.disclosures.find { |d| (key && d.key == key) || (value && d.value == value) }
  end

  describe '.issue' do
    it 'replaces selected object fields with sorted digest lists' do
      body = signed_payload(issued)

      expect(body).not_to include('name', 'email')
      expect(body['_sd']).to eq(body['_sd'].sort)
      expect(body['_sd'].size).to eq(2)
      expect(body['_sd_alg']).to eq('sha-256')
      expect(body['address']).not_to include('city')
      expect(body['address']['country']).to eq('CN')
      expect(body['address']['_sd'].size).to eq(1)
    end

    it 'replaces selected array elements with markers and hides the values' do
      body = signed_payload(issued)

      body['nationalities'].each do |element|
        expect(element).to match('...' => a_string_matching(/\A[A-Za-z0-9_-]+\z/))
      end
      expect(issued.to_s).not_to include('FR')
    end

    it 'marks the JWT as an SD token in the header' do
      header = JWT::JSON.parse(JWT::Base64.url_decode(issued.jwt.split('.')[0]))
      expect(header['typ']).to eq('sd+jwt')
      expect(header['alg']).to eq('HS256')
    end

    it 'uses the injected salt source and keeps sha-256 digests' do
      disclosure = issued.disclosures.find { |d| d.key == 'name' }

      expect(disclosure.salt).to eq('salta')
      expected = JWT::Base64.url_encode(
        OpenSSL::Digest.digest('SHA256', disclosure.encoded)
      )
      expect(disclosure.digest).to eq(expected)
      expect(signed_payload(issued)['_sd']).to include(disclosure.digest)
    end

    it 'issues different salts/salts by default through secure randomness' do
      first = described_class.issue(payload, secret, 'HS256', disclosable_paths: [['name']])
      second = described_class.issue(payload, secret, 'HS256', disclosable_paths: [['name']])

      expect(first.disclosures.first.salt).not_to eq(second.disclosures.first.salt)
      expect(first.jwt).not_to eq(second.jwt)
    end

    it 'encodes disclosures as compact ASCII-only JSON arrays' do
      encoded = disclosure_for(issued, key: 'name').encoded
      decoded = JWT::Base64.url_decode(encoded)

      expect(JWT::JSON.parse(decoded)).to eq(['salta', 'name', 'Ada'])
      expect(decoded.bytes).to all(be <= 127)
    end

    it 'rejects a non-hash payload' do
      expect { described_class.issue([], secret) }.to raise_error(JWT::EncodeError)
    end

    it 'rejects unknown or out of range disclosure paths' do
      expect do
        described_class.issue(payload, secret, disclosable_paths: [['unknown']], salt_source: salt_source)
      end.to raise_error(JWT::InvalidDisclosurePath)

      expect do
        described_class.issue(payload, secret, disclosable_paths: [['nationalities', 9]], salt_source: salt_source)
      end.to raise_error(JWT::InvalidDisclosurePath)
    end

    it 'rejects nested and duplicate disclosure paths' do
      expect do
        described_class.issue(payload, secret, disclosable_paths: [['address'], ['address', 'city']], salt_source: salt_source)
      end.to raise_error(JWT::InvalidDisclosurePath, /overlaps/)

      expect do
        described_class.issue(payload, secret, disclosable_paths: [['name'], ['name']], salt_source: salt_source)
      end.to raise_error(JWT::InvalidDisclosurePath, /Duplicate/)
    end

    it 'rejects payloads already using reserved marker names' do
      expect do
        described_class.issue({ '_sd' => [] }, secret)
      end.to raise_error(JWT::EncodeError)

      expect do
        described_class.issue({ 'items' => [{ '...' => 'x' }] }, secret)
      end.to raise_error(JWT::EncodeError)
    end

    it 'can disclose a whole nested object or array element verbatim' do
      whole = described_class.issue(
        payload,
        secret,
        disclosable_paths: [['address'], ['nationalities', 1]],
        salt_source: salt_source
      )
      result = described_class.verify(whole.to_s, secret, 'HS256')

      expect(result.claims).to include(payload)
    end
  end

  describe 'holder presentation' do
    it 'attaches only the selected disclosures' do
      presentation = issued.present(disclosure_for(issued, key: 'name'))

      expect(presentation).to end_with('~')
      expect(presentation).to include(disclosure_for(issued, key: 'name').encoded)
      expect(presentation).not_to include(disclosure_for(issued, key: 'email').encoded)
    end

    it 'supports a zero-disclosure presentation' do
      presentation = issued.present

      result = described_class.verify(presentation, secret, 'HS256')
      expect(result.claims).to eq(
        'iss' => 'issuer',
        'address' => { 'country' => 'CN' },
        'nationalities' => []
      )
    end

    it 'cannot present a disclosure from another token' do
      other = described_class.issue({ 'name' => 'Bob' }, secret, disclosable_paths: [['name']], salt_source: salt_source)

      expect { issued.present(other.disclosures.first) }.to raise_error(JWT::InvalidDisclosure)
    end
  end

  describe '.verify' do
    it 'reconstructs only the presented claims after signature verification' do
      presentation = issued.present(
        disclosure_for(issued, key: 'name'),
        disclosure_for(issued, value: 'FR')
      )

      result = described_class.verify(presentation, secret, 'HS256')

      expect(result.claims).to eq(
        'iss' => 'issuer',
        'address' => { 'country' => 'CN' },
        'nationalities' => ['FR'],
        'name' => 'Ada'
      )
      expect(result.disclosed_keys).to eq(['name'])
      expect(result.header['typ']).to eq('sd+jwt')
    end

    it 'reconstructs everything when all disclosures are presented' do
      result = described_class.verify(issued.to_s, secret, 'HS256')
      expect(result.claims).to eq(payload)
    end

    it 'rejects a wrong signature' do
      expect do
        described_class.verify(issued.to_s, 'wrong', 'HS256')
      end.to raise_error(JWT::VerificationError)
    end

    it 'rejects a signed payload altered after issuance' do
      header, _payload, signature = issued.jwt.split('.')
      tampered_payload = JWT::Base64.url_encode(JWT::JSON.generate('iss' => 'issuer', 'admin' => true, '_sd_alg' => 'sha-256'))
      forged = [header, tampered_payload, signature].join('.') + '~'

      expect { described_class.verify(forged, secret) }.to raise_error(JWT::VerificationError)
    end

    it 'does not accept ordinary JWTs automatically' do
      plain = JWT.encode(payload, secret, 'HS256')

      expect { described_class.verify(plain, secret, 'HS256') }
        .to raise_error(JWT::MalformedSDToken)
      expect { JWT.decode(issued.to_s, secret, true, algorithm: 'HS256') }
        .to raise_error(JWT::Error)
    end

    it 'rejects malformed containers' do
      aggregate_failures do
        expect { described_class.verify('', secret) }.to raise_error(JWT::MalformedSDToken)
        expect { described_class.verify('not-a-jwt~', secret) }.to raise_error(JWT::MalformedSDToken)
        expect { described_class.verify(issued.jwt, secret) }.to raise_error(JWT::MalformedSDToken)
        expect { described_class.verify("#{issued.jwt}~~", secret) }.to raise_error(JWT::MalformedSDToken)
        expect { described_class.verify('a.b~d~', secret) }.to raise_error(JWT::MalformedSDToken)
      end
    end

    it 'rejects malformed marker structures even without disclosures' do
      bad_sd = signed_payload(issued)
      bad_sd['_sd'] = 'not-an-array'
      bad_marker = signed_payload(issued)
      bad_marker['nationalities'] = [{ '...' => 123 }]

      expect { described_class.verify(resign(bad_sd), secret) }.to raise_error(JWT::MalformedSDToken)
      expect { described_class.verify(resign(bad_marker), secret) }.to raise_error(JWT::MalformedSDToken)
    end

    it 'rejects a wrong or absent sd header/algorithm marker' do
      plain = JWT.encode(signed_payload(issued), secret, 'HS256')
      expect { described_class.verify("#{plain}~", secret) }
        .to raise_error(JWT::MalformedSDToken, /typ/)

      body = signed_payload(issued).tap { |b| b['_sd_alg'] = 'sha-512' }
      expect { described_class.verify(resign(body), secret) }
        .to raise_error(JWT::MalformedSDToken, /sha-256/)
    end

    it 'rejects malformed or tampered disclosures' do
      good = disclosure_for(issued, key: 'name').encoded
      tampered = JWT::Base64.url_encode(JSON.generate(['salta', 'name', 'ATTACKER']))
      bad_json = JWT::Base64.url_encode('not-json')

      expect { described_class.verify("#{issued.jwt}~#{tampered}~", secret) }
        .to raise_error(JWT::OrphanDisclosure)
      expect { described_class.verify("#{issued.jwt}~#{bad_json}~", secret) }
        .to raise_error(JWT::InvalidDisclosure)
      expect { described_class.verify("#{issued.jwt}~@@@@~", secret) }
        .to raise_error(JWT::InvalidDisclosure)
      expect(good).not_to eq(tampered)
    end

    it 'accepts non-canonical transport bytes that re-encode to the same disclosure' do
      disclosure = disclosure_for(issued, key: 'name')
      spaced_json = ' [ "salta" , "name" , "Ada" ] '
      transport = JWT::Base64.url_encode(spaced_json)

      # The digest the issuer anchored is over the canonical encoding, and the
      # verifier re-canonicalises before hashing.
      expect(transport).not_to eq(disclosure.encoded)
      result = described_class.verify("#{issued.jwt}~#{transport}~", secret)
      expect(result.claims['name']).to eq('Ada')
    end

    it 'rejects duplicate digests anchored in the signed payload' do
      body = signed_payload(issued)
      body['_sd'] = [body['_sd'].first, body['_sd'].first]
      forged = resign(body)

      expect { described_class.verify(forged, secret) }
        .to raise_error(JWT::DuplicateDigest, /anchored more than once/)
    end

    it 'rejects the same disclosure presented twice' do
      disclosure = disclosure_for(issued, key: 'name')
      presentation = "#{issued.jwt}~#{disclosure.encoded}~#{disclosure.encoded}~"

      expect { described_class.verify(presentation, secret) }
        .to raise_error(JWT::DuplicateDigest, /presented more than once/)
    end

    it 'rejects duplicate disclosures already when building a presentation' do
      disclosure = disclosure_for(issued, key: 'name')

      expect { issued.present(disclosure, disclosure) }
        .to raise_error(JWT::DuplicateDigest)
    end

    it 'rejects orphan disclosures after reconstruction' do
      extra = JWT::SelectiveDisclosure::Disclosure.create(salt: 'x', key: 'ssn', value: '123')
      presentation = "#{issued.jwt}~#{extra.encoded}~"

      expect { described_class.verify(presentation, secret) }
        .to raise_error(JWT::OrphanDisclosure)
    end

    it 'rejects a disclosed key colliding with a visible claim' do
      body = signed_payload(issued)
      disclosure = JWT::SelectiveDisclosure::Disclosure.create(salt: 'x', key: 'iss', value: 'forged')
      body['_sd'] << disclosure.digest
      forged = resign(body, [disclosure])

      expect { described_class.verify(forged, secret) }
        .to raise_error(JWT::DisclosureCollision)
    end

    it 'rejects property/array digest kind mismatches' do
      body = signed_payload(issued)
      array_digest = body['nationalities'].first['...']
      body['_sd'] = [array_digest]
      body['nationalities'] = []
      disclosure = issued.disclosures.find { |d| d.digest == array_digest }
      forged = resign(body, [disclosure])

      expect { described_class.verify(forged, secret) }
        .to raise_error(JWT::InvalidDisclosure, /matched an object digest/)
    end

    it 'rejects object digests used as array element markers' do
      body = signed_payload(issued)
      name_digest = body['_sd'].find { |digest| digest == disclosure_for(issued, key: 'name').digest }
      body['nationalities'] = [{ '...' => name_digest }]
      body['_sd'] = []
      disclosure = disclosure_for(issued, key: 'name')
      forged = resign(body, [disclosure])

      expect { described_class.verify(forged, secret) }
        .to raise_error(JWT::InvalidDisclosure, /matched an array element digest/)
    end

    it 'handles nested disclosures regardless of presentation order' do
      # Whole address object is one disclosure whose value itself contains a
      # digest anchor for the city. Build it manually to reorder disclosures.
      city = JWT::SelectiveDisclosure::Disclosure.create(
        salt: 'inner', key: 'city', value: 'Shanghai'
      )
      address = JWT::SelectiveDisclosure::Disclosure.create(
        salt: 'outer',
        key: 'address',
        value: { 'country' => 'CN', '_sd' => [city.digest] }
      )
      body = signed_payload(issued)
      body.delete('address')
      body['_sd'] = (body['_sd'] + [address.digest]).sort
      body.delete('nationalities')

      # Child (city) is presented before its parent (address).
      token = resign(body, [city, address])
      result = described_class.verify(token, secret)

      expect(result.claims['address']).to eq('country' => 'CN', 'city' => 'Shanghai')
    end

    it 'verifies registered claims through decode options' do
      expiring = described_class.issue(
        payload.merge('exp' => Time.now.to_i - 10),
        secret,
        'HS256',
        disclosable_paths: [['name']],
        salt_source: salt_source
      )

      expect { described_class.verify(expiring.to_s, secret, 'HS256') }
        .to raise_error(JWT::ExpiredSignature)
    end

    def resign(body, disclosures = [])
      headers = { 'typ' => 'sd+jwt' }
      jwt = JWT.encode(body, secret, 'HS256', headers)
      JWT::SelectiveDisclosure::Serializer.serialize(jwt: jwt, disclosures: disclosures)
    end
  end

  describe JWT::SelectiveDisclosure::Disclosure do
    it 'round trips property and array element disclosures' do
      property = JWT::SelectiveDisclosure::Disclosure.create(salt: 's', key: 'k', value: 'v')
      element = JWT::SelectiveDisclosure::Disclosure.create(salt: 's', value: 42)

      expect(property.property?).to be(true)
      expect(element.array_element?).to be(true)
      expect(JWT::SelectiveDisclosure::Disclosure.from_encoded(property.encoded).to_a).to eq(['s', 'k', 'v'])
      expect(JWT::SelectiveDisclosure::Disclosure.from_encoded(element.encoded).value).to eq(42)
    end
  end
end
