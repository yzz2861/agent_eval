# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'time'

class TestResolvDNSSEC < Test::Unit::TestCase
  KEY_BLOB = [
    '03010001dd3e0e30075e70cbe23f5eb42e29f6181bd907eb4ef657f721b75e5ec',
    '42ec1bf50c7729b09bcfa913b0f13c45343294f647104ecea483c7d89aeda078',
    '0d73f60d04e6ec95f4c13ef4e579a3e7d109931265eb8ac4b07c9f2d0f529e87',
    '27dae63e15b3de7347f942c08f9ec788f813ff9c7bb94edc54fef1fa56a1c956',
    'eba5eab'
  ].join.freeze

  SIGNATURE = [
    'da4759156e5a95e3e8e244553390d530081a8a02f3f093efa11acb3533e11c56',
    'cd19f38b657f436582bcfa42b55f3629880f3bbd8bcc9185260601fa84121e62',
    '4cc36159f112031780de5507228d7f99c77e8e9922e4660f1f99547f18ad5d7d',
    '7e484549bfdff746781d40ab9ceace8136fcceb3905713542cc968a332abc177'
  ].join.freeze

  SIGNED_DATA = [
    '0001080200000e1070dbd8805e0be10001f60161076578616d706c6500',
    '012a0161076578616d706c65000001000100000e100004c0000201',
    '012a0161076578616d706c65000001000100000e100004c0000202'
  ].join.freeze

  INCEPTION = Time.utc(2020, 1, 1).to_i
  EXPIRATION = Time.utc(2030, 1, 1).to_i
  CURRENT_TIME = Time.utc(2025, 1, 1)

  def setup
    @dnssec = Resolv::DNS::DNSSEC
    @rrset = valid_rrset
    @rrsig = valid_rrsig_tuple
    @dnskey = valid_dnskey_tuple
  end

  def test_verify_signed_wildcard_rrset
    assert_equal true, @dnssec.verify_rrset(@rrset, @rrsig, @dnskey, CURRENT_TIME)
  end

  def test_signed_data_uses_canonical_names_original_ttl_and_rdata_order
    rrsig = @rrsig.last
    owner = @dnssec.send(:canonical_wildcard_owner, @rrset.first.first, rrsig)
    signed_data = @dnssec.send(:build_signed_data, @rrset, rrsig, owner)

    assert_equal [SIGNED_DATA].pack('H*'), signed_data.b
  end

  def test_canonical_rdata_names_are_lowercase_and_uncompressed
    target = Resolv::DNS::Name.create('TARGET.Example.')
    resource = Resolv::DNS::Resource::IN::CNAME.new(target)
    owner = Resolv::DNS::Name.create('Foo.Example.')

    rr = @dnssec.send(:build_canonical_rr, owner, 3600, resource)

    assert_equal "\x03foo\x07example\x00".b, rr.byteslice(0, 13)
    assert_equal "\x06target\x07example\x00".b, rr.byteslice(23, 16)
    assert_not_match(/[\xc0-\xff][\x00-\xff]/n, rr)
  end

  def test_records_are_sorted_for_signature
    assert_equal true, @dnssec.verify_rrset(@rrset.reverse, @rrsig, @dnskey, CURRENT_TIME)
  end

  def test_owner_name_is_case_insensitive
    rrset = valid_rrset(owner: 'foo.a.example.')
    assert_equal true, @dnssec.verify_rrset(rrset, @rrsig, @dnskey, CURRENT_TIME)
  end

  def test_original_ttl_is_used_instead_of_rrset_ttl
    rrset = @rrset.map do |name, _ttl, resource|
      [name, 1, resource]
    end
    assert_equal true, @dnssec.verify_rrset(rrset, @rrsig, @dnskey, CURRENT_TIME)
  end

  def test_validity_boundaries_are_inclusive
    assert_equal true, @dnssec.verify_rrset(@rrset, @rrsig, @dnskey, Time.at(INCEPTION))
    assert_equal true, @dnssec.verify_rrset(@rrset, @rrsig, @dnskey, Time.at(EXPIRATION))
  end

  def test_expired_signature
    assert_raise(@dnssec::ExpiredSignature) do
      @dnssec.verify_rrset(@rrset, @rrsig, @dnskey, Time.at(EXPIRATION + 1))
    end
  end

  def test_signature_not_yet_valid
    assert_raise(@dnssec::SignatureNotYetValid) do
      @dnssec.verify_rrset(@rrset, @rrsig, @dnskey, Time.at(INCEPTION - 1))
    end
  end

  def test_unsupported_rrsig_algorithm
    rrsig = rrsig_tuple(algorithm: 7)
    dnskey = dnskey_tuple(algorithm: 7)
    assert_raise(@dnssec::UnsupportedAlgorithm) do
      @dnssec.verify_rrset(@rrset, rrsig, dnskey, CURRENT_TIME)
    end
  end

  def test_algorithm_mismatch
    dnskey = dnskey_tuple(algorithm: 7)
    assert_raise(@dnssec::SignatureMismatch) do
      @dnssec.verify_rrset(@rrset, @rrsig, dnskey, CURRENT_TIME)
    end
  end

  def test_key_tag_mismatch
    rrsig = rrsig_tuple(key_tag: 503)
    assert_raise(@dnssec::SignatureMismatch) do
      @dnssec.verify_rrset(@rrset, rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_dnskey_protocol_must_be_3
    dnskey = dnskey_tuple(protocol: 2)
    assert_invalid_signature(@rrset, @rrsig, dnskey)
  end

  def test_empty_dnskey_key_blob
    dnskey = dnskey_tuple(key: ''.b)
    assert_invalid_signature(@rrset, @rrsig, dnskey)
  end

  def test_tampered_record_rdata
    @rrset.each_index do |index|
      rrset = tamper_rrset(@rrset, index) do |name, ttl, _resource|
        [name, ttl, Resolv::DNS::Resource::IN::A.new(Resolv::IPv4.new("\xc0\x00\x02\x03"))]
      end
      assert_invalid_signature(rrset, @rrsig, @dnskey)
    end
  end

  def test_tampered_record_owner
    rrset = tamper_rrset(@rrset) {|_name, ttl, resource| ['bar.a.example.', ttl, resource] }
    assert_raise(@dnssec::MalformedRRset) do
      @dnssec.verify_rrset(rrset, @rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_tampered_record_type
    rrset = tamper_rrset(@rrset) do |name, ttl, _resource|
      [name, ttl, Resolv::DNS::Resource::IN::AAAA.new(Resolv::IPv6.new("\x00".b * 16))]
    end
    assert_raise(@dnssec::MalformedRRset) do
      @dnssec.verify_rrset(rrset, @rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_tampered_record_class
    resource_class = Class.new(Resolv::DNS::Resource::Generic) do
      const_set(:TypeValue, 1)
      const_set(:ClassValue, 3)
    end
    rrset = tamper_rrset(@rrset) do |name, ttl, _resource|
      [name, ttl, resource_class.new("\xc0\x00\x02\x01")]
    end
    assert_raise(@dnssec::MalformedRRset) do
      @dnssec.verify_rrset(rrset, @rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_tampered_original_ttl
    rrsig = rrsig_tuple(original_ttl: 3599)
    assert_invalid_signature(@rrset, rrsig, @dnskey)
  end

  def test_tampered_signer_name
    rrsig = rrsig_tuple(signer: 'example.')
    assert_raise(@dnssec::MalformedRRset) do
      @dnssec.verify_rrset(@rrset, rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_tampered_labels
    rrsig = rrsig_tuple(labels: 3)
    assert_raise(@dnssec::MalformedRRset) do
      @dnssec.verify_rrset(@rrset, rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_tampered_type_covered
    rrsig = rrsig_tuple(type_covered: 28)
    assert_raise(@dnssec::SignatureMismatch) do
      @dnssec.verify_rrset(@rrset, rrsig, @dnskey, CURRENT_TIME)
    end
  end

  def test_tampered_signature
    signature = [SIGNATURE].pack('H*')
    byte_index = signature.bytesize / 2
    signature.setbyte(byte_index, signature.getbyte(byte_index) ^ 1)
    rrsig = rrsig_tuple(signature: signature)
    assert_invalid_signature(@rrset, rrsig, @dnskey)
  end

  def test_tampered_dnskey_key_blob
    key = [KEY_BLOB].pack('H*')
    key.setbyte(4, key.getbyte(4) ^ 1)
    dnskey = dnskey_tuple(key: key)
    assert_raise(@dnssec::SignatureMismatch) do
      @dnssec.verify_rrset(@rrset, @rrsig, dnskey, CURRENT_TIME)
    end
  end

  def test_rrsig_and_dnskey_message_roundtrip
    message = Resolv::DNS::Message.new
    message.add_answer(*@rrsig)
    message.add_answer(*@dnskey)

    decoded = Resolv::DNS::Message.decode(message.encode)

    rrsig = decoded.answer[0].last
    dnskey = decoded.answer[1].last
    assert_kind_of Resolv::DNS::Resource::IN::RRSIG, rrsig
    assert_kind_of Resolv::DNS::Resource::IN::DNSKEY, dnskey
    assert_equal 8, rrsig.algorithm
    assert_equal 'a.example', rrsig.signer.to_s
    assert_equal @dnskey.last.key_tag, dnskey.key_tag
  end

  private

  def assert_invalid_signature(rrset, rrsig, dnskey)
    assert_raise(@dnssec::SignatureMismatch) do
      @dnssec.verify_rrset(rrset, rrsig, dnskey, CURRENT_TIME)
    end
  end

  def tamper_rrset(rrset, index = rrset.length / 2)
    rrset.each_with_index.map do |record, current_index|
      current_index == index ? yield(*record) : record
    end
  end

  def valid_rrset(owner: 'FOO.a.Example.')
    [
      [
        Resolv::DNS::Name.create(owner), 7200,
        Resolv::DNS::Resource::IN::A.new(Resolv::IPv4.new("\xc0\x00\x02\x02"))
      ],
      [
        Resolv::DNS::Name.create('foo.a.example.'), 100,
        Resolv::DNS::Resource::IN::A.new(Resolv::IPv4.new("\xc0\x00\x02\x01"))
      ]
    ]
  end

  def valid_rrsig_tuple
    rrsig_tuple
  end

  def rrsig_tuple(type_covered: 1,
                  algorithm: 8,
                  labels: 2,
                  original_ttl: 3600,
                  expiration: EXPIRATION,
                  inception: INCEPTION,
                  key_tag: 502,
                  signer: 'a.example.',
                  signature: [SIGNATURE].pack('H*'))
    resource = Resolv::DNS::Resource::IN::RRSIG.new(
      type_covered, algorithm, labels, original_ttl,
      expiration, inception, key_tag, signer, signature
    )
    ['foo.a.example.', 300, resource]
  end

  def valid_dnskey_tuple
    dnskey_tuple
  end

  def dnskey_tuple(flags: 257, protocol: 3, algorithm: 8, key: [KEY_BLOB].pack('H*'))
    resource = Resolv::DNS::Resource::IN::DNSKEY.new(flags, protocol, algorithm, key)
    ['a.example.', 3600, resource]
  end
end
