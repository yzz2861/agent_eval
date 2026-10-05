# frozen_string_literal: true
require 'test/unit'
require 'resolv/dnssec'
require 'time'
require 'ipaddr'

class TestResolvDNSSEC < Test::Unit::TestCase
  DNSSEC = Resolv::DNS::DNSSEC
  IN = Resolv::DNS::Resource::IN

  DNSKEY_RDATA = [
    "0100030803010001a0df7b73382ec2f867b99b032559a3d50f5eb213165859a7" \
    "0e02302b0e2308b9e9d0e124707513d656095bec6232820167f542e414a24d3" \
    "9163150274804d8e5fca61cd0adf23390d36f424b1f7559e7e0ce6920b3ae3" \
    "82ef9baa6dc9d8511e4729cd0e50f91e1c9618dacfe39ea87a4711b480d8b4" \
    "e7762fd7da092d119d5d5"
  ].join

  RRSIG_RDATA = [
    "0001080200000e1070dbd8805e0be100fffd076578616d706c65003e4aa469" \
    "f70fd360a3b04eaad5664660b9374f969f2683b5a1fb11251b2621c747af6b" \
    "ebefb4edd0ac8cf5d7e4fafa2d356b4bbc583aa5542ef4a6ba89ade610323a" \
    "3d7bfa6e79280ad5a7da3037ce81c7eff302fcff7b02390f286226deccf820" \
    "4462fcd2c96b1dd7601be72aa522b517cf2e8ce39347b4e047e5d5e6f34528"
  ].join

  SIGNED_DATA = [
    "0001080200000e1070dbd8805e0be100fffd076578616d706c650005686f73" \
    "7433076578616d706c65000001000100000e100004c000020105686f737433" \
    "076578616d706c65000001000100000e100004c000020205686f7374330765" \
    "78616d706c65000001000100000e100004c0000203"
  ].join

  WILDCARD_RRSIG_RDATA = [
    "0001080200000e1070dbd8805e0be100fffd076578616d706c650037f90b7c" \
    "b0af5b93179860fa55aada9a036e12f07de8fb86616f83b8d0e23f09eb37c" \
    "b3a572f4fb6cc083aeeb3732904eafeea940b767be11d916a696d719d8d28e" \
    "feb430fadf52ef22ee588894eec0d175b23c8020fca45dc124ee490dc5e5ee" \
    "72074f0fdd7ce5b49f6af302a63735fe6b7476f0aa6179f19d3cd6d38b84b35"
  ].join

  WILDCARD_SIGNED_DATA = [
    "0001080200000e1070dbd8805e0be100fffd076578616d706c6500012a0373" \
    "7562076578616d706c65000001000100000e100004c6336407012a03737562" \
    "076578616d706c65000001000100000e100004c6336408"
  ].join

  def hex(value)
    [value].pack('H*')
  end

  def ip(address)
    IPAddr.new(address).hton
  end

  def record(name, address, ttl: 3600)
    DNSSEC::Record.new(name, IN::A::TypeValue, DNSSEC::CLASS_IN, ttl, ip(address))
  end

  def base_rrset(addresses = %w[192.0.2.3 192.0.2.1 192.0.2.2],
                 name: 'HOST3.Example.')
    records = addresses.map.with_index {|address, index|
      record(name, address, ttl: index.zero? ? 300 : 600)
    }
    DNSSEC::RRset.new(name, IN::A::TypeValue, DNSSEC::CLASS_IN, records)
  end

  def verify(rrset = base_rrset, rrsig: RRSIG_RDATA, dnskey: DNSKEY_RDATA,
             time: Time.utc(2025, 1, 1))
    DNSSEC.verify_rrset(rrset: rrset, rrsig: hex(rrsig), dnskey: hex(dnskey), time: time)
  end

  def verify_raw(rrset, rrsig, dnskey = hex(DNSKEY_RDATA), time: Time.utc(2025, 1, 1), owner: nil)
    rrsig = {rdata: rrsig}
    rrsig[:owner] = owner if owner
    DNSSEC.verify_rrset(rrset: rrset, rrsig: rrsig, dnskey: dnskey, time: time)
  end

  def test_rsasha256_fixed_vector_sorts_and_canonicalizes
    result = verify

    assert_predicate(result, :valid?)
    assert_not_predicate(result, :trusted?)
    assert_equal(hex(SIGNED_DATA), result.signed_data)
    assert_match(/not asserted as trusted/, result.message)
  end

  def test_input_order_does_not_affect_signed_data
    rrset = base_rrset(%w[192.0.2.2 192.0.2.3 192.0.2.1])

    assert_predicate(verify(rrset), :valid?)
  end

  def test_encodable_resource_rdata_is_canonicalized
    resource = IN::A.new('192.0.2.4')
    rrset = DNSSEC::RRset.new(
      'host4.example.',
      IN::A::TypeValue,
      DNSSEC::CLASS_IN,
      [DNSSEC::Record.new('host4.example.', IN::A::TypeValue, DNSSEC::CLASS_IN, 3600, resource)]
    )
    rrsig = DNSSEC::RRSIG.new(
      IN::A::TypeValue,
      8,
      2,
      3600,
      1893456000,
      1577836800,
      65533,
      Resolv::DNS::Name.create('example.'),
      nil,
      nil
    )
    signed_data = DNSSEC.build_signed_data(rrset, rrsig)
    assert_include(signed_data, IPAddr.new('192.0.2.4').hton)
  end

  def test_wildcard_label_is_reconstructed_before_signing
    rrset = DNSSEC::RRset.new(
      'RANDOM.Sub.Example.',
      IN::A::TypeValue,
      DNSSEC::CLASS_IN,
      [
        record('RANDOM.Sub.Example.', '198.51.100.7'),
        record('random.sub.example.', '198.51.100.8')
      ]
    )
    result = verify_raw(rrset, hex(WILDCARD_RRSIG_RDATA), owner: '*.sub.example.')

    assert_predicate(result, :valid?)
    assert_equal(hex(WILDCARD_SIGNED_DATA), result.signed_data)
    assert_include(result.signed_data, hex('012a03737562076578616d706c6500'))
  end

  def test_original_ttl_replaces_current_record_ttl
    rrset = base_rrset
    rrset.records.each {|entry| entry.ttl = 1 }

    result = verify(rrset)
    assert_predicate(result, :valid?)
    assert_equal(hex('00000e10'), result_ttl_field(result))
  end

  def test_each_changed_record_makes_signature_invalid
    %w[192.0.2.23 192.0.2.21 192.0.2.32].each.with_index do |address, index|
      addresses = %w[192.0.2.3 192.0.2.1 192.0.2.2]
      addresses[index] = address
      result = verify(base_rrset(addresses))

      assert_equal(:invalid_signature, result.status)
      assert_match(/does not match/, result.reason)
    end
  end

  def test_owner_name_case_change_preserves_canonical_match
    rrset = base_rrset(%w[192.0.2.3 192.0.2.1 192.0.2.2], name: 'host3.EXAMPLE.')

    assert_predicate(verify(rrset), :valid?)
  end

  def test_signer_name_case_change_preserves_canonical_match
    rrsig = hex(RRSIG_RDATA)
    rrsig[19..25] = 'EXAMPLE'

    result = DNSSEC.verify_rrset(
      rrset: base_rrset,
      rrsig: rrsig,
      dnskey: hex(DNSKEY_RDATA),
      time: Time.utc(2025, 1, 1)
    )
    assert_predicate(result, :valid?)
  end

  def test_expired_and_future_times_are_distinct
    assert_equal(:expired, verify(time: Time.utc(2030, 1, 1, 0, 0, 1)).status)
    assert_equal(:not_yet_valid, verify(time: Time.utc(2019, 1, 1)).status)
  end

  def test_validity_interval_is_inclusive
    assert_predicate(verify(time: Time.at(1577836800)), :valid?)
    assert_predicate(verify(time: Time.at(1893456000)), :valid?)
  end

  def test_unsupported_algorithm
    rrsig = mutated_rrsig {|bytes| bytes[2] = 10.chr }
    dnskey = hex(DNSKEY_RDATA)
    dnskey[3] = 10.chr
    result = DNSSEC.verify_rrset(rrset: base_rrset, rrsig: rrsig, dnskey: dnskey,
                                 time: Time.utc(2025, 1, 1))

    assert_equal(:unsupported_algorithm, result.status)
    assert_match(/RSASHA256/, result.reason)
  end

  def test_algorithm_mismatch
    dnskey = hex(DNSKEY_RDATA)
    dnskey[3] = 10.chr
    result = DNSSEC.verify_rrset(rrset: base_rrset, rrsig: hex(RRSIG_RDATA),
                                 dnskey: dnskey, time: Time.utc(2025, 1, 1))

    assert_equal(:algorithm_mismatch, result.status)
  end

  def test_key_tag_mismatch
    dnskey = hex(DNSKEY_RDATA)
    dnskey.setbyte(10, dnskey.getbyte(10) ^ 1)
    result = DNSSEC.verify_rrset(rrset: base_rrset, rrsig: hex(RRSIG_RDATA),
                                 dnskey: dnskey, time: Time.utc(2025, 1, 1))

    assert_equal(:key_tag_mismatch, result.status)
  end

  def test_type_covered_mismatch
    rrsig = mutated_rrsig {|bytes| bytes[0..1] = [28].pack('n') }
    result = DNSSEC.verify_rrset(rrset: base_rrset, rrsig: rrsig,
                                 dnskey: hex(DNSKEY_RDATA), time: Time.utc(2025, 1, 1))

    assert_equal(:type_mismatch, result.status)
  end

  def test_malformed_rrsig_is_a_validation_error
    assert_raise_with_message(DNSSEC::ValidationError, /malformed RRSIG/) do
      verify(rrsig: '00' * 18 + '076578616d706c65')
    end
  end

  def test_compressed_signer_name_is_rejected
    assert_raise_with_message(DNSSEC::ValidationError, /compressed signer/) do
      verify(rrsig: '00' * 18 + 'c000')
    end
  end

  def test_relative_signer_is_a_validation_error
    rrsig = DNSSEC::RRSIG.new(
      1, 8, 2, 3600, 1893456000, 1577836800, 65533,
      Resolv::DNS::Name.create('example'), 'sig', nil
    )

    assert_raise_with_message(DNSSEC::ValidationError, /absolute/) do
      DNSSEC.verify_rrset(rrset: base_rrset, rrsig: rrsig, dnskey: hex(DNSKEY_RDATA),
                          time: Time.utc(2025, 1, 1))
    end
  end

  def test_wildcard_labels_cannot_skip_multiple_labels
    rrsig = hex(WILDCARD_RRSIG_RDATA)
    rrsig.setbyte(3, 0)

    assert_raise_with_message(DNSSEC::ValidationError, /does not match/) do
      rrset = DNSSEC::RRset.new(
        'random.sub.example.',
        IN::A::TypeValue,
        DNSSEC::CLASS_IN,
        [record('random.sub.example.', '198.51.100.7')]
      )
      verify_raw(rrset, rrsig)
    end
  end

  def test_explicit_wildcard_owner_must_match_rrset_suffix
    rrset = DNSSEC::RRset.new(
      'random.sub.example.',
      IN::A::TypeValue,
      DNSSEC::CLASS_IN,
      [record('random.sub.example.', '198.51.100.7')]
    )

    assert_raise_with_message(DNSSEC::ValidationError, /wildcard owner/) do
      verify_raw(rrset, hex(WILDCARD_RRSIG_RDATA), owner: '*.other.example.')
    end
  end

  def test_duplicate_records_are_invalid
    assert_raise_with_message(DNSSEC::ValidationError, /duplicate records/) do
      verify(base_rrset(%w[192.0.2.1 192.0.2.1 192.0.2.2]))
    end
  end

  def test_non_absolute_names_are_rejected
    rrset = base_rrset
    rrset.name = 'host3.example'

    assert_raise_with_message(DNSSEC::ValidationError, /absolute/) do
      verify(rrset)
    end
  end

  def result_ttl_field(result)
    result.signed_data.byteslice(46, 4)
  end

  def mutated_rrsig
    bytes = hex(RRSIG_RDATA).dup
    yield bytes
    bytes
  end
end
