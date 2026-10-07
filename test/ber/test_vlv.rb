# -*- ruby encoding: utf-8 -*-
require_relative '../test_helper'

class TestBERVLV < Test::Unit::TestCase
  # VirtualListViewRequest byOffset, no contextID:
  #   beforeCount=2, afterCount=3, offset=50 (0x32), contentCount=100 (0x64)
  BY_OFFSET_NO_CONTEXT =
    "\x30\x0e" \
    "\x02\x01\x02" \
    "\x02\x01\x03" \
    "\xa0\x06\x02\x01\x32\x02\x01\x64".b

  # Same request with contextID "CTX" (0x43 0x54 0x58).
  BY_OFFSET_WITH_CONTEXT =
    "\x30\x13" \
    "\x02\x01\x02" \
    "\x02\x01\x03" \
    "\xa0\x06\x02\x01\x32\x02\x01\x64" \
    "\x04\x03CTX".b

  # greaterThanOrEqual "Smith" (5 bytes), before=0, after=9.
  BY_VALUE_SMITH =
    "\x30\x0d" \
    "\x02\x01\x00" \
    "\x02\x01\x09" \
    "\x81\x05Smith".b

  # VLV response: targetPosition=52, contentCount=215 (0x00d7),
  # virtualListViewResult=0, contextID="CTX2".
  VLV_RESPONSE_BYTES =
    "\x30\x10" \
    "\x02\x01\x34" \
    "\x02\x02\x00\xd7" \
    "\x0a\x01\x00" \
    "\x04\x04CTX2".b

  # Sort result success.
  SORT_RESPONSE_SUCCESS = "\x30\x03\x0a\x01\x00".b

  # Sort result noSuchAttribute(16) attributeType "bogusattr".
  SORT_RESPONSE_NO_ATTR =
    "\x30\x0f" \
    "\x0a\x01\x10" \
    "\x80\x09bogusattr".b

  def test_encode_request_value_by_offset_no_context
    value = Net::LDAP::VLV.encode_request_value(
      2, 3, { :offset => 50, :content_count => 100 }, nil)
    # The control value is an OCTET STRING wrapping the SEQUENCE.
    assert_equal "\x04\x10".b + BY_OFFSET_NO_CONTEXT, value
  end

  def test_encode_request_value_by_offset_with_context
    value = Net::LDAP::VLV.encode_request_value(
      2, 3, { :offset => 50, :content_count => 100 }, "CTX".b)
    assert_equal "\x04\x15".b + BY_OFFSET_WITH_CONTEXT, value
  end

  def test_encode_request_value_by_greater_than_or_equal
    value = Net::LDAP::VLV.encode_request_value(
      0, 9, { :greater_than_or_equal => "Smith" }, nil)
    assert_equal "\x04\x0f".b + BY_VALUE_SMITH, value
  end

  def test_request_value_bytes_round_trip_by_offset
    inner = Net::LDAP::VLV.encode_request_value(
      2, 3, { :offset => 50, :content_count => 100 }, "CTX".b)
    sequence = inner.read_ber
    assert_equal BY_OFFSET_WITH_CONTEXT, sequence
    # The default BER syntax has no rule for the [0] constructed choice,
    # so locate it by its raw tag byte.
    target_start = sequence.index("\xa0".b)
    refute_nil target_start
    assert_equal 0xa0, sequence.bytes[target_start]
  end

  def test_encode_request_control_is_critical_by_default
    control = Net::LDAP::VLV.encode_request_control(
      0, 0, { :offset => 1, :content_count => 0 }, nil)
    parsed = control.read_ber(Net::LDAP::AsnSyntax)
    assert_equal Net::LDAP::VLV::VLV_REQUEST, parsed[0]
    assert_equal true, parsed[1]
  end

  def test_encode_request_control_non_critical
    control = Net::LDAP::VLV.encode_request_control(
      0, 0, { :offset => 1, :content_count => 0 }, nil, false)
    parsed = control.read_ber(Net::LDAP::AsnSyntax)
    assert_equal false, parsed[1]
  end

  def test_encode_sort_control_is_critical_for_vlv
    control = Net::LDAP::VLV.encode_sort_control("sn", true)
    parsed = control.read_ber(Net::LDAP::AsnSyntax)
    assert_equal Net::LDAP::LDAPControls::SORT_REQUEST, parsed[0]
    assert_equal true, parsed[1]
  end

  def test_encode_sort_control_simple_attribute_bytes
    control = Net::LDAP::VLV.encode_sort_control("cn", false)
    parsed = control.read_ber(Net::LDAP::AsnSyntax)
    assert_equal false, parsed[1]
    inner = parsed[2].read_ber
    assert_equal [["cn"]], inner
  end

  def test_encode_sort_control_reverse_order_and_matching_rule
    control = Net::LDAP::VLV.encode_sort_control(
      [['sn', 'caseExactOrderingMatch', true]], true)
    parsed = control.read_ber(Net::LDAP::AsnSyntax)
    inner = parsed[2].read_ber(Net::LDAP::VLV::ResponseSyntax)
    key = inner[0]
    assert_equal 'sn', key[0]
    assert_equal 0x80, key[1].ber_identifier
    assert_equal 'caseExactOrderingMatch', key[1]
    assert_equal true, key[2]
  end

  def test_parse_vlv_response_bytes
    data = Net::LDAP::VLV.parse_response(VLV_RESPONSE_BYTES)
    assert_equal 52, data[:target_position]
    assert_equal 215, data[:content_count]
    assert_equal 0, data[:result_code]
    assert_equal 'CTX2', data[:context_id]
  end

  def test_parse_vlv_response_without_context_id
    bytes = "\x30\x0b\x02\x01\x01\x02\x01\x05\x0a\x01\x00".b
    data = Net::LDAP::VLV.parse_response(bytes)
    assert_equal 1, data[:target_position]
    assert_equal 5, data[:content_count]
    assert_nil data[:context_id]
  end

  def test_parse_sort_response_success_bytes
    data = Net::LDAP::VLV.parse_sort_response(SORT_RESPONSE_SUCCESS)
    assert_equal 0, data[:result_code]
    assert_nil data[:attribute_type]
  end

  def test_parse_sort_response_no_such_attribute_bytes
    data = Net::LDAP::VLV.parse_sort_response(SORT_RESPONSE_NO_ATTR)
    assert_equal 16, data[:result_code]
    assert_equal 'bogusattr', data[:attribute_type]
  end

  def test_offset_below_one_is_rejected
    assert_raise(ArgumentError) do
      Net::LDAP::VLV.encode_request_value(
        0, 0, { :offset => 0 }, nil)
    end
  end

  def test_missing_target_is_rejected
    assert_raise(ArgumentError) do
      Net::LDAP::VLV.encode_request_value(0, 0, {}, nil)
    end
  end

  def test_malformed_vlv_response_raises
    assert_raise(Net::LDAP::VLV::ResponseError) do
      Net::LDAP::VLV.parse_response("\x02\x01\x01".b)
    end
  end
end
