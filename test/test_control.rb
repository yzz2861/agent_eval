require_relative 'test_helper'

class TestLDAPControl < Test::Unit::TestCase
  # Decode a BER controls field the way the library receives one on the
  # wire and hand it to a PDU so result-control parsing is exercised.
  def pdu_with_controls(app_tag, code, *controls)
    result = Net::BER::BerIdentifiedArray.new([code, "", ""])
    result.ber_identifier = app_tag
    field = controls.to_ber_contextspecific(0).read_ber(Net::LDAP::AsnSyntax)
    Net::LDAP::PDU.new([1, result, field])
  end

  def read_entry_control(oid, dn, attributes)
    attrs = attributes.map do |name, values|
      [name.to_s.to_ber, Array(values).map(&:to_ber).to_ber_set].to_ber_sequence
    end
    value = [dn.to_ber, attrs.to_ber_sequence].to_ber_sequence.to_s.to_ber
    [oid.to_ber, true.to_ber, value].to_ber_sequence
  end

  def test_requested_normalizes_assertion_as_critical_filter
    request = Net::LDAP::Control.requested(
      :assertion => Net::LDAP::Filter.eq("uid", "user1"))

    assert_equal [Net::LDAP::Control::AssertionOid], request.keys
    assert request[Net::LDAP::Control::AssertionOid][:critical]
    assert_instance_of Net::LDAP::Filter,
                       request[Net::LDAP::Control::AssertionOid][:filter]
  end

  def test_requested_accepts_filter_string
    request = Net::LDAP::Control.requested(:assertion => "(uid=user1)")
    filter = request[Net::LDAP::Control::AssertionOid][:filter]
    assert_instance_of Net::LDAP::Filter, filter
    assert_equal "(uid=user1)", filter.to_s
  end

  def test_requested_normalizes_read_options
    request = Net::LDAP::Control.requested(
      :pre_read => true,
      :post_read => [:cn, :mail])

    assert_equal [], request[Net::LDAP::Control::PreReadOid][:attributes]
    assert request[Net::LDAP::Control::PreReadOid][:critical]
    assert_equal ["cn", "mail"],
                 request[Net::LDAP::Control::PostReadOid][:attributes]
  end

  def test_requested_read_option_allows_non_critical
    request = Net::LDAP::Control.requested(
      :pre_read => { :attributes => [:cn], :critical => false })
    option = request[Net::LDAP::Control::PreReadOid]
    assert_equal ["cn"], option[:attributes]
    refute option[:critical]
  end

  def test_post_read_is_rejected_for_delete
    request = Net::LDAP::Control.requested(:post_read => true)
    assert_raise(Net::LDAP::ControlError) do
      Net::LDAP::Control.validate_for_operation!(request, :delete)
    end
  end

  def test_post_read_is_allowed_for_modify_and_rename
    request = Net::LDAP::Control.requested(:post_read => true)
    assert_nothing_raised do
      Net::LDAP::Control.validate_for_operation!(request, :modify)
      Net::LDAP::Control.validate_for_operation!(request, :rename)
    end
  end

  def test_pre_read_and_assertion_allowed_for_all_writes
    request = Net::LDAP::Control.requested(
      :assertion => Net::LDAP::Filter.present("objectclass"),
      :pre_read => true)
    assert_nothing_raised do
      [:modify, :rename, :delete].each do |operation|
        Net::LDAP::Control.validate_for_operation!(request, operation)
      end
    end
  end

  def test_assertion_control_is_encoded_critical_with_filter_value
    filter = Net::LDAP::Filter.eq("uid", "user1")
    request = Net::LDAP::Control.requested(:assertion => filter)
    field = Net::LDAP::Control.encode_controls(request).read_ber(Net::LDAP::AsnSyntax)

    assert_equal 1, field.length
    oid, criticality, value = field.first
    assert_equal Net::LDAP::Control::AssertionOid, oid
    assert_equal true, criticality
    # controlValue is an OCTET STRING wrapping the BER filter.
    decoded_filter = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal ["uid", "user1"], decoded_filter
  end

  def test_read_entry_control_lists_requested_attributes
    request = Net::LDAP::Control.requested(:pre_read => [:cn, :mail])
    field = Net::LDAP::Control.encode_controls(request).read_ber(Net::LDAP::AsnSyntax)
    oid, criticality, value = field.first
    assert_equal Net::LDAP::Control::PreReadOid, oid
    assert_equal true, criticality
    assert_equal ["cn", "mail"], value.read_ber(Net::LDAP::AsnSyntax)
  end

  def test_no_controls_encodes_to_nil
    assert_nil Net::LDAP::Control.encode_controls({})
  end

  def test_pdu_exposes_assertion_failure
    pdu = pdu_with_controls(Net::LDAP::PDU::ModifyResponse,
                            Net::LDAP::ResultCodeAssertionFailed)
    assert pdu.assertion_failed?
    refute pdu.success?
  end

  def test_pdu_decodes_pre_and_post_read_entries
    pre = read_entry_control(Net::LDAP::Control::PreReadOid,
                             "uid=user1,dc=example,dc=org",
                             :cn => "before")
    post = read_entry_control(Net::LDAP::Control::PostReadOid,
                              "uid=user1,dc=example,dc=org",
                              :cn => "after")
    pdu = pdu_with_controls(Net::LDAP::PDU::ModifyResponse,
                            Net::LDAP::ResultCodeSuccess, pre, post)

    assert_equal ["before"], pdu.pre_read_entry.cn
    assert_equal ["after"], pdu.post_read_entry.cn
  end

  def test_pdu_preserves_binary_attribute_values
    binary = "\xff\xd8\xff\x00".force_encoding(Encoding::BINARY)
    control = read_entry_control(Net::LDAP::Control::PostReadOid,
                                 "uid=user1,dc=example,dc=org",
                                 :jpegPhoto => binary)
    pdu = pdu_with_controls(Net::LDAP::PDU::ModifyResponse,
                            Net::LDAP::ResultCodeSuccess, control)

    value = pdu.post_read_entry.jpegPhoto.first
    assert_equal Encoding::BINARY, value.encoding
    assert_equal binary.b, value
  end

  def test_pdu_preserves_multiple_response_controls
    pre = read_entry_control(Net::LDAP::Control::PreReadOid,
                             "uid=user1,dc=example,dc=org", :cn => "a")
    extra = ["9.9.9.9".to_ber, true.to_ber, "x".to_ber].to_ber_sequence
    pdu = pdu_with_controls(Net::LDAP::PDU::DeleteResponse,
                            Net::LDAP::ResultCodeSuccess, pre, extra)

    assert_equal 2, pdu.result_controls.length
    assert_equal ["a"], pdu.pre_read_entry.cn
    assert_equal "9.9.9.9", pdu.result_controls.last.oid
  end

  def test_missing_critical_control_on_success_raises
    request = Net::LDAP::Control.requested(:pre_read => true)
    pdu = pdu_with_controls(Net::LDAP::PDU::ModifyResponse,
                            Net::LDAP::ResultCodeSuccess)
    assert_raise(Net::LDAP::CriticalControlMissingError) do
      Net::LDAP::Control.verify_response!(request, pdu)
    end
  end

  def test_missing_non_critical_control_on_success_is_ok
    request = Net::LDAP::Control.requested(
      :pre_read => { :attributes => [:cn], :critical => false })
    pdu = pdu_with_controls(Net::LDAP::PDU::ModifyResponse,
                            Net::LDAP::ResultCodeSuccess)
    assert_nothing_raised do
      Net::LDAP::Control.verify_response!(request, pdu)
    end
  end

  def test_missing_control_on_failure_is_not_verified
    request = Net::LDAP::Control.requested(:pre_read => true)
    pdu = pdu_with_controls(Net::LDAP::PDU::ModifyResponse,
                            Net::LDAP::ResultCodeUnavailableCriticalExtension)
    assert_nothing_raised do
      Net::LDAP::Control.verify_response!(request, pdu)
    end
  end
end
