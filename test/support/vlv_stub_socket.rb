# -*- ruby encoding: utf-8 -*-
require 'stringio'

# Scripted socket that serves pre-built LDAP PDUs to a Connection while
# recording every packet written, so VLV tests can inspect the controls
# the client put on the wire across multiple search rounds.
class VLVStubSocket
  attr_reader :written

  def initialize(responses)
    # responses is a flat Array of raw BER packets drained one per read.
    @responses = responses
    @written = []
  end

  def write(packet)
    @written << packet
    packet.bytesize
  end

  def read_ber(_syntax = nil)
    packet = @responses.shift
    return nil if packet.nil?
    StringIO.new(packet).read_ber(Net::LDAP::AsnSyntax)
  end

  def close; end

  # BER syntax for VirtualListViewRequest: [0] constructed byOffset,
  # [1] primitive greaterThanOrEqual, plus the universal INTEGER/STRING
  # fields.
  VLV_REQUEST_SYNTAX = Net::BER.compile_syntax(
    :context_specific => {
      :primitive   => { 1 => :string },
      :constructed => { 0 => :array },
    }
  )

  # Builders and inspectors for wire PDUs.
  module Helpers
    module_function

    def entry_pdu(message_id, dn, attributes = {})
      attrs = attributes.map do |name, values|
        [name.to_ber, Array(values).map { |v| v.to_ber }.to_ber_set].to_ber_sequence
      end
      search_entry = [dn.to_ber, attrs.to_ber_sequence]
                      .to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
      [message_id.to_ber, search_entry].to_ber_sequence
    end

    def sort_response_control(result_code = 0, attribute_type = nil,
                              criticality = false)
      value = [result_code.to_ber_enumerated]
      value << attribute_type.to_ber_contextspecific(0) if attribute_type
      [
        Net::LDAP::LDAPControls::SORT_RESPONSE.to_ber,
        criticality.to_ber,
        value.to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence
    end

    def vlv_response_control(target_position, content_count,
                             result_code, context_id = nil,
                             criticality = true)
      value = [
        target_position.to_ber,
        content_count.to_ber,
        result_code.to_ber_enumerated,
      ]
      value << context_id.to_ber_bin if context_id
      [
        Net::LDAP::VLV::VLV_RESPONSE.to_ber,
        criticality.to_ber,
        value.to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence
    end

    def result_pdu(message_id, code, error_message = '', controls = nil)
      result = [code.to_ber_enumerated, ''.to_ber, error_message.to_ber]
               .to_ber_appsequence(Net::LDAP::PDU::SearchResult)
      packet = [message_id.to_ber, result]
      packet << controls if controls
      packet.to_ber_sequence
    end

    def request_controls(packet)
      parsed = StringIO.new(packet).read_ber(Net::LDAP::AsnSyntax)
      controls_ber = parsed[2]
      return [] unless controls_ber
      controls_ber.map do |control|
        oid = control[0]
        criticality = control[1]
        value = control[2]
        if criticality.is_a?(String)
          value = criticality
          criticality = false
        end
        { :oid => oid, :criticality => criticality, :value => value }
      end
    end

    def parse_vlv_request(octet_value)
      # The control value is an OCTET STRING containing a SEQUENCE whose
      # [0]/[1] target choice has no entry in Net::LDAP::AsnSyntax, so
      # decode the inner SEQUENCE with default BER and resolve the raw
      # tags manually.
      seq = StringIO.new(octet_value).read_ber(VLV_REQUEST_SYNTAX)
      data = { :before_count => seq[0], :after_count => seq[1] }
      target = seq[2]
      if target.ber_identifier == 0xa0
        data[:offset] = target[0]
        data[:content_count] = target[1]
      else
        data[:greater_than_or_equal] = target
      end
      data[:context_id] = seq[3] if seq.length > 3
      data
    end

    def find_control(packet, oid)
      request_controls(packet).find { |c| c[:oid] == oid }
    end
  end
end
