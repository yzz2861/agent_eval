# -*- ruby encoding: utf-8 -*-

# Encoding and decoding helpers for the entry-guarding and read-entry LDAP
# controls:
#
# - RFC 4528: the Assertion Control (1.3.6.1.1.12).  Its value is a
#   BER-encoded Search Filter that the server evaluates against the target
#   entry atomically with the operation.
# - RFC 4527: the Pre-Read (1.3.6.1.1.13.1) and Post-Read
#   (1.3.6.1.1.13.2) controls.  The request value lists the attributes to
#   return; the response value contains the entry as read immediately
#   before or after the operation.
class Net::LDAP::Control
  AssertionOid = "1.3.6.1.1.12"   # RFC 4528
  PreReadOid   = "1.3.6.1.1.13.1" # RFC 4527
  PostReadOid  = "1.3.6.1.1.13.2" # RFC 4527

  # RFC 4527 section 3.2: post-read is only attached to add/compare/
  # modify/modifyDN/search requests (and entry-containing extended
  # operations).  Of the operations extended here, delete must reject it.
  # Pre-read and assertion are legal on all three write operations.
  UnsupportedOperations = {
    PostReadOid => [:delete],
  }.freeze

  class << self
    # Internal: Normalize the supported keyword options used by #modify,
    # #rename, and #delete into a Hash keyed by control OID.  Returns an
    # empty hash when nothing was requested.
    #
    # :assertion :: a Net::LDAP::Filter or a filter string.  Always sent
    #               as critical (required by RFC 4528).
    # :pre_read ::  true, an attribute name, or an Array of attribute
    #               names.  An Array may be wrapped in a Hash as
    #               {:attributes => [...], :critical => false}.
    # :post_read :: same shape as :pre_read.
    def requested(args)
      controls = {}

      if args[:assertion]
        filter = args[:assertion]
        filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
        controls[AssertionOid] = { :filter => filter, :critical => true }
      end

      if option = read_option(args[:pre_read])
        controls[PreReadOid] = option
      end

      if option = read_option(args[:post_read])
        controls[PostReadOid] = option
      end

      controls
    end

    # Internal: Validate that every requested control is permitted for the
    # given operation (:modify, :rename, or :delete).  Raises
    # Net::LDAP::ControlError before any request is sent when a control is
    # not allowed for the operation.
    def validate_for_operation!(controls, operation)
      UnsupportedOperations.each do |oid, operations|
        if controls.key?(oid) && operations.include?(operation)
          raise Net::LDAP::ControlError,
                "control #{oid} is not permitted on #{operation} operations"
        end
      end
    end

    # Internal: Encode the requested controls plus any caller-supplied
    # pre-encoded controls into the BER controls field (context [0]) used
    # by the write requests.  Returns nil when there are no controls at
    # all.
    def encode_controls(requested, extra = nil)
      encoded = Array(extra).dup

      requested.each do |oid, option|
        encoded << encode(oid, option)
      end

      return nil if encoded.empty?
      encoded.to_ber_contextspecific(0)
    end

    # Internal: After the response is received, ensure every control that
    # was requested as critical and that the server returns on success is
    # actually present.  A successful operation missing a critical
    # read-entry response means the server did not honor the guarantee,
    # so the caller must not mistake it for an unconditional write.
    def verify_response!(requested, response_pdu)
      return if response_pdu.result_code != Net::LDAP::ResultCodeSuccess

      returned = response_pdu.result_controls
      requested.each do |oid, option|
        next unless option.fetch(:critical, true)
        # RFC 4528 carries no assertion response control; its effect is
        # reported solely through the operation's result code.
        next if oid == AssertionOid
        unless returned.any? { |control| control.oid == oid }
          raise Net::LDAP::CriticalControlMissingError,
                "server did not return critical control #{oid}"
        end
      end
    end

    # Internal: Decode a pre-read or post-read response control value into
    # a Net::LDAP::Entry.  Returns nil when the control carries no value.
    def read_entry(control)
      return nil unless control && control.value

      sequence = control.value.read_ber(Net::LDAP::AsnSyntax)
      entry = Net::LDAP::Entry.new(sequence[0])
      sequence[1].each do |attribute, values|
        entry[attribute] = values
      end
      entry
    end

    private

    # Internal: Encode one supported control.
    def encode(oid, option)
      case oid
      when AssertionOid
        # RFC 4528: the controlValue is the BER encoding of a Filter,
        # wrapped in an OCTET STRING.
        [
          oid.to_ber,
          true.to_ber,
          option[:filter].to_ber.to_ber_bin,
        ].to_ber_sequence
      when PreReadOid, PostReadOid
        attributes = Array(option[:attributes])
        value = attributes.map { |attribute| attribute.to_s.to_ber }
                            .to_ber_sequence.to_s.to_ber
        [
          oid.to_ber,
          option.fetch(:critical, true).to_ber,
          value,
        ].to_ber_sequence
      else
        raise Net::LDAP::ControlError, "unknown control #{oid}"
      end
    end

    # Internal: Normalize a :pre_read / :post_read option value.
    def read_option(value)
      return nil if value.nil? || value == false

      case value
      when Hash
        critical = value.fetch(:critical, true)
        attributes = value[:attributes] || value[:attribute] || []
        { :attributes => Array(attributes).map(&:to_s), :critical => critical }
      when Array
        { :attributes => value.map(&:to_s), :critical => true }
      when true
        # An empty attribute selection requests all user attributes.
        { :attributes => [], :critical => true }
      else
        { :attributes => Array(value).map(&:to_s), :critical => true }
      end
    end
  end
end
