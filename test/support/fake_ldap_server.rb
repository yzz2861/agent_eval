# -*- ruby encoding: utf-8 -*-
# A tiny in-process LDAP server used by the entry-guarding control tests.
# It speaks just enough BER to accept modify/modifyDN/delete requests with
# RFC 4528/4527 controls, and keeps the whole exchange on a single socket
# pair so the client never performs (and can be asserted not to perform)
# a separate search round trip.
class FakeLDAPServer
  ASSERTION_OID    = "1.3.6.1.1.12"
  PRE_READ_OID     = "1.3.6.1.1.13.1"
  POST_READ_OID    = "1.3.6.1.1.13.2"

  MODIFY_REQUEST   = 6
  DELETE_REQUEST   = 10
  MODIFY_RDN_REQUEST = 12

  MODIFY_RESPONSE   = 7
  DELETE_RESPONSE   = 11
  MODIFY_RDN_RESPONSE = 13

  SUCCESS                     = 0
  ASSERTION_FAILED            = 122
  UNAVAILABLE_CRITICAL_EXT   = 12

  Syntax = Net::BER.compile_syntax(
    :application => {
      :primitive   => { DELETE_REQUEST => :string },
      :constructed => { MODIFY_REQUEST => :array,
                        MODIFY_RDN_REQUEST => :array },
    },
    :context_specific => {
      :primitive   => { 0 => :string, 7 => :string },
      :constructed => { 0 => :array, 2 => :array, 3 => :array,
                        4 => :array },
    },
  )

  # Records every application tag the server receives. The tests assert no
  # SearchRequest (3) ever appears.
  attr_reader :received_tags

  def initialize(entries)
    @entries = deep_copy(entries)
    @received_tags = []
    @mutex = Mutex.new
  end

  # Run one session on the given socket pair, then close the server side.
  def serve(client_socket, server_socket)
    @socket = server_socket
    @client = client_socket
    @thread = Thread.new do
      begin
        while pdu = @socket.read_ber(Syntax)
          handle(pdu)
        end
      rescue IOError, Errno::EPIPE
        # client closed
      ensure
        server_socket.close rescue nil
      end
    end
  end

  # Test hook: mutate an entry while the client is blocked inside its
  # write request. There is no search round trip, so this simulates the
  # entry changing strictly between the client's UI read and the atomic
  # server-side assertion evaluation.
  def mutate_after_request(dn, &block)
    @mutation = [dn, block]
  end

  def join
    @thread.join
  end

  private

  def handle(pdu)
    message_id = pdu[0]
    app = pdu[1]
    tag = app.ber_identifier & 0x1f
    @mutex.synchronize { @received_tags << tag }

    controls = parse_controls(pdu[2])

    case tag
    when MODIFY_REQUEST
      handle_modify(message_id, app, controls)
    when MODIFY_RDN_REQUEST
      handle_rename(message_id, app, controls)
    when DELETE_REQUEST
      handle_delete(message_id, app, controls)
    end
  end

  def handle_modify(message_id, request, controls)
    dn = request[0]
    respond_write(message_id, MODIFY_RESPONSE, dn, controls) do
      apply_modify(dn, request[1])
    end
  end

  def handle_rename(message_id, request, controls)
    dn = request[0]
    new_rdn = request[1]
    new_dn = "#{new_rdn},#{parent_dn(dn)}"
    respond_write(message_id, MODIFY_RDN_RESPONSE, dn, controls, new_dn) do
      if (entry = @entries.delete(dn))
        @entries[new_dn] = entry
      end
    end
  end

  def handle_delete(message_id, request, controls)
    dn = request
    respond_write(message_id, DELETE_RESPONSE, dn, controls) do
      @entries.delete(dn)
    end
  end

  # Shared pre-read / assertion / mutation / apply / post-read ordering,
  # exactly as a real server evaluates RFC 4525/4527/4528 controls.
  def respond_write(message_id, response_tag, dn, controls, post_dn = dn)
    pre_control = controls[PRE_READ_OID]
    post_control = controls[POST_READ_OID]
    assertion = controls[ASSERTION_OID]

    unsupported = controls.any? do |oid, control|
      oid == POST_READ_OID && response_tag == DELETE_RESPONSE &&
        control[:critical]
    end
    if unsupported
      return send_result(message_id, response_tag,
                         UNAVAILABLE_CRITICAL_EXT, dn, "")
    end

    # Simulate another client committing a change after any client-side
    # UI read but before this request is processed atomically on the
    # server. Pre-read and the assertion therefore observe the new state.
    if @mutation && @mutation[0] == dn
      _dn, block = @mutation
      block.call(@entries)
    end

    # The server-side snapshot used by pre-read and the assertion.
    before = deep_copy(@entries[dn] || {})

    if assertion && !matches?(dn, assertion[:filter], before)
      return send_result(message_id, response_tag,
                         ASSERTION_FAILED, dn,
                         "assertion failed",
                         controls_for(dn, pre_control, nil, before, {}, dn))
    end

    yield

    after = deep_copy(@entries[post_dn] || {})
    response_controls = controls_for(dn, pre_control, post_control,
                                     before, after, post_dn)
    send_result(message_id, response_tag, SUCCESS, dn, "", response_controls)
  end

  def controls_for(dn, pre_control, post_control, before = nil, after = nil,
                   post_dn = dn)
    response = []
    response << read_control(PRE_READ_OID, dn, before, pre_control[:selection]) if pre_control
    response << read_control(POST_READ_OID, post_dn, after,
                             post_control[:selection]) if post_control
    response
  end

  def read_control(oid, dn, attributes, selection)
    attributes ||= {}
    selected = if selection.empty?
                 attributes.reject { |name, _| name == "objectclass" }
               else
                 attributes.select { |name, _| selection.include?(name) }
               end
    value = entry_value(dn, selected)
    [oid.to_ber, true.to_ber, value].to_ber_sequence
  end

  def entry_value(dn, attributes)
    attr_sequence = attributes.map do |name, values|
      [name.to_ber, Array(values).map(&:to_ber_bin).to_ber_set].to_ber_sequence
    end
    [dn.to_ber, attr_sequence.to_ber_sequence].to_ber_sequence.to_s.to_ber
  end

  def send_result(message_id, app_tag, code, matched_dn, message, controls = [])
    result = [code.to_ber_enumerated,
              matched_dn.to_ber,
              message.to_ber].to_ber_appsequence(app_tag)
    controls_field = controls.empty? ? nil : controls.to_ber_contextspecific(0)
    packet = [message_id.to_ber, result, controls_field].compact.to_ber_sequence
    @socket.write(packet)
  end

  # Only the filter shapes the tests use are needed: present (0x87),
  # equality (0xA3), and a single AND (0xA0) of equalities.
  def matches?(dn, filter_ber, attributes)
    tag = filter_ber.respond_to?(:ber_identifier) ? filter_ber.ber_identifier : 0xa3
    case tag
    when 0x87
      attributes.key?(filter_ber.to_s)
    when 0xa3
      name, value = filter_ber
      Array(attributes[name]).include?(value)
    when 0xa0
      filter_ber.all? { |part| matches?(dn, part, attributes) }
    else
      false
    end
  end

  def apply_modify(dn, operations)
    entry = @entries[dn] ||= {}
    operations.each do |opcode, (name, values)|
      case opcode
      when 0 # add
        entry[name] = Array(entry[name]) + values
      when 1 # delete
        if values.empty?
          entry.delete(name)
        else
          entry[name] = Array(entry[name]) - values
        end
      when 2 # replace
        entry[name] = values
      end
    end
  end

  def parse_controls(field)
    (field || []).each_with_object({}) do |control, hash|
      oid, criticality, value = control
      if criticality.is_a?(String)
        value = criticality
        criticality = false
      end
      next unless value

      data = { :critical => criticality == true, :value => value }
      if [PRE_READ_OID, POST_READ_OID].include?(oid)
        data[:selection] = value.read_ber(Syntax)
      elsif oid == ASSERTION_OID
        data[:filter] = value.read_ber(Syntax)
      end
      hash[oid] = data
    end
  end

  def parent_dn(dn)
    dn.split(",", 2).last
  end

  def deep_copy(object)
    Marshal.load(Marshal.dump(object))
  end
end
