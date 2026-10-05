# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'socket'
require 'timeout'

class TestResolvDNSUpdate < Test::Unit::TestCase
  Update = Resolv::DNS::Update
  IN = Resolv::DNS::Resource::IN

  def with_udp(host, port)
    u = UDPSocket.new
    u.bind(host, port)
    yield u
  rescue Errno::EPERM, Errno::EACCES, Errno::EADDRNOTAVAIL
    omit 'cannot bind loopback socket in this environment'
  ensure
    u&.close
  end

  def with_tcp(host, port)
    t = TCPServer.new(host, port)
    yield t
  rescue Errno::EPERM, Errno::EACCES, Errno::EADDRNOTAVAIL
    omit 'cannot bind loopback socket in this environment'
  ensure
    t&.close
  end

  def decode(update)
    Resolv::DNS::Message.decode(update.encode)
  end

  # --- header & zone section -------------------------------------------

  def test_header_is_update_with_no_flags
    msg = decode(Update.new('example.org'))
    assert_equal(0, msg.qr)
    assert_equal(Resolv::DNS::OpCode::Update, msg.opcode)
    assert_equal(0, msg.aa)
    assert_equal(0, msg.tc)
    assert_equal(0, msg.rd)
    assert_equal(0, msg.ra)
    assert_equal(0, msg.rcode)
  end

  def test_zone_section_is_single_soa_question
    msg = decode(Update.new('example.org'))
    assert_equal(1, msg.question.length)
    name, typeclass = msg.question[0]
    assert_equal('example.org', name.to_s)
    assert_predicate(name, :absolute?)
    assert_equal(Resolv::DNS::Resource::SOA::TypeValue, typeclass::TypeValue)
    assert_equal(IN::ClassValue, typeclass::ClassValue)
    assert_equal(0, msg.answer.length)
    assert_equal(0, msg.authority.length)
    assert_equal(0, msg.additional.length)
  end

  def test_zone_origin_itself_is_in_zone
    msg = decode(Update.new('example.org').add('example.org', IN::A.new('192.0.2.1')))
    assert_equal(1, msg.authority.length)
  end

  def test_custom_zone_class
    msg = decode(Update.new('example.org', 3))
    _name, typeclass = msg.question[0]
    assert_equal(3, typeclass::ClassValue)
  end

  # --- prerequisites ---------------------------------------------------

  def test_require_name_wire_format
    msg = decode(Update.new('example.org').require_name('www.example.org'))
    assert_equal(1, msg.answer.length)
    name, ttl, data = msg.answer[0]
    assert_equal('www.example.org', name.to_s)
    assert_equal(255, data.class::TypeValue) # TYPE_ANY
    assert_equal(1, data.class::ClassValue)   # zone class
    assert_equal(0, ttl)
  end

  def test_require_no_name_wire_format
    msg = decode(Update.new('example.org').require_no_name('gone.example.org'))
    name, ttl, data = msg.answer[0]
    assert_equal('gone.example.org', name.to_s)
    assert_equal(255, data.class::TypeValue)
    assert_equal(254, data.class::ClassValue) # CLASS_NONE
    assert_equal(0, ttl)
  end

  def test_require_rrset_wire_format
    msg = decode(Update.new('example.org').require_rrset('mx.example.org', IN::MX))
    name, ttl, data = msg.answer[0]
    assert_equal('mx.example.org', name.to_s)
    assert_equal(IN::MX::TypeValue, data.class::TypeValue)
    assert_equal(1, data.class::ClassValue)
    assert_equal(0, ttl)
  end

  def test_require_no_rrset_wire_format
    msg = decode(Update.new('example.org').require_no_rrset('a.example.org', IN::A))
    name, ttl, data = msg.answer[0]
    assert_equal('a.example.org', name.to_s)
    assert_equal(IN::A::TypeValue, data.class::TypeValue)
    assert_equal(254, data.class::ClassValue) # CLASS_NONE
    assert_equal(0, ttl)
  end

  def test_require_record_wire_format_ttl_zero_and_rdata
    update = Update.new('example.org')
    update.require_record('www.example.org', IN::A.new('192.0.2.5'))
    msg = decode(update)
    name, ttl, data = msg.answer[0]
    assert_equal('www.example.org', name.to_s)
    assert_equal(1, data.class::TypeValue)
    assert_equal(1, data.class::ClassValue)
    assert_equal(0, ttl)
    assert_equal('192.0.2.5', data.address.to_s)
  end

  def test_prerequisites_and_updates_land_in_different_sections
    update = Update.new('example.org')
    update.require_rrset('www.example.org', IN::A)
    update.add('www.example.org', IN::A.new('192.0.2.1'))
    msg = decode(update)
    assert_equal(1, msg.answer.length)     # prerequisite
    assert_equal(1, msg.authority.length)  # update
    assert_equal(0, msg.additional.length)
  end

  # --- update operations ----------------------------------------------

  def test_add_wire_format
    update = Update.new('example.org')
    update.add('www.example.org', IN::A.new('192.0.2.2'), ttl: 600)
    name, ttl, data = decode(update).authority[0]
    assert_equal('www.example.org', name.to_s)
    assert_equal(1, data.class::TypeValue)
    assert_equal(1, data.class::ClassValue)
    assert_equal(600, ttl)
    assert_equal('192.0.2.2', data.address.to_s)
  end

  def test_add_applies_default_ttl
    update = Update.new('example.org')
    update.add('www.example.org', IN::A.new('192.0.2.2'))
    _name, ttl, _data = decode(update).authority[0]
    assert_equal(Update::DEFAULT_TTL, ttl)
  end

  def test_add_rejects_zero_ttl
    update = Update.new('example.org')
    assert_raise(ArgumentError) do
      update.add('www.example.org', IN::A.new('192.0.2.2'), ttl: 0)
    end
  end

  def test_add_multiple_records
    update = Update.new('example.org')
    update.add('www.example.org', IN::A.new('192.0.2.2'), IN::A.new('192.0.2.3'), ttl: 100)
    section = decode(update).authority
    assert_equal(2, section.length)
    assert_equal([100, 100], section.map { |_, ttl, _| ttl })
  end

  def test_delete_record_wire_format
    update = Update.new('example.org')
    update.delete_record('www.example.org', IN::A.new('192.0.2.9'))
    name, ttl, data = decode(update).authority[0]
    assert_equal('www.example.org', name.to_s)
    assert_equal(1, data.class::TypeValue)
    assert_equal(1, data.class::ClassValue)
    assert_equal(0, ttl)
    assert_equal('192.0.2.9', data.address.to_s)
  end

  def test_delete_rrset_wire_format
    update = Update.new('example.org')
    update.delete_rrset('old.example.org', IN::AAAA)
    name, ttl, data = decode(update).authority[0]
    assert_equal('old.example.org', name.to_s)
    assert_equal(28, data.class::TypeValue)
    assert_equal(255, data.class::ClassValue) # CLASS_ANY
    assert_equal(0, ttl)
  end

  def test_delete_name_wire_format
    update = Update.new('example.org')
    update.delete_name('dead.example.org')
    name, ttl, data = decode(update).authority[0]
    assert_equal('dead.example.org', name.to_s)
    assert_equal(255, data.class::TypeValue)
    assert_equal(255, data.class::ClassValue)
    assert_equal(0, ttl)
  end

  def test_empty_rdata_records_encode_with_zero_rdlength
    update = Update.new('example.org')
    update.delete_name('dead.example.org')
    wire = update.encode
    # The trailing RR is the delete-name RRset: compressed NAME pointer to
    # the zone origin, then TYPE/CLASS/TTL/RDLENGTH with no RDATA, and it
    # must be the very last thing in the datagram.
    rr = wire[-12..-1]
    pointer, type, klass, ttl, rdlen = rr.unpack('nnnNn')
    assert_equal(0xc00c, pointer)    # zone origin at offset 12
    assert_equal(255, type)
    assert_equal(255, klass)
    assert_equal(0, ttl)
    assert_equal(0, rdlen)
    assert_equal(46, wire.bytesize) # 12 header + 22 zone + 12 empty RR
  end

  # --- validation ------------------------------------------------------

  def test_rejects_names_outside_zone
    update = Update.new('example.org')
    assert_raise(ArgumentError) { update.require_name('example.com') }
    assert_raise(ArgumentError) { update.require_no_name('example.com') }
    assert_raise(ArgumentError) { update.require_rrset('x.example.com', IN::A) }
    assert_raise(ArgumentError) { update.require_no_rrset('x.example.com', IN::A) }
    assert_raise(ArgumentError) { update.require_record('x.example.com', IN::A.new('1.2.3.4')) }
    assert_raise(ArgumentError) { update.add('x.example.com', IN::A.new('1.2.3.4')) }
    assert_raise(ArgumentError) { update.delete_record('x.example.com', IN::A.new('1.2.3.4')) }
    assert_raise(ArgumentError) { update.delete_rrset('x.example.com', IN::A) }
    assert_raise(ArgumentError) { update.delete_name('x.example.com') }
  end

  def test_rejects_meta_classes_in_zone
    assert_raise(ArgumentError) { Update.new('example.org', 254) }
    assert_raise(ArgumentError) { Update.new('example.org', 255) }
    assert_raise(ArgumentError) { Update.new('example.org', 0) }
    assert_raise(ArgumentError) { Update.new('example.org', 256) }
  end

  def test_rejects_any_type_for_rrset_operations
    update = Update.new('example.org')
    assert_raise(ArgumentError) { update.require_rrset('x.example.org', IN::ANY) }
    assert_raise(ArgumentError) { update.require_no_rrset('x.example.org', IN::ANY) }
    assert_raise(ArgumentError) { update.delete_rrset('x.example.org', IN::ANY) }
  end

  def test_rejects_invalid_ttl
    update = Update.new('example.org')
    assert_raise(ArgumentError) { update.add('x.example.org', IN::A.new('1.2.3.4'), ttl: -1) }
    assert_raise(ArgumentError) { update.add('x.example.org', IN::A.new('1.2.3.4'), ttl: 0x100000000) }
    assert_raise(ArgumentError) { update.add('x.example.org', IN::A.new('1.2.3.4'), ttl: '60') }
  end

  def test_rejects_non_resource_in_record_operations
    update = Update.new('example.org')
    assert_raise(ArgumentError) { update.add('x.example.org', '1.2.3.4') }
    assert_raise(ArgumentError) { update.require_record('x.example.org', '1.2.3.4') }
    assert_raise(ArgumentError) { update.delete_record('x.example.org', '1.2.3.4') }
  end

  def test_rejects_add_without_records
    assert_raise(ArgumentError) { Update.new('example.org').add('x.example.org') }
  end

  def test_rejects_record_class_mismatch
    ch_a = Class.new(Resolv::DNS::Resource::Generic)
    ch_a.const_set(:TypeValue, 1)
    ch_a.const_set(:ClassValue, 3) # CHAOS
    record = ch_a.new("\x01\x02\x03\x04".b)
    update = Update.new('example.org')
    assert_raise(ArgumentError) { update.add('x.example.org', record) }
    assert_raise(ArgumentError) { update.require_record('x.example.org', record) }
    assert_raise(ArgumentError) { update.delete_record('x.example.org', record) }
  end

  def test_builder_methods_return_self_for_chaining
    update = Update.new('example.org')
    assert_same(update, update.require_name('a.example.org'))
    assert_same(update, update.require_no_name('b.example.org'))
    assert_same(update, update.require_rrset('c.example.org', IN::A))
    assert_same(update, update.require_no_rrset('d.example.org', IN::A))
    assert_same(update, update.require_record('e.example.org', IN::A.new('1.2.3.4')))
    assert_same(update, update.add('f.example.org', IN::A.new('1.2.3.4')))
    assert_same(update, update.delete_record('g.example.org', IN::A.new('1.2.3.4')))
    assert_same(update, update.delete_rrset('h.example.org', IN::A))
    assert_same(update, update.delete_name('i.example.org'))
  end

  # --- result handling (transport seam, no real sockets) ---------------

  class FakeTransport
    Outcome = Struct.new(:reply, :uncertain, :error)
    def initialize(reply: nil, uncertain: false, error: nil)
      @reply = reply
      @uncertain = uncertain
      @error = error
      @tcp_used = nil
      @captured = []
    end
    attr_reader :captured
    attr_reader :tcp_used
    def exchange(wire, id)
      @captured << [wire, id]
      Outcome.new(@reply, @uncertain, @error)
    end
  end

  def update_reply(rcode)
    m = Update.new('example.org').to_message
    m.qr = 1
    m.rcode = rcode
    m
  end

  def dns
    Resolv::DNS.new(nameserver: ['192.0.2.10'])
  end

  def sample_update
    Update.new('example.org').add('www.example.org', IN::A.new('192.0.2.1'), ttl: 3600)
  end

  def test_send_update_passes_encoded_message_with_matching_id
    transport = FakeTransport.new(reply: update_reply(0))
    result = dns.send_update(sample_update, transport: transport)
    assert result.ok?
    wire, id = transport.captured[0]
    assert_equal(id, wire.unpack1('n'))
    sent = Resolv::DNS::Message.decode(wire)
    assert_equal(Resolv::DNS::OpCode::Update, sent.opcode)
  end

  def test_result_noerror
    result = dns.send_update(sample_update, transport: FakeTransport.new(reply: update_reply(0)))
    assert_equal(:ok, result.status)
    assert result.ok?
    assert ! result.rejected?
    assert ! result.failed?
    assert ! result.prerequisite?
    assert ! result.uncertain?
    assert_equal(0, result.rcode)
    assert_kind_of(Resolv::DNS::Message, result.response)
  end

  def test_prerequisite_failures_are_distinct_from_other_rejections
    {6 => :YXDomain, 7 => :YXRRSet, 8 => :NXRRSet}.each do |rcode, _name|
      result = dns.send_update(sample_update, transport: FakeTransport.new(reply: update_reply(rcode)))
      assert_equal(:rejected, result.status)
      assert result.rejected?
      assert result.prerequisite?, "rcode #{rcode} should be a prerequisite failure"
      assert ! result.failed?
      assert ! result.uncertain?
      assert_equal(rcode, result.rcode)
    end
  end

  def test_other_server_rcodes_are_rejected_but_not_prerequisite
    [1, 2, 3, 4, 5, 9, 10].each do |rcode|
      result = dns.send_update(sample_update, transport: FakeTransport.new(reply: update_reply(rcode)))
      assert_equal(:rejected, result.status)
      assert result.rejected?
      assert ! result.prerequisite?, "rcode #{rcode} is not a prerequisite failure"
      assert_equal(rcode, result.rcode)
    end
  end

  def test_transport_failure_after_send_is_failed_and_uncertain
    result = dns.send_update(sample_update,
      transport: FakeTransport.new(uncertain: true, error: 'update timed out'))
    assert_equal(:failed, result.status)
    assert result.failed?
    assert result.uncertain?
    assert ! result.rejected?
    assert_nil result.rcode
    assert_equal('update timed out', result.error)
  end

  def test_transport_failure_before_send_is_failed_and_certain
    result = dns.send_update(sample_update,
      transport: FakeTransport.new(uncertain: false, error: 'Errno::ECONNREFUSED'))
    assert result.failed?
    assert ! result.uncertain?
  end

  def test_send_update_is_sent_exactly_once
    transport = FakeTransport.new(uncertain: true, error: 'update timed out')
    dns.send_update(sample_update, transport: transport)
    assert_equal(1, transport.captured.length)
  end

  def test_send_update_rejects_non_update_message
    assert_raise(ArgumentError) do
      dns.send_update(Resolv::DNS::Message.new, transport: FakeTransport.new)
    end
  end

  def test_send_update_rejects_non_positive_timeout
    assert_raise(ArgumentError) do
      dns.send_update(sample_update, timeout: 0, transport: FakeTransport.new)
    end
  end

  def test_rrset_typeclass_accepts_integer_type_values
    update = Update.new('example.org')
    update.require_rrset('x.example.org', 16)
    update.delete_rrset('y.example.org', 28)
    msg = decode(update)
    assert_equal(16, msg.answer[0][2].class::TypeValue)
    assert_equal(1,  msg.answer[0][2].class::ClassValue)
    assert_equal(28, msg.authority[0][2].class::TypeValue)
    assert_equal(255, msg.authority[0][2].class::ClassValue)
  end

  def test_rrset_typeclass_rejects_integer_type_any
    update = Update.new('example.org')
    assert_raise(ArgumentError) { update.require_rrset('x.example.org', 255) }
    assert_raise(ArgumentError) { update.delete_rrset('x.example.org', 255) }
  end

  def test_non_absolute_zone_suffix_name_is_canonicalized
    update = Update.new('example.org')
    update.add('www.example.org', IN::A.new('192.0.2.1'))
    name, = decode(update).authority[0]
    assert_predicate(name, :absolute?)
    assert_equal('www.example.org', name.to_s)
  end

  # --- transport via injected socket factory (no real sockets) ---------

  class SilentUDPSocket
    class << self
      attr_accessor :sent
    end
    self.sent = []
    def initialize(_family)
      @closed = false
    end
    def do_not_reverse_lookup=(_v); end
    def connect(host, port); end
    def send(data, _flags)
      self.class.sent << data
    end
    def wait_readable(seconds); nil; end # immediately time out
    def recvfrom(_n); raise Errno::EAGAIN; end
    def close; @closed = true; end
  end

  class RefusingSocketFactory
    def tcp(_host, _port); raise Errno::ECONNREFUSED; end
    def udp(family); SilentUDPSocket.new(family); end
  end

  class ReplyUDPSocket
    def initialize(rcode)
      @rcode = rcode
      @request = nil
    end
    def do_not_reverse_lookup=(_v); end
    def connect(_host, _port); end
    def send(data, _flags); @request = data; end
    def wait_readable(_seconds); true; end
    def recvfrom(_n)
      id = @request.unpack1('n')
      flags = (1 << 15) | (Resolv::DNS::OpCode::Update << 11) | @rcode
      [[id, flags, 0, 0, 0, 0].pack('nnnnnn'), nil]
    end
    def close; end
  end

  class UnreachableUDPSocket < ReplyUDPSocket
    def initialize; super(0); end
    def wait_readable(_seconds); true; end
    def recvfrom(_n); raise Errno::ECONNREFUSED; end
  end

  class UnreachableSocketFactory
    def tcp(_h, _p); raise 'should not use tcp'; end
    def udp(_f); UnreachableUDPSocket.new; end
  end

  class ReplySocketFactory
    def initialize(rcode); @rcode = rcode; end
    def tcp(_host, _port); raise 'should not use tcp'; end
    def udp(_family); ReplyUDPSocket.new(@rcode); end
  end

  def transport_dns
    Resolv::DNS.new(nameserver: ['127.0.0.1'])
  end

  def test_udp_silent_server_is_uncertain_failure_without_replay
    SilentUDPSocket.sent = []
    result = transport_dns.send_update(sample_update,
      timeout: 0.05, socket_factory: Object.new.tap {|o|
        def o.udp(_f); TestResolvDNSUpdate::SilentUDPSocket.new(0); end
        def o.tcp(_h, _p); raise 'should not use tcp'; end
      })
    assert result.failed?
    assert result.uncertain?
    assert_equal(1, SilentUDPSocket.sent.length) # exactly one datagram
  end

  def test_tcp_connection_refused_is_certain_failure
    result = transport_dns.send_update(sample_update,
      tcp: true, socket_factory: RefusingSocketFactory.new)
    assert result.failed?
    assert ! result.uncertain?
    assert_match(/ECONNREFUSED/, result.error)
  end

  def test_udp_transport_success_via_fake_socket
    update = sample_update
    result = transport_dns.send_update(update, socket_factory: ReplySocketFactory.new(0))
    assert result.ok?
    assert ! result.uncertain?
  end

  def test_udp_transport_nxrrset_via_fake_socket
    update = sample_update
    result = transport_dns.send_update(update, socket_factory: ReplySocketFactory.new(8))
    assert result.rejected?
    assert result.prerequisite?
    assert_equal(8, result.rcode)
  end

  def test_udp_icmp_unreachable_is_certain_failure
    result = transport_dns.send_update(sample_update,
      socket_factory: UnreachableSocketFactory.new)
    assert result.failed?
    assert ! result.uncertain?
    assert_match(/ECONNREFUSED/, result.error)
  end

  # --- real loopback fake server ---------------------------------------

  def make_server_reply(request, rcode)
    id = request.unpack1('n')
    [id, (1 << 15) | (Resolv::DNS::OpCode::Update << 11) | rcode, 0, 0, 0, 0].pack('nnnnnn')
  end

  def test_udp_fake_server_noerror_and_bytes
    with_udp('127.0.0.1', 0) do |server|
      _, port, _, host = server.addr
      update = sample_update
      result = nil
      client = Thread.new do
        resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
        resolver.timeouts = 2
        result = resolver.send_update(update)
      end
      request, _from = Timeout.timeout(5) { server.recvfrom(4096) }
      received = Resolv::DNS::Message.decode(request)
      assert_equal(Resolv::DNS::OpCode::Update, received.opcode)
      assert_equal(1, received.question.length)
      assert_equal(1, received.authority.length)
      name, ttl, data = received.authority[0]
      assert_equal('www.example.org', name.to_s)
      assert_equal(1, data.class::TypeValue)
      assert_equal(3600, ttl)
      server.send(make_server_reply(request, 0), 0, _from[3], _from[1])
      client.join
      assert result.ok?
    end
  end

  def test_udp_fake_server_nxrrset_is_prerequisite_failure
    with_udp('127.0.0.1', 0) do |server|
      _, port, _, host = server.addr
      result = nil
      client = Thread.new do
        resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
        resolver.timeouts = 2
        result = resolver.send_update(sample_update)
      end
      request, from = Timeout.timeout(5) { server.recvfrom(4096) }
      server.send(make_server_reply(request, 8), 0, from[3], from[1])
      client.join
      assert result.rejected?
      assert result.prerequisite?
      assert_equal(8, result.rcode)
      assert ! result.failed?
    end
  end

  def test_udp_fake_server_refused_is_rejected_not_transport
    with_udp('127.0.0.1', 0) do |server|
      _, port, _, host = server.addr
      result = nil
      client = Thread.new do
        resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
        resolver.timeouts = 2
        result = resolver.send_update(sample_update)
      end
      request, from = Timeout.timeout(5) { server.recvfrom(4096) }
      server.send(make_server_reply(request, 5), 0, from[3], from[1])
      client.join
      assert result.rejected?
      assert ! result.prerequisite?
      assert ! result.failed?
    end
  end

  def test_udp_timeout_is_transport_failure_and_uncertain
    with_udp('127.0.0.1', 0) do |server|
      _, port, _, host = server.addr
      resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
      resolver.timeouts = 0.2
      start = Time.now
      result = resolver.send_update(sample_update)
      elapsed = Time.now - start
      # Consume the single datagram the client sent.
      Timeout.timeout(5) { server.recvfrom(4096) }
      assert result.failed?
      assert result.uncertain?
      assert_operator elapsed, :>=, 0.19
    end
  end

  def test_udp_no_replay_after_timeout
    with_udp('127.0.0.1', 0) do |server|
      _, port, _, host = server.addr
      resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
      resolver.timeouts = 0.2
      resolver.send_update(sample_update)
      first, = Timeout.timeout(5) { server.recvfrom(4096) }
      assert_raise(Timeout::Error) do
        Timeout.timeout(0.5) { server.recvfrom(4096) }
      end
    end
  end

  def test_connection_refused_is_certain_transport_failure
    # Pick a closed port by opening and immediately closing a listener.
    probe = TCPServer.new('127.0.0.1', 0)
    port = probe.addr[1]
    probe.close
    resolver = Resolv::DNS.new(nameserver_port: [['127.0.0.1', port]])
    resolver.timeouts = 1
    result = resolver.send_update(sample_update, tcp: true)
    assert result.failed?
    assert ! result.uncertain?
  rescue Errno::EPERM, Errno::EACCES
    omit 'cannot open loopback socket in this environment'
  end

  def test_tcp_fake_server_noerror_and_framing
    with_tcp('127.0.0.1', 0) do |listener|
      _, port, _, host = listener.addr
      result = nil
      client = Thread.new do
        resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
        resolver.timeouts = 2
        result = resolver.send_update(sample_update, tcp: true)
      end
      conn = Timeout.timeout(5) { listener.accept }
      len = conn.read(2).unpack1('n')
      request = conn.read(len)
      received = Resolv::DNS::Message.decode(request)
      assert_equal(Resolv::DNS::OpCode::Update, received.opcode)
      reply = make_server_reply(request, 0)
      conn.write([reply.bytesize].pack('n') + reply)
      conn.close
      client.join
      assert result.ok?
    end
  end

  def test_large_update_uses_tcp_automatically
    with_tcp('127.0.0.1', 0) do |listener|
      _, port, _, host = listener.addr
      update = Update.new('example.org')
      # Exceed the 512 octet UDP limit with many TXT records.
      20.times do |i|
        update.add("host#{i}.example.org", IN::TXT.new('x' * 60), ttl: 60)
      end
      assert_operator update.encode.bytesize, :>, Resolv::DNS::UDPSize
      result = nil
      client = Thread.new do
        resolver = Resolv::DNS.new(nameserver_port: [[host, port]])
        resolver.timeouts = 2
        result = resolver.send_update(update)
      end
      conn = Timeout.timeout(5) { listener.accept }
      len = conn.read(2).unpack1('n')
      request = conn.read(len)
      received = Resolv::DNS::Message.decode(request)
      assert_equal(20, received.authority.length)
      reply = make_server_reply(request, 0)
      conn.write([reply.bytesize].pack('n') + reply)
      conn.close
      client.join
      assert result.ok?
    end
  end
end
