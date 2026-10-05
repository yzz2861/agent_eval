# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'socket'
require 'timeout'

class TestResolvDNSUpdate < Test::Unit::TestCase
  def setup
    @save_do_not_reverse_lookup = BasicSocket.do_not_reverse_lookup
    BasicSocket.do_not_reverse_lookup = true
  end

  def teardown
    BasicSocket.do_not_reverse_lookup = @save_do_not_reverse_lookup
  end

  def with_udp_server
    u = UDPSocket.new
    begin
      u.bind('127.0.0.1', 0)
      _, port, _, addr = u.addr
      yield u, addr, port
    ensure
      u.close
    end
  end

  def with_udp_and_tcp_server
    10.times do
      u = UDPSocket.new
      u.bind('127.0.0.1', 0)
      _, port, _, addr = u.addr
      begin
        t = TCPServer.new(addr, port)
      rescue Errno::EADDRINUSE, Errno::EACCES
        u.close
        next
      end
      t.listen(1)
      begin
        return yield u, t, addr, port
      ensure
        t.close
        u.close
      end
    end
    flunk "could not bind UDP and TCP to the same port"
  end

  # A minimal RFC 2136 response header: QR=1, opcode UPDATE, no sections.
  def update_response(id, rcode:, tc: 0)
    word2 = (1 << 15) | (5 << 11) | (tc << 9) | rcode
    [id, word2, 0, 0, 0, 0].pack("nnnnnn")
  end

  def example_update
    update = Resolv::DNS::Update.new("example.com.")
    update.add("host.example.com.", Resolv::DNS::Resource::IN::A.new("192.0.2.1"), ttl: 300)
    update
  end

  def test_encode_wire_bytes
    update = Resolv::DNS::Update.new("example.com.")
    update.require_name_absent("host.example.com.")
    update.add("host.example.com.", Resolv::DNS::Resource::IN::A.new("192.0.2.1"), ttl: 300)

    expected = [0x1234, 0x2800, 1, 1, 1, 0].pack("nnnnnn") # id, opcode UPDATE, ZO/PR/UP/AD counts
    expected << [7, "example", 3, "com", 0].pack("Ca*Ca*C")
    expected << [6, 1].pack("nn")                        # ZTYPE SOA, ZCLASS IN
    expected << [4, "host", 0xc00c].pack("Ca*n")         # prerequisite owner
    expected << [255, 254, 0, 0].pack("nnNn")            # TYPE ANY, CLASS NONE, TTL 0, RDLENGTH 0
    expected << [0xc01d].pack("n")                       # update owner: pointer to the prerequisite owner
    expected << [1, 1, 300, 4].pack("nnNn")              # TYPE A, CLASS IN, TTL 300, RDLENGTH 4
    expected << [192, 0, 2, 1].pack("CCCC")

    assert_equal(expected, update.to_message(0x1234).encode)
  end

  def test_message_sections
    update = Resolv::DNS::Update.new("example.com.")
    update.require_name_present("www.example.com.")
    update.require_name_absent("gone.example.com.")
    update.require_rrset_present("www.example.com.", Resolv::DNS::Resource::IN::A)
    update.require_rrset_present("www.example.com.", Resolv::DNS::Resource::IN::A.new("192.0.2.1"))
    update.require_rrset_absent("www.example.com.", Resolv::DNS::Resource::IN::AAAA)
    update.add("www.example.com.", Resolv::DNS::Resource::IN::A.new("192.0.2.2"), ttl: 300)
    update.delete_record("old.example.com.", Resolv::DNS::Resource::IN::A.new("192.0.2.3"))
    update.delete_rrset("old.example.com.", Resolv::DNS::Resource::IN::AAAA)
    update.delete_name("veryold.example.com.")

    msg = Resolv::DNS::Message.decode(update.to_message(0x1234).encode)
    assert_equal(0x1234, msg.id)
    assert_equal(Resolv::DNS::OpCode::Update, msg.opcode)

    questions = []
    msg.each_question {|name, typeclass| questions << [name, typeclass] }
    assert_equal([[Resolv::DNS::Name.create("example.com."), Resolv::DNS::Resource::IN::SOA]], questions)

    prereqs = []
    msg.each_answer {|name, ttl, rr| prereqs << [name, ttl, rr] }
    assert_equal(5, prereqs.length)

    name, ttl, rr = prereqs[0] # require_name_present: TYPE ANY, CLASS ANY
    assert_equal(Resolv::DNS::Name.create("www.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([255, 255], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal("", rr.data)

    name, ttl, rr = prereqs[1] # require_name_absent: TYPE ANY, CLASS NONE
    assert_equal(Resolv::DNS::Name.create("gone.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([255, 254], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal("", rr.data)

    name, ttl, rr = prereqs[2] # require_rrset_present with a class: TYPE A, CLASS ANY
    assert_equal(Resolv::DNS::Name.create("www.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([1, 255], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal("", rr.data)

    name, ttl, rr = prereqs[3] # require_rrset_present with a resource: TYPE A, CLASS IN, rdata
    assert_equal(Resolv::DNS::Name.create("www.example.com."), name)
    assert_equal(0, ttl)
    assert_instance_of(Resolv::DNS::Resource::IN::A, rr)
    assert_equal("192.0.2.1", rr.address.to_s)

    name, ttl, rr = prereqs[4] # require_rrset_absent: TYPE AAAA, CLASS NONE
    assert_equal(Resolv::DNS::Name.create("www.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([28, 254], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal("", rr.data)

    updates = []
    msg.each_authority {|name, ttl, rr| updates << [name, ttl, rr] }
    assert_equal(4, updates.length)

    name, ttl, rr = updates[0] # add: TYPE A, CLASS IN, TTL 300, rdata
    assert_equal(Resolv::DNS::Name.create("www.example.com."), name)
    assert_equal(300, ttl)
    assert_instance_of(Resolv::DNS::Resource::IN::A, rr)
    assert_equal("192.0.2.2", rr.address.to_s)

    name, ttl, rr = updates[1] # delete_record: TYPE A, CLASS NONE, TTL 0, rdata
    assert_equal(Resolv::DNS::Name.create("old.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([1, 254], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal([192, 0, 2, 3].pack("CCCC"), rr.data)

    name, ttl, rr = updates[2] # delete_rrset: TYPE AAAA, CLASS ANY, TTL 0, no rdata
    assert_equal(Resolv::DNS::Name.create("old.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([28, 255], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal("", rr.data)

    name, ttl, rr = updates[3] # delete_name: TYPE ANY, CLASS ANY, TTL 0, no rdata
    assert_equal(Resolv::DNS::Name.create("veryold.example.com."), name)
    assert_equal(0, ttl)
    assert_equal([255, 255], [rr.class::TypeValue, rr.class::ClassValue])
    assert_equal("", rr.data)
  end

  def test_zone_must_be_absolute
    assert_raise(ArgumentError) { Resolv::DNS::Update.new("example.com") }
  end

  def test_names_must_be_absolute
    update = Resolv::DNS::Update.new("example.com.")
    assert_raise(ArgumentError) { update.require_name_present("www.example.com") }
    assert_raise(ArgumentError) { update.delete_name("www.example.com") }
    assert_raise(ArgumentError) {
      update.add("www.example.com", Resolv::DNS::Resource::IN::A.new("192.0.2.1"), ttl: 300)
    }
  end

  def test_names_must_be_in_zone
    update = Resolv::DNS::Update.new("example.com.")
    assert_raise(ArgumentError) { update.require_name_absent("other.org.") }
    assert_raise(ArgumentError) { update.require_rrset_absent("other.org.", Resolv::DNS::Resource::IN::A) }
    assert_raise(ArgumentError) { update.delete_rrset("other.org.", Resolv::DNS::Resource::IN::A) }
    assert_raise(ArgumentError) { update.delete_name("other.org.") }
    assert_raise(ArgumentError) {
      update.add("other.org.", Resolv::DNS::Resource::IN::A.new("192.0.2.1"), ttl: 300)
    }
    # the zone name itself is in the zone
    update.add("example.com.", Resolv::DNS::Resource::IN::A.new("192.0.2.1"), ttl: 300)
    assert_equal(1, update.updates.length)
  end

  def test_add_validates_ttl
    update = Resolv::DNS::Update.new("example.com.")
    a = Resolv::DNS::Resource::IN::A.new("192.0.2.1")
    assert_raise(ArgumentError) { update.add("host.example.com.", a, ttl: -1) }
    assert_raise(ArgumentError) { update.add("host.example.com.", a, ttl: 0x80000000) }
    assert_raise(ArgumentError) { update.add("host.example.com.", a, ttl: "300") }
    assert_raise(ArgumentError) { update.add("host.example.com.", a, ttl: nil) }
    update.add("host.example.com.", a, ttl: 0)
    update.add("host.example.com.", a, ttl: 0x7fffffff)
    assert_equal(2, update.updates.length)
  end

  def test_resource_class_must_match_zone_class
    update = Resolv::DNS::Update.new("example.com.")
    ch_a = Resolv::DNS::Resource::Generic.create(1, 3).new([192, 0, 2, 1].pack("CCCC")) # CLASS CH
    assert_raise(ArgumentError) { update.add("host.example.com.", ch_a, ttl: 300) }
    assert_raise(ArgumentError) { update.delete_record("host.example.com.", ch_a) }
    assert_raise(ArgumentError) { update.require_rrset_present("host.example.com.", ch_a) }

    ch_update = Resolv::DNS::Update.new("example.com.", 3)
    ch_update.add("host.example.com.", ch_a, ttl: 300)
    msg = Resolv::DNS::Message.decode(ch_update.to_message(0).encode)
    msg.each_question {|_, typeclass| assert_equal(3, typeclass::ClassValue) }
    msg.each_authority {|_, ttl, rr|
      assert_equal(300, ttl)
      assert_equal([1, 3], [rr.class::TypeValue, rr.class::ClassValue])
    }
  end

  def test_any_type_rejected_for_rrset_operations
    update = Resolv::DNS::Update.new("example.com.")
    assert_raise(ArgumentError) { update.delete_rrset("host.example.com.", Resolv::DNS::Resource::IN::ANY) }
    assert_raise(ArgumentError) { update.require_rrset_absent("host.example.com.", Resolv::DNS::Resource::IN::ANY) }
    assert_raise(ArgumentError) { update.require_rrset_present("host.example.com.", Resolv::DNS::Resource::IN::ANY) }
  end

  def test_update_errors_are_resolv_errors
    assert_operator(Resolv::DNS::UpdatePrerequisiteFailed, :<, Resolv::ResolvError)
    assert_operator(Resolv::DNS::UpdateServerError, :<, Resolv::ResolvError)
    assert_operator(Resolv::DNS::UpdateIndeterminate, :<, Resolv::ResolvError)
  end

  def test_update_success
    with_udp_server {|u, addr, port|
      client = Thread.new {
        Resolv::DNS.open(nameserver_port: [[addr, port]]) {|dns|
          dns.update(example_update, timeout: 5)
        }
      }
      server = Thread.new {
        msg, (_, client_port, _, client_addr) = Timeout.timeout(5) { u.recvfrom(4096) }
        id, word2, zocount, prcount, upcount, adcount = msg.unpack("nnnnnn")
        assert_equal(0, (word2 >> 15) & 1)  # QR: request
        assert_equal(5, (word2 >> 11) & 15) # opcode UPDATE
        assert_equal(1, zocount)
        assert_equal(0, prcount)
        assert_equal(1, upcount)
        assert_equal(0, adcount)
        u.send(update_response(id, rcode: 0), 0, client_addr, client_port)
      }
      reply, _ = assert_join_threads([client, server])
      assert_equal(0, reply.rcode)
      assert_equal(5, reply.opcode)
    }
  end

  def test_update_prerequisite_failed
    with_udp_server {|u, addr, port|
      client = Thread.new {
        Resolv::DNS.open(nameserver_port: [[addr, port]]) {|dns|
          update = Resolv::DNS::Update.new("example.com.")
          update.require_rrset_present("host.example.com.", Resolv::DNS::Resource::IN::A)
          update.delete_rrset("host.example.com.", Resolv::DNS::Resource::IN::A)
          err = assert_raise(Resolv::DNS::UpdatePrerequisiteFailed) { dns.update(update, timeout: 5) }
          assert_equal(7, err.rcode) # YXRRSET
          assert_equal(7, err.reply.rcode)
          assert_kind_of(Resolv::ResolvError, err)
        }
      }
      server = Thread.new {
        msg, (_, client_port, _, client_addr) = Timeout.timeout(5) { u.recvfrom(4096) }
        id, word2, _, prcount, upcount, _ = msg.unpack("nnnnnn")
        assert_equal(1, prcount)
        assert_equal(1, upcount)
        u.send(update_response(id, rcode: 7), 0, client_addr, client_port)
      }
      assert_join_threads([client, server])
    }
  end

  def test_update_server_error_is_distinct_from_prerequisite_failure
    with_udp_server {|u, addr, port|
      client = Thread.new {
        Resolv::DNS.open(nameserver_port: [[addr, port]]) {|dns|
          err = assert_raise(Resolv::DNS::UpdateServerError) { dns.update(example_update, timeout: 5) }
          assert_equal(5, err.rcode) # REFUSED
          assert_not_kind_of(Resolv::DNS::UpdatePrerequisiteFailed, err)
          assert_not_kind_of(Resolv::DNS::UpdateIndeterminate, err)
        }
      }
      server = Thread.new {
        msg, (_, client_port, _, client_addr) = Timeout.timeout(5) { u.recvfrom(4096) }
        id, = msg.unpack("n")
        u.send(update_response(id, rcode: 5), 0, client_addr, client_port)
      }
      assert_join_threads([client, server])
    }
  end

  def test_update_timeout_is_indeterminate_and_not_replayed
    with_udp_server {|u, addr, port|
      client = Thread.new {
        Resolv::DNS.open(nameserver_port: [[addr, port]]) {|dns|
          assert_raise(Resolv::DNS::UpdateIndeterminate) { dns.update(example_update, timeout: 0.2) }
        }
      }
      server = Thread.new {
        msg, = Timeout.timeout(5) { u.recvfrom(4096) }
        word2 = msg.unpack("nn")[1]
        assert_equal(5, (word2 >> 11) & 15) # opcode UPDATE
        # Outlast the client timeout: a replayed update would arrive here.
        sleep 0.5
        assert_raise(IO::WaitReadable) { u.recvfrom_nonblock(4096) }
      }
      assert_join_threads([client, server])
    }
  end

  def test_update_tcp_fallback_on_truncation
    with_udp_and_tcp_server {|u, t, addr, port|
      client = Thread.new {
        Resolv::DNS.open(nameserver_port: [[addr, port]]) {|dns|
          dns.update(example_update, timeout: 5)
        }
      }
      server = Thread.new {
        msg, (_, client_port, _, client_addr) = Timeout.timeout(5) { u.recvfrom(4096) }
        id, = msg.unpack("n")
        u.send(update_response(id, rcode: 0, tc: 1), 0, client_addr, client_port)
        sock = Timeout.timeout(5) { t.accept }
        begin
          len = sock.read(2).unpack1("n")
          tcp_id, word2, zocount, _, upcount, _ = sock.read(len).unpack("nnnnnn")
          assert_equal(5, (word2 >> 11) & 15) # opcode UPDATE
          assert_equal(1, zocount)
          assert_equal(1, upcount)
          response = update_response(tcp_id, rcode: 0)
          sock.write([response.length].pack("n") + response)
        ensure
          sock.close
        end
      }
      reply, _ = assert_join_threads([client, server])
      assert_equal(0, reply.rcode)
    }
  end
end
