# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'socket'
require 'timeout'

class TestResolvDNSEDNS < Test::Unit::TestCase
  TEST_HOST = '127.0.0.1'

  class PingOption < Resolv::DNS::EDNS::Option
    CODE = 65000

    def self.decode(data)
      new(data.unpack1('n'))
    end

    def initialize(sequence)
      super(CODE)
      @sequence = sequence
    end

    attr_reader :sequence

    def encode_data
      [sequence].pack('n')
    end
  end

  Resolv::DNS::EDNS::Option.register(PingOption::CODE, PingOption)

  def test_edns_configuration_and_option_codec
    edns = Resolv::DNS::EDNS.create(
      udp_payload_size: 1400,
      dnssec_ok: true,
      options: [[PingOption::CODE, 7], [65001, "\xab\xcd".b]]
    )

    assert_equal 1400, edns.udp_payload_size
    assert_equal true, edns.do_bit?
    assert_equal PingOption.new(7), edns.options[0]
    assert_equal 7, edns.options[0].sequence
    assert_equal "\xab\xcd".b, edns.options[1].data
    assert_equal false, edns.fallback?
  end

  def test_edns_configuration_aliases
    edns = Resolv::DNS::EDNS.create(udp_size: 1200, do: true)
    assert_equal 1200, edns.udp_size
    assert_equal true, edns.dnssec_ok?
  end

  def test_edns_opt_encoding_and_extended_rcode
    message = Resolv::DNS::Message.new(1234)
    message.rd = 1
    message.add_question('example.org', Resolv::DNS::Resource::IN::A)
    edns = Resolv::DNS::EDNS.new(
      udp_payload_size: 1400,
      do_bit: true,
      options: [PingOption.new(8), [65001, "\x01\x02".b]]
    )
    message.add_additional(Resolv::DNS::Name.root, 0, edns.opt)

    encoded = message.encode
    assert_include encoded, [41, 1400].pack('nn')
    assert_include encoded, [0, 0, 0x80, 0].pack('CCCC')
    assert_include encoded, [65000, 2, 8].pack('nnn')
    assert_include encoded, [65001, 2, 1, 2].pack('nnCC')

    decoded = Resolv::DNS::Message.decode(encoded)
    opt = decoded.additional[0][2]
    assert_equal 1400, opt.udp_payload_size
    assert_equal true, opt.do_bit?
    assert_equal PingOption.new(8), opt.options[0]
    assert_equal "\x01\x02".b, opt.options[1].data

    response = encoded.b
    response.setbyte(3, response.getbyte(3) & 0xf0)
    type_offset = response.rindex([41, 1400].pack('nn'))
    response.setbyte(type_offset + 4, 1)
    response[type_offset + 5, 3] = "\0\0\0".b
    decoded_response = Resolv::DNS::Message.decode(response)
    assert_equal 16, decoded_response.rcode
  end

  def test_opt_position_and_uniqueness
    opt_data = "\0".b + [41, 1232, 0, 0].pack('nnN') + [0].pack('n')
    question = "\x07example\x03org\0\0\x01\0\x01".b

    duplicate = [1234, 0x8000, 0, 0, 0, 2].pack('nnnnnn') + question + opt_data + opt_data
    assert_raise(Resolv::DNS::DecodeError) { Resolv::DNS::Message.decode(duplicate) }

    answer = "\xc0\x0c".b + [1, 1, 60, 4].pack('nnNn') + "\xc0\x00\x02\x0a".b
    not_last = [1234, 0x8000, 0, 1, 0, 2].pack('nnnnnn') + question + answer + opt_data
    assert_raise(Resolv::DNS::DecodeError) { Resolv::DNS::Message.decode(not_last) }
  end

  def test_edns_request_and_response_udp
    with_fake_udp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        query, client = server.pop
        requests << query
        server.reply(client, normal_reply(query))
      end

      resources = resolve_edns(address, port, [PingOption.new(3)])
      assert_equal ['192.0.2.10'], resources.map {|resource| resource.address.to_s }
      query = join_with_queue(requests, server_thread)
      opt = opt_record(query)
      assert_equal 1232, opt.udp_payload_size
      assert_equal true, opt.do_bit?
      assert_equal [3], opt.options.grep(PingOption).map(&:sequence)
      assert_equal 0, Resolv::DNS::Message.decode(query).rcode
    end
  end

  def test_edns_request_and_response_tcp
    with_fake_tcp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        query, client = server.pop
        requests << query
        server.reply(client, normal_reply(query))
      end

      reply, query = request_tcp(address, port, [PingOption.new(4)])
      assert_equal ['192.0.2.10'], answer_addresses(reply)
      query = join_with_queue(requests, server_thread)
      opt = opt_record(query)
      assert_equal 1232, opt.udp_payload_size
      assert_equal true, opt.do_bit?
      assert_equal [4], opt.options.grep(PingOption).map(&:sequence)
    end
  end

  def test_formerr_fallback_without_opt_udp
    with_fake_udp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        first, client = server.pop
        requests << first
        server.reply(client, error_reply(first, Resolv::DNS::RCode::FormErr))

        second, _ = server.pop
        requests << second
        server.reply(client, normal_reply(second))
      end

      resources = resolve_edns(address, port, [], fallback: true)
      assert_equal ['192.0.2.10'], resources.map {|resource| resource.address.to_s }
      first = requests.pop
      second = requests.pop
      assert_not_nil opt_record(first)
      assert_nil opt_record(second)
      server_thread.join(5)
    end
  end

  def test_formerr_fallback_state_machine
    dns = Resolv::DNS.new(
      nameserver: TEST_HOST,
      timeouts: 1,
      edns: {udp_payload_size: 1232, fallback: true}
    )
    udp = FakeInMemoryRequester.new
    tcp = FakeInMemoryRequester.new
    udp.enqueue(:truncated)
    tcp.enqueue(:formerr, :answer)
    dns.define_singleton_method(:make_udp_requester) { udp }
    dns.define_singleton_method(:make_tcp_requester) { |_host, _port| tcp }
    begin
      resources = dns.getresources('example.org', Resolv::DNS::Resource::IN::A)
      assert_equal ['192.0.2.10'], resources.map {|resource| resource.address.to_s }
    end

    assert_equal 1, udp.requests.length
    assert_equal 2, tcp.requests.length
    assert_not_nil opt_record(udp.requests[0])
    assert_not_nil opt_record(tcp.requests[0])
    assert_nil opt_record(tcp.requests[1])
  ensure
    dns&.close
  end

  def test_formerr_without_fallback_does_not_retry
    with_fake_udp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        query, client = server.pop
        requests << query
        server.reply(client, error_reply(query, Resolv::DNS::RCode::FormErr))
      end

      assert_raise(Resolv::DNS::Config::OtherResolvError) do
        resolve_edns(address, port, [], dnssec_ok: true)
      end
      query = join_with_queue(requests, server_thread)
      assert_not_nil opt_record(query)
    end
  end

  def test_formerr_fallback_replays_formerr_only_once
    with_fake_udp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        2.times do
          query, client = server.pop
          requests << query
          server.reply(client, error_reply(query, Resolv::DNS::RCode::FormErr))
        end
      end

      assert_raise(Resolv::DNS::Config::OtherResolvError) do
        resolve_edns(address, port, [], fallback: true, timeouts: 5)
      end
      assert_equal 2, Array.new(2) { requests.pop }.length
      server_thread.join(5)
    end
  end

  def test_truncated_udp_retries_tcp_with_edns
    with_fake_udp_and_tcp do |udp_server, tcp_server, address, port|
      requests = Queue.new
      udp_thread = Thread.new do
        query, client = udp_server.pop
        requests << [:udp, query]
        udp_server.reply(client, truncated_reply(query))
      end
      tcp_thread = Thread.new do
        query, client = tcp_server.pop
        requests << [:tcp, query]
        tcp_server.reply(client, normal_reply(query))
      end

      resources = resolve_edns(address, port, [PingOption.new(5)], timeouts: 5)
      assert_equal ['192.0.2.10'], resources.map {|resource| resource.address.to_s }
      transport, query = join_with_queue(requests, udp_thread)
      assert_equal :udp, transport
      assert_not_nil opt_record(query)
      transport, query = join_with_queue(requests, tcp_thread)
      assert_equal :tcp, transport
      assert_not_nil opt_record(query)
    end
  end

  def test_formerr_after_truncation_retries_tcp_without_opt
    with_fake_udp_and_tcp do |udp_server, tcp_server, address, port|
      requests = Queue.new
      udp_thread = Thread.new do
        query, client = udp_server.pop
        requests << [:udp, query]
        udp_server.reply(client, truncated_reply(query))
      end
      tcp_thread = Thread.new do
        first, client = tcp_server.pop
        requests << [:tcp_first, first]
        tcp_server.reply(client, error_reply(first, Resolv::DNS::RCode::FormErr))
        client.close

        second, client = tcp_server.pop
        requests << [:tcp_second, second]
        tcp_server.reply(client, normal_reply(second))
      end

      resources = resolve_edns(address, port, [], fallback: true, timeouts: 5)
      assert_equal ['192.0.2.10'], resources.map {|resource| resource.address.to_s }
      _, first = join_with_queue(requests, udp_thread)
      _, tcp_first = Timeout.timeout(5) { requests.pop }
      _, tcp_second = Timeout.timeout(5) { requests.pop }
      tcp_thread.join(5)
      assert_not_nil opt_record(first)
      assert_not_nil opt_record(tcp_first)
      assert_nil opt_record(tcp_second)
    end
  end

  def test_wrong_id_is_ignored_udp
    with_fake_udp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        query, client = server.pop
        requests << query
        server.reply(client, normal_reply(query, id: query.id ^ 0xffff))
        server.reply(client, normal_reply(query))
      end

      resources = resolve_edns(address, port, [], timeouts: 5)
      assert_equal ['192.0.2.10'], resources.map {|resource| resource.address.to_s }
      join_with_queue(requests, server_thread)
    end
  end

  def test_wrong_id_is_ignored_tcp
    with_fake_tcp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        query, client = server.pop
        requests << query
        server.reply(client, normal_reply(query, id: query.id ^ 0xffff))
        server.reply(client, normal_reply(query))
      end

      reply, = request_tcp(address, port, [], timeouts: 5)
      assert_equal ['192.0.2.10'], answer_addresses(reply)
      join_with_queue(requests, server_thread)
    end
  end

  def test_extended_rcode_and_unknown_option_bytes
    reply = nil
    with_fake_udp do |server, address, port|
      requests = Queue.new
      server_thread = Thread.new do
        query, client = server.pop
        requests << query
        reply = normal_reply(query)
        opt = reply.additional[0][2]
        reply.additional.pop
        reply.add_additional(
          Resolv::DNS::Name.root,
          0,
          Resolv::DNS::EDNS::OPT.new(
            1232,
            extended_rcode: 1,
            do_bit: true,
            options: [[65002, "\x01\x02\x03".b], [PingOption::CODE, "\x00\x09".b]]
          )
        )
        server.reply(client, reply.encode)
      end

      assert_raise(Resolv::DNS::Config::OtherResolvError) do
        resolve_edns(address, port, [], timeouts: 5)
      end
      join_with_queue(requests, server_thread)
      decoded = Resolv::DNS::Message.decode(reply.encode)
      assert_equal 16, decoded.rcode
      opt = opt_record(decoded.encode)
      assert_equal 1, opt.extended_rcode
      assert_equal "\x01\x02\x03".b, opt.options[0].data
      assert_equal PingOption.new(9), opt.options[1]
    end
  end

  private

  def resolve_edns(address, port, options, fallback: false, dnssec_ok: false, timeouts: 2)
    config = {
      nameserver_port: [[address, port]],
      timeouts: timeouts,
      edns: {
        udp_payload_size: 1232,
        dnssec_ok: dnssec_ok,
        fallback: fallback,
        options: options
      }
    }
    Resolv::DNS.open(config) {|dns| dns.getresources('example.org', Resolv::DNS::Resource::IN::A) }
  end

  def request_tcp(address, port, options, timeouts: 2)
    requester = Resolv::DNS::Requester::TCP.new(address, port)
    message = Resolv::DNS::Message.new
    message.rd = 1
    message.add_question('example.org', Resolv::DNS::Resource::IN::A)
    edns = Resolv::DNS::EDNS.new(udp_payload_size: 1232, do_bit: true, options: options)
    message.add_additional(Resolv::DNS::Name.root, 0, edns.opt)
    sender = requester.sender(message, message, address, port)
    begin
      reply, _data = Timeout.timeout(5) { requester.request(sender, timeouts) }
      [reply, message]
    ensure
      requester.close
    end
  end

  def answer_addresses(message)
    message.answer.map {|_, _, record| record.address.to_s }
  end

  def opt_record(message)
    message = message.encode if message.is_a?(Resolv::DNS::Message)
    decoded = Resolv::DNS::Message.decode(message)
    decoded.additional.map(&:last).grep(Resolv::DNS::Resource::EDNS::OPT).first
  end

  def normal_reply(query, id: query.id)
    reply = Resolv::DNS::Message.new(id)
    reply.qr = 1
    reply.rd = query.rd
    reply.ra = 1
    query.each_question {|name, typeclass| reply.add_question(name, typeclass) }
    reply.add_answer(query.question[0][0], 60, Resolv::DNS::Resource::IN::A.new('192.0.2.10'))
    query_opt = opt_record(query)
    if query_opt
      reply.add_additional(
        Resolv::DNS::Name.root,
        0,
        Resolv::DNS::EDNS::OPT.new(query_opt.udp_payload_size, do_bit: query_opt.do_bit?, options: query_opt.options)
      )
    end
    reply
  end

  def error_reply(query, rcode)
    reply = normal_reply(query)
    reply.rcode = rcode
    reply.answer.clear
    reply
  end

  def truncated_reply(query)
    reply = normal_reply(query)
    reply.tc = 1
    reply.answer.clear
    reply
  end

  def with_fake_udp
    FakeUDPServer.open(TEST_HOST) {|server| yield server, TEST_HOST, server.port }
  rescue Errno::EPERM, Errno::EACCES, Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT
    omit 'cannot bind local fake UDP server in this environment'
  end

  def with_fake_tcp
    FakeTCPServer.open(TEST_HOST) {|server| yield server, TEST_HOST, server.port }
  rescue Errno::EPERM, Errno::EACCES, Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT
    omit 'cannot bind local fake TCP server in this environment'
  end

  def with_fake_udp_and_tcp
    udp = nil
    tcp = nil
    begin
      udp = FakeUDPServer.new(TEST_HOST)
      begin
        tcp = FakeTCPServer.new(TEST_HOST, udp.port)
      rescue
        udp.close
        raise
      end
    rescue Errno::EPERM, Errno::EACCES, Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT
      omit 'cannot bind local fake UDP/TCP servers in this environment'
    end
    begin
      yield udp, tcp, TEST_HOST, udp.port
    ensure
      tcp.close
      udp.close
    end
  end

  def join_with_queue(queue, thread)
    result = Timeout.timeout(5) { queue.pop }
    thread.join(5)
    result
  end

  class FakeInMemoryRequester
    attr_reader :requests

    def initialize
      @requests = []
      @responses = []
    end

    def enqueue(*responses)
      @responses.concat(responses)
    end

    def sender(message, data, *)
      @requests << message
      sender = [message, Resolv::DNS::Name.create("example.org.")]
      @senders = {current: sender}
      sender
    end

    def request((message, data), _timeout)
      [fake_reply(message, data, @responses.shift), data]
    end

    def reusable?
      true
    end

    def sender_for(addr, message)
      @senders[:current]
    end

    def close
    end

    private

    def fake_reply(query, reply_name, mode)
      reply = Resolv::DNS::Message.new(query.id)
      reply.qr = 1
      reply.rd = query.rd
      query.each_question do |name, typeclass|
        reply.add_question(name, typeclass)
      end
      case mode
      when :truncated
        reply.tc = 1
      when :formerr
        reply.rcode = Resolv::DNS::RCode::FormErr
      when :answer
        reply.add_answer(reply_name, 60, Resolv::DNS::Resource::IN::A.new('192.0.2.10'))
      end
      reply
    end
  end

  class FakeUDPServer
    def self.open(host)
      server = new(host)
      begin
        yield server
      ensure
        server.close
      end
    end

    def initialize(host)
      @socket = UDPSocket.new
      @socket.bind(host, 0)
    end

    attr_reader :port

    def pop
      data, from = Timeout.timeout(5) { @socket.recvfrom(65535) }
      [Resolv::DNS::Message.decode(data), [from[3], from[1]]]
    end

    def reply(client, message)
      data = message.is_a?(String) ? message : message.encode
      @socket.send(data, 0, client[0], client[1])
    end

    def close
      @socket.close
    end
  end

  class FakeTCPServer
    def self.open(host)
      server = new(host)
      begin
        yield server
      ensure
        server.close
      end
    end

    def initialize(host, port = nil)
      @server = TCPServer.new(host, port || 0)
    end

    def port
      @server.addr[1]
    end

    def pop
      client = Timeout.timeout(5) { @server.accept }
      length_data = client.read(2)
      length = length_data.unpack1('n')
      query = Resolv::DNS::Message.decode(client.read(length))
      [query, client]
    end

    def reply(client, message)
      data = message.is_a?(String) ? message : message.encode
      client.write([data.bytesize].pack('n') + data)
    end

    def close
      @server.close
    end
  end
end
