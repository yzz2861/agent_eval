# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'socket'
require 'openssl'
require 'timeout'

class TestResolvTSIG < Test::Unit::TestCase
  SECRET = "0123456789abcdef".b
  KEY_NAME = 'key.example.'
  NOW = 1_700_000_000

  def setup
    @save_do_not_reverse_lookup = BasicSocket.do_not_reverse_lookup
    BasicSocket.do_not_reverse_lookup = true
  end

  def teardown
    BasicSocket.do_not_reverse_lookup = @save_do_not_reverse_lookup
  end

  def new_tsig(secret: SECRET, key_name: KEY_NAME, fudge: 300, clock: -> { Time.at(NOW) })
    Resolv::DNS::TSIG.new(key_name, secret, fudge: fudge, clock: clock)
  end

  def new_query_wire(id: 0x1234, name: 'foo.example.org')
    msg = Resolv::DNS::Message.new(id)
    msg.rd = 1
    msg.add_question(name, Resolv::DNS::Resource::IN::A)
    msg.encode
  end

  # Signs +message+ the way a server signs a response to a request whose MAC
  # was +request_mac+, building the digest input from the raw message bytes.
  # [RFC 8945 4.3]
  def server_sign(message, request_mac, secret: SECRET, key_name: KEY_NAME,
                  time: NOW, fudge: 300, error: 0, other: ''.b)
    key = Resolv::DNS::Name.create(key_name)
    algorithm = Resolv::DNS::Name.create('hmac-sha256.')
    variables = String.new
    variables << Resolv::DNS::TSIG.canonical_name_wire(key)
    variables << [255, 0].pack('nN')
    variables << Resolv::DNS::TSIG.canonical_name_wire(algorithm)
    variables << [time >> 32, time & 0xffffffff].pack('nN')
    variables << [fudge, error, other.bytesize].pack('nnn')
    variables << other
    data = [request_mac.bytesize].pack('n') + request_mac + message + variables
    mac = OpenSSL::HMAC.digest('SHA256', secret, data)
    rdata = String.new
    rdata << Resolv::DNS::TSIG.canonical_name_wire(algorithm)
    rdata << [time >> 32, time & 0xffffffff].pack('nN')
    rdata << [fudge, mac.bytesize].pack('nn')
    rdata << mac
    rdata << [message.unpack1('n'), error, other.bytesize].pack('nnn')
    rdata << other
    signed = message.dup
    signed[10, 2] = [signed.unpack1('@10 n') + 1].pack('n')
    signed << Resolv::DNS::TSIG.name_wire(key)
    signed << [250, 255, 0].pack('nnN')
    signed << [rdata.bytesize].pack('n') << rdata
    signed
  end

  def new_response_wire(request_wire, address: '192.0.2.1')
    query = Resolv::DNS::Message.decode(request_wire)
    response = Resolv::DNS::Message.new(query.id)
    response.qr = 1
    response.rd = 1
    response.ra = 1
    query.each_question {|name, typeclass| response.add_question(name, typeclass) }
    response.add_answer('foo.example.org', 300, Resolv::DNS::Resource::IN::A.new(address))
    response.encode
  end

  def sign_and_respond(tsig, **options)
    request, request_mac = tsig.sign_request(new_query_wire)
    response = server_sign(new_response_wire(request), request_mac, **options)
    return request_mac, response
  end

  def test_unsupported_algorithm
    assert_raise(ArgumentError) do
      Resolv::DNS::TSIG.new(KEY_NAME, SECRET, algorithm: 'hmac-md5')
    end
  end

  def test_sign_request_appends_tsig_record
    tsig = new_tsig
    request = new_query_wire
    signed, mac = tsig.sign_request(request)
    assert_equal(32, mac.bytesize)
    assert_equal(1, signed.unpack1('@10 n'))
    offset, record = Resolv::DNS::TSIG.extract_tsig(signed)
    assert_not_nil(record)
    assert_equal(request.bytesize, offset)
    assert_equal(Resolv::DNS::Name.create(KEY_NAME).to_a, record.name.to_a)
    assert_equal(Resolv::DNS::Name.create('hmac-sha256.').to_a, record.algorithm.to_a)
    assert_equal(NOW, record.time)
    assert_equal(300, record.fudge)
    assert_equal(0x1234, record.original_id)
    assert_equal(0, record.error)
    assert_equal(mac, record.mac)
  end

  def test_verify_response_roundtrip
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig)
    stripped = tsig.verify_response(response, request_mac)
    assert_nil(Resolv::DNS::TSIG.extract_tsig(stripped)[1])
    msg = Resolv::DNS::Message.decode(stripped)
    assert_equal(1, msg.answer.size)
    name, ttl, data = msg.answer[0]
    assert_equal('foo.example.org', name.to_s)
    assert_equal('192.0.2.1', data.address.to_s)
  end

  def test_verify_response_uses_request_mac
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig)
    other_mac = OpenSSL::HMAC.digest('SHA256', SECRET, 'other')
    assert_raise(Resolv::DNS::TSIG::BadSignature) do
      tsig.verify_response(response, other_mac)
    end
    assert_nothing_raised { tsig.verify_response(response, request_mac) }
  end

  def test_verify_response_tampered_message
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig)
    # Flip a byte inside the answer, before the TSIG record.
    offset, = Resolv::DNS::TSIG.extract_tsig(response)
    response = response.dup
    response.setbyte(offset - 1, response.getbyte(offset - 1) ^ 0xff)
    assert_raise(Resolv::DNS::TSIG::BadSignature) do
      tsig.verify_response(response, request_mac)
    end
  end

  def test_verify_response_wrong_secret
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig, secret: 'FEDCBA9876543210'.b)
    assert_raise(Resolv::DNS::TSIG::BadSignature) do
      tsig.verify_response(response, request_mac)
    end
  end

  def test_verify_response_unknown_key_name
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig, key_name: 'other.example.')
    assert_raise(Resolv::DNS::TSIG::BadKey) do
      tsig.verify_response(response, request_mac)
    end
  end

  def test_verify_response_bad_time
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig, time: NOW - 1000)
    assert_raise(Resolv::DNS::TSIG::BadTime) do
      tsig.verify_response(response, request_mac)
    end
    request_mac, response = sign_and_respond(tsig, time: NOW + 299)
    assert_nothing_raised { tsig.verify_response(response, request_mac) }
  end

  def test_verify_response_unsigned
    tsig = new_tsig
    request_mac, = tsig.sign_request(new_query_wire)
    response = new_response_wire(new_query_wire)
    assert_raise(Resolv::DNS::TSIG::Error) do
      tsig.verify_response(response, request_mac)
    end
  end

  def test_verify_response_error_field
    tsig = new_tsig
    {
      16 => Resolv::DNS::TSIG::BadSignature,
      17 => Resolv::DNS::TSIG::BadKey,
      18 => Resolv::DNS::TSIG::BadTime,
      22 => Resolv::DNS::TSIG::Error,
    }.each do |error, exception|
      request_mac, response = sign_and_respond(tsig, error: error)
      assert_raise(exception) { tsig.verify_response(response, request_mac) }
    end
  end

  def test_verify_response_unsigned_error_report
    # BADKEY/BADSIG reports are allowed to carry an empty MAC. [RFC 8945 4.5]
    tsig = new_tsig
    request, request_mac = tsig.sign_request(new_query_wire)
    response = new_response_wire(request)
    key = Resolv::DNS::Name.create(KEY_NAME)
    algorithm = Resolv::DNS::Name.create('hmac-sha256.')
    rdata = String.new
    rdata << Resolv::DNS::TSIG.canonical_name_wire(algorithm)
    rdata << [NOW >> 32, NOW & 0xffffffff].pack('nN')
    rdata << [300, 0].pack('nn')
    rdata << [response.unpack1('n'), 17, 0].pack('nnn')
    response[10, 2] = [1].pack('n')
    response << Resolv::DNS::TSIG.name_wire(key)
    response << [250, 255, 0].pack('nnN')
    response << [rdata.bytesize].pack('n') << rdata
    assert_raise(Resolv::DNS::TSIG::BadKey) do
      tsig.verify_response(response, request_mac)
    end
  end

  def test_verify_response_format_errors
    tsig = new_tsig
    request_mac, response = sign_and_respond(tsig)

    # TSIG record not the last additional record.
    not_last = response.dup
    not_last[10, 2] = [2].pack('n')
    not_last << Resolv::DNS::TSIG.name_wire(Resolv::DNS::Name.create(KEY_NAME))
    not_last << [1, 1, 0].pack("nnN") << [4].pack("n") << [192, 0, 2, 1].pack("C4")
    assert_raise(Resolv::DNS::TSIG::FormatError) do
      tsig.verify_response(not_last, request_mac)
    end

    # Truncated message.
    assert_raise(Resolv::DNS::TSIG::FormatError) do
      tsig.verify_response(response.byteslice(0, response.bytesize - 5), request_mac)
    end

    # Message shorter than a header.
    assert_raise(Resolv::DNS::TSIG::FormatError) do
      tsig.verify_response('abc', request_mac)
    end
  end

  def test_error_class_hierarchy
    assert_operator(Resolv::DNS::TSIG::BadKey, :<, Resolv::DNS::TSIG::Error)
    assert_operator(Resolv::DNS::TSIG::BadSignature, :<, Resolv::DNS::TSIG::Error)
    assert_operator(Resolv::DNS::TSIG::BadTime, :<, Resolv::DNS::TSIG::Error)
    assert_operator(Resolv::DNS::TSIG::FormatError, :<, Resolv::DNS::TSIG::Error)
  end

  def with_udp_and_tcp(host, port)
    retries_remaining = 10
    begin
      u = UDPSocket.new
      u.bind(host, port)
      _, udp_port, _, _ = u.addr
      t = TCPServer.new(host, udp_port)
      t.listen(1)
    rescue Errno::EADDRINUSE, Errno::EACCES
      u&.close
      retry if (retries_remaining -= 1) >= 0
      raise
    end
    begin
      yield u, t
    ensure
      u.close
      t.close
    end
  end

  def test_udp_query_with_tsig
    tsig = new_tsig(clock: -> { Time.now })
    with_udp_and_tcp('127.0.0.1', 0) do |u, _t|
      _, port, _, address = u.addr
      server = Thread.new do
        query, (_, client_port, _, client_address) =
          Timeout.timeout(EnvUtil.apply_timeout_scale(10)) { u.recvfrom(4096) }
        _, record = Resolv::DNS::TSIG.extract_tsig(query)
        assert_not_nil(record)
        response = server_sign(new_response_wire(query), record.mac)
        u.send(response, 0, client_address, client_port)
      end
      dns = Resolv::DNS.new(nameserver_port: [[address, port]], tsig: tsig)
      begin
        resources = Timeout.timeout(EnvUtil.apply_timeout_scale(10)) do
          dns.getresources('foo.example.org', Resolv::DNS::Resource::IN::A)
        end
        assert_equal(['192.0.2.1'], resources.map {|r| r.address.to_s })
      ensure
        dns.close
      end
      assert_join_threads([server])
    end
  end

  def test_udp_query_with_tsig_rejects_bad_signature
    tsig = new_tsig(clock: -> { Time.now })
    with_udp_and_tcp('127.0.0.1', 0) do |u, _t|
      _, port, _, address = u.addr
      server = Thread.new do
        query, (_, client_port, _, client_address) =
          Timeout.timeout(EnvUtil.apply_timeout_scale(10)) { u.recvfrom(4096) }
        _, record = Resolv::DNS::TSIG.extract_tsig(query)
        response = server_sign(new_response_wire(query), record.mac,
                               secret: 'FEDCBA9876543210'.b)
        u.send(response, 0, client_address, client_port)
      end
      dns = Resolv::DNS.new(nameserver_port: [[address, port]], tsig: tsig)
      begin
        assert_raise(Resolv::DNS::TSIG::BadSignature) do
          Timeout.timeout(EnvUtil.apply_timeout_scale(10)) do
            dns.getresources('foo.example.org', Resolv::DNS::Resource::IN::A)
          end
        end
      ensure
        dns.close
      end
      assert_join_threads([server])
    end
  end

  def test_tcp_query_with_tsig
    tsig = new_tsig(clock: -> { Time.now })
    with_udp_and_tcp('127.0.0.1', 0) do |u, t|
      _, port, _, address = u.addr
      udp_server = Thread.new do
        query, (_, client_port, _, client_address) =
          Timeout.timeout(EnvUtil.apply_timeout_scale(10)) { u.recvfrom(4096) }
        _, record = Resolv::DNS::TSIG.extract_tsig(query)
        # Signed truncated response makes the client retry over TCP.
        id = query.unpack1('n')
        truncated = [id, 0x8300, 0, 0, 0, 0].pack('nnnnnn')
        u.send(server_sign(truncated, record.mac), 0, client_address, client_port)
      end
      tcp_server = Thread.new do
        socket = Timeout.timeout(EnvUtil.apply_timeout_scale(10)) { t.accept }
        begin
          length = socket.read(2).unpack1('n')
          query = socket.read(length)
          _, record = Resolv::DNS::TSIG.extract_tsig(query)
          assert_not_nil(record)
          response = server_sign(new_response_wire(query), record.mac)
          socket.write([response.bytesize].pack('n') << response)
        ensure
          socket.close
        end
      end
      dns = Resolv::DNS.new(nameserver_port: [[address, port]], tsig: tsig)
      begin
        resources = Timeout.timeout(EnvUtil.apply_timeout_scale(10)) do
          dns.getresources('foo.example.org', Resolv::DNS::Resource::IN::A)
        end
        assert_equal(['192.0.2.1'], resources.map {|r| r.address.to_s })
      ensure
        dns.close
      end
      assert_join_threads([udp_server, tcp_server])
    end
  end
end
