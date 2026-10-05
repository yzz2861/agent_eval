# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'openssl'

class TestResolvDNSTSIG < Test::Unit::TestCase
  KEY_NAME = "key.example.com."
  SECRET = "topsecretkey123"
  ALGORITHM = "hmac-sha256."
  T0 = 0x12345678

  class FixedClock
    def initialize(time); @time = time; end
    attr_accessor :time
    def call; @time; end
  end

  # A requester that never touches a socket: #send records the request and
  # #recv_reply hands back a queued wire response.
  class LoopbackRequester < Resolv::DNS::Requester
    def initialize(tsig:)
      super(tsig: tsig)
      @reply = nil
      @handler = nil
      @socks = [self]
    end

    attr_accessor :handler

    def reply=(wire); @reply = wire; end

    def wait_readable(_); true; end

    def recv_reply(_, _ = nil)
      if @handler
        sender = @senders.values.last
        [@handler.call(sender.instance_variable_get(:@msg), sender.mac), nil]
      else
        [@reply, nil]
      end
    end

    def sender(msg, data, host = nil, port = nil)
      id = msg.id
      request, mac = finalize_request(msg, id)
      sender = Resolv::DNS::Requester::Sender.new(request, data, nil, mac)
      def sender.send; end
      @senders[[nil, id]] = sender
    end

    def run_with(sender, tout = 5)
      request(sender, tout)
    end
  end

  def setup
    @clock = FixedClock.new(T0)
    @tsig = Resolv::DNS::TSIG.new(KEY_NAME, SECRET, clock: @clock)
  end

  def unsigned_query
    msg = Resolv::DNS::Message.new(0x1234)
    msg.rd = 1
    msg.add_question("example.com", Resolv::DNS::Resource::IN::A)
    wire = msg.encode
    wire[0, 2] = [0x1234].pack("n")
    wire
  end

  def build_query_msg
    msg = Resolv::DNS::Message.new(0x1234)
    msg.rd = 1
    msg.add_question("example.com", Resolv::DNS::Resource::IN::A)
    msg
  end

  # Response that echoes the question and carries a TSIG record signed with
  # +mac+ as the request MAC.  The owner name is compressed, as a real server
  # sends it.
  def signed_response(mac, time: T0 + 5, fudge: 300, error: 0,
                     other_data: "".b, secret: SECRET, key_name: KEY_NAME,
                     algorithm: ALGORITHM, tamper: nil, owner_name: "key.example.com.")
    q = unsigned_query
    question = q[12..]
    signer = Resolv::DNS::TSIG.new(key_name, secret, fudge: fudge,
                                   algorithm: algorithm, clock: FixedClock.new(time))
    # The MAC covers the message with the TSIG excluded from ARCOUNT.
    unsigned = [0x1234, 0x8180, 1, 0, 0, 0].pack("nnnnnn") + question
    computed = signer.send(:mac_for, unsigned, 0x1234, time, error, other_data, mac, fudge)
    computed = tamper.call(computed) if tamper
    rr_owner = encode_owner(owner_name)
    rdata = tsig_rdata(algorithm, time, fudge, computed, 0x1234, error, other_data)
    header = [0x1234, 0x8180, 1, 0, 0, 1].pack("nnnnnn")
    header + question + rr_owner + [250, 255, 0, rdata.bytesize].pack("nnNn") + rdata
  end

  # Encodes the TSIG owner name with compression against the question, which
  # starts at offset 12 (example.com).
  def encode_owner(owner_name)
    owner = Resolv::DNS::Name.create(owner_name)
    suffix = Resolv::DNS::Name.create("example.com.")
    if owner.subdomain_of?(suffix)
      name = owner.to_a
      s = suffix.to_a
      prefix = name[0, name.length - s.length]
      Resolv::DNS::Message::MessageEncoder.new { |m|
        prefix.each { |label| m.put_string(label.to_s) }
        m.put_pack("n", 0xc000 | 12)
      }.to_s
    else
      Resolv::DNS::Message::MessageEncoder.new { |m|
        m.put_name(owner, compress: false)
      }.to_s
    end
  end

  def tsig_rdata(algorithm, time, fudge, mac, original_id, error, other_data)
    enc = Resolv::DNS::Message::MessageEncoder.new { |m|
      m.put_name(Resolv::DNS::Name.create(algorithm), compress: false)
      m.put_pack("nNn", (time >> 32) & 0xffff, time & 0xffffffff, fudge)
      m.put_pack("n", mac.bytesize)
      m.put_bytes(mac)
      m.put_pack("nnn", original_id, error, other_data.bytesize)
      m.put_bytes(other_data)
    }
    enc.to_s
  end

  def test_request_mac_matches_known_vector
    signed, mac = @tsig.sign_request(unsigned_query)
    # Verified independently against dnspython 2.7 (hmac-sha256, key
    # "topsecretkey123", time 0x12345678, fudge 300, id 0x1234).
    assert_equal("22e0b84b9e2fc2530e062f7217e270d2f000637de704a5cd464afa9159672a96",
                 mac.unpack1("H*"))
    assert_equal 1, signed[10, 2].unpack1("n")
    decoded = Resolv::DNS::Message.decode(signed)
    assert_instance_of Resolv::DNS::Resource::TSIG, decoded.additional.last[2]
  end

  def test_tsig_record_round_trips_and_is_not_query_data
    time = T0
    mac = "\xaa".b * 32
    rr = Resolv::DNS::Resource::TSIG.new(
      Resolv::DNS::Name.create(ALGORITHM), time, 300, mac, 0x4321, 0, "".b
    )
    msg = Resolv::DNS::Message.new(0x4321)
    msg.add_additional(KEY_NAME, 0, rr)
    decoded = Resolv::DNS::Message.decode(msg.encode)
    got = decoded.additional.last[2]
    assert_instance_of Resolv::DNS::Resource::TSIG, got
    assert_equal time, got.time_signed
    assert_equal 300, got.fudge
    assert_equal mac, got.mac
    assert_equal 0x4321, got.original_id
    assert_equal 0, got.error
    assert_equal ALGORITHM, got.algorithm_name.to_s + "."
    # TSIG lives only in additional and is never an answer.
    assert_empty decoded.answer
  end

  def test_badtime_other_data_must_be_six_bytes
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, time: T0 + 10_000, error: 18,
                               other_data: "\0".b * 4)
    assert_raise(Resolv::DNS::DecodeError) do
      @tsig.verify_response(response, mac)
    end
  end

  def test_roundtrip
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac)
    assert_nil @tsig.verify_response(response, mac)
  end

  def test_valid_response_accepted_by_requester
    requester = LoopbackRequester.new(tsig: @tsig)
    sender = requester.sender(build_query_msg, nil)
    requester.reply = signed_response(sender.mac)
    reply_msg, = requester.run_with(sender)
    assert_equal 0, reply_msg.rcode
  end

  def test_bad_signature_raises_and_is_not_accepted
    requester = LoopbackRequester.new(tsig: @tsig)
    sender = requester.sender(build_query_msg, nil)
    response = signed_response(sender.mac, tamper: ->(m) {
      n = m.dup
      n[0] = (n.getbyte(0) ^ 0xff).chr
      n
    })
    requester.reply = response
    assert_raise(Resolv::DNS::TSIGBadSigError) { requester.run_with(sender) }
  end

  def test_bad_signature_with_wrong_secret
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, secret: "another-secret!!")
    assert_raise(Resolv::DNS::TSIGBadSigError) do
      @tsig.verify_response(response, mac)
    end
  end

  def test_bad_key_name_raises
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, key_name: "other.key.",
                               owner_name: "other.key.")
    assert_raise(Resolv::DNS::TSIGBadKeyError) do
      @tsig.verify_response(response, mac)
    end
  end

  def test_bad_algorithm_raises
    # Build a record that claims a different algorithm but still has a valid
    # hmac-sha256 MAC over the wire; the claim must still be rejected.
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response_with_algorithm(mac, "hmac-sha1.")
    assert_raise(Resolv::DNS::TSIGBadKeyError) do
      @tsig.verify_response(response, mac)
    end
  end

  def signed_response_with_algorithm(mac, algorithm)
    time = T0 + 5
    q = unsigned_query
    header = [0x1234, 0x8180, 1, 0, 0, 1].pack("nnnnnn")
    body = header + q[12..]
    computed = @tsig.send(:mac_for, body, 0x1234, time, 0, "".b, mac, 300)
    rr_owner = "\x03key\xc0\x0c".b
    rdata = tsig_rdata(algorithm, time, 300, computed, 0x1234, 0, "".b)
    body + rr_owner + [250, 255, 0, rdata.bytesize].pack("nnNn") + rdata
  end

  def test_bad_time_raises
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, time: T0 + 10_000)
    assert_raise(Resolv::DNS::TSIGBadTimeError) do
      @tsig.verify_response(response, mac)
    end
  end

  def test_time_within_fudge_accepted
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, time: T0 + 300)
    assert_nil @tsig.verify_response(response, mac)
  end

  def test_fudge_boundary
    _, mac = @tsig.sign_request(unsigned_query)
    assert_nil @tsig.verify_response(signed_response(mac, time: T0 + 300, fudge: 300), mac)
    assert_raise(Resolv::DNS::TSIGBadTimeError) do
      @tsig.verify_response(signed_response(mac, time: T0 + 301, fudge: 300), mac)
    end
  end

  def test_server_reported_badtime_raises_badtime
    now_bytes = [0, T0].pack("nN")
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, time: T0 + 10_000, error: 18,
                               other_data: now_bytes)
    assert_raise(Resolv::DNS::TSIGBadTimeError) do
      @tsig.verify_response(response, mac)
    end
  end

  def test_server_reported_badkey_and_badsig
    _, mac = @tsig.sign_request(unsigned_query)
    [[17, Resolv::DNS::TSIGBadKeyError],
     [16, Resolv::DNS::TSIGBadSigError]].each do |rcode, klass|
      response = signed_response(mac, error: rcode, other_data: "".b)
      assert_raise(klass) { @tsig.verify_response(response, mac) }
    end
  end

  def test_response_without_tsig_is_a_local_format_error
    response = unsigned_query
    response[0, 2] = [0x1234].pack("n")
    response[10, 2] = [0].pack("n") # arcount 0
    @tsig.sign_request(unsigned_query)
    assert_raise(Resolv::DNS::DecodeError) do
      @tsig.verify_response(response, "x" * 32)
    end
  end

  def test_truncated_tsig_is_a_local_format_error
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac)
    assert_raise(Resolv::DNS::DecodeError) do
      @tsig.verify_response(response[0, response.bytesize - 4], mac)
    end
  end

  def test_tsig_not_last_record_is_format_error
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac)
    # Append trailing junk past the TSIG record.
    junked = response + "\0\0\0\0".b
    assert_raise(Resolv::DNS::DecodeError) do
      @tsig.verify_response(junked, mac)
    end
  end

  def test_mac_too_short_is_bad_sig
    _, mac = @tsig.sign_request(unsigned_query)
    response = signed_response(mac, tamper: ->(m) { m[0, 15] })
    assert_raise(Resolv::DNS::TSIGBadSigError) do
      @tsig.verify_response(response, mac)
    end
  end

  def test_only_hmac_sha256_accepted
    assert_raise(ArgumentError) do
      Resolv::DNS::TSIG.new(KEY_NAME, SECRET, algorithm: "hmac-sha1.")
    end
  end

  def test_fudge_validation
    assert_raise(ArgumentError) do
      Resolv::DNS::TSIG.new(KEY_NAME, SECRET, fudge: -1)
    end
  end

  def test_empty_key_rejected
    assert_raise(ArgumentError) { Resolv::DNS::TSIG.new(KEY_NAME, "") }
  end

  def test_clock_is_used
    clock = FixedClock.new(T0)
    t = Resolv::DNS::TSIG.new(KEY_NAME, SECRET, clock: clock)
    _, mac1 = t.sign_request(unsigned_query)
    clock.time = T0 + 1
    _, mac2 = t.sign_request(unsigned_query)
    assert_not_equal mac1, mac2
  end

  def test_no_tsig_requester_does_not_verify
    requester = Resolv::DNS::Requester.new
    assert_nil requester.instance_variable_get(:@tsig)
  end

  # Drives the whole Resolv::DNS fetch path with a TSIG configured as a Hash,
  # using an in-memory requester instead of a real socket.
  def test_end_to_end_fetch_verifies_before_returning_data
    dns = Resolv::DNS.new(
      nameserver_port: [["127.0.0.1", 53]],
      tsig: { key_name: KEY_NAME, key: SECRET, clock: FixedClock.new(T0) }
    )
    testcase = self
    dns.define_singleton_method(:make_udp_requester) do
      tsig = @config.requester_options[:tsig]
      r = LoopbackRequester.new(tsig: tsig)
      r.handler = ->(request, request_mac) {
        id = request[0, 2].unpack1("n")
        q_end = nil
        Resolv::DNS::Message::MessageDecoder.new(request) { |m|
          m.get_unpack("nnnnnn")
          qdcount = request[4, 2].unpack1("n")
          qdcount.times { m.get_question }
          q_end = m.index
        }
        question = request.byteslice(12, q_end - 12)
        answer = "\xc0\x0c".b + [1, 1, 3600, 4].pack("nnNn") +
                 [192, 0, 2, 1].pack("CCCC")
        testcase.send(:signed_answer_response, tsig, id, question, answer,
                      request_mac, T0 + 5)
      }
      r
    end

    resources = dns.getresources("example.com", Resolv::DNS::Resource::IN::A)
    assert_equal 1, resources.length
    assert_equal "192.0.2.1", resources[0].address.to_s
  ensure
    dns&.close
  end

  def signed_answer_response(signer, id, question, answer, mac, time)
    unsigned = [id, 0x8180, 1, 1, 0, 0].pack("nnnnnn") + question + answer
    computed = signer.send(:mac_for, unsigned, id, time, 0, "".b, mac, 300)
    rdata = tsig_rdata(ALGORITHM, time, 300, computed, id, 0, "".b)
    owner = encode_owner(KEY_NAME)
    [id, 0x8180, 1, 1, 0, 1].pack("nnnnnn") + question + answer +
      owner + [250, 255, 0, rdata.bytesize].pack("nnNn") + rdata
  end
end
