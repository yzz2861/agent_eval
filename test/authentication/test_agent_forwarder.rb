require_relative '../common'
require 'net/ssh/authentication/agent_forward_policy'
require 'net/ssh/authentication/agent_forwarder'

module Authentication
  class TestAgentForwarder < NetSSHTest
    Policy = Net::SSH::Authentication::AgentForwardPolicy
    Forwarder = Net::SSH::Authentication::AgentForwarder

    IDENTITIES_REQUEST = 11
    IDENTITIES_ANSWER = 12
    SIGN_REQUEST = 13
    SIGN_RESPONSE = 14
    EXTENSION_REQUEST = 27
    SUCCESS = 6
    FAILURE = 30

    def setup
      @upstream = FakeForwardedAgent.new
      @allowed_key = "allowed-public-key"
      @denied_key = "denied-public-key"
      @policy = Policy.new(
        identities: [@allowed_key],
        signatures: { @allowed_key => :userauth }
      )
      @forwarder = Forwarder.new(@upstream, @policy, session_bind: valid_session_bind)
    end

    def test_fragmented_and_consecutive_requests_keep_message_boundaries_and_order
      requests = [
        request(IDENTITIES_REQUEST),
        sign_request(@allowed_key, userauth_data),
        sign_request(@allowed_key, "arbitrary data"),
        sign_request(@denied_key, userauth_data),
        request(99, Net::SSH::Buffer.from(:string, "ignored body").to_s),
        malformed_session_bind_request
      ]

      requests.each do |packet|
        packet.each_byte { |byte| @forwarder.send([byte].pack("C")) }
      end
      raw = @forwarder.read(8192)
      assert_equal requests.length, read_packet_count(raw)
      responses = parse_packets(raw, requests.length)

      assert_equal [IDENTITIES_ANSWER, SIGN_RESPONSE, FAILURE, FAILURE, FAILURE, FAILURE],
                   responses.map(&:first)
      identity_body = Net::SSH::Buffer.new(responses[0].last)
      assert_equal 1, identity_body.read_long
      assert_equal @allowed_key, strict_read_string(identity_body)
      assert_equal "allowed", strict_read_string(identity_body)
      assert identity_body.eof?
    end

    def test_visible_identity_does_not_allow_non_userauth_signatures
      @forwarder.send(request(IDENTITIES_REQUEST))
      @forwarder.send(sign_request(@allowed_key, "arbitrary data"))

      responses = read_responses(@forwarder, 2)

      assert_equal IDENTITIES_ANSWER, responses[0].first
      assert_equal FAILURE, responses[1].first
      assert_empty @upstream.signed_requests
    end

    def test_unknown_extension_is_denied_without_forwarding
      body = Net::SSH::Buffer.from(:string, "query").to_s
      upstream = FakeForwardedAgent.new
      forwarder = Forwarder.new(upstream, @policy)
      forwarder.send(request(EXTENSION_REQUEST, body))

      type, = read_responses(forwarder, 1).first

      assert_equal FAILURE, type
      assert_empty upstream.request_types
    end

    def test_malformed_session_bind_is_denied_without_forwarding
      upstream = FakeForwardedAgent.new
      forwarder = Forwarder.new(upstream, @policy)
      forwarder.send(malformed_session_bind_request)

      type, = read_responses(forwarder, 1).first

      assert_equal FAILURE, type
      assert_empty upstream.request_types
      assert_nil upstream.session_bind
    end

    def test_initial_session_bind_is_sent_to_compatible_agent
      assert_equal [EXTENSION_REQUEST], @upstream.request_types
      assert_equal(
        {
          name: Policy::SESSION_BIND_EXTENSION,
          session_id: valid_session_bind[:session_id],
          is_forwarding: 0,
          upstream_host_key: String.new,
          downstream_host_key: "server-host-key"
        },
        @upstream.session_bind
      )
    end

    def test_invalid_packet_length_returns_failure_and_closes_connection
      @forwarder.send([0, 0, 0, 0].pack("N"))

      type, = read_responses(@forwarder, 1).first

      assert_equal FAILURE, type
      assert @forwarder.closed?
      assert @upstream.closed?
    end

    private

    def valid_session_bind
      {
        session_id: "session-id",
        is_forwarding: false,
        upstream_host_key: String.new,
        downstream_host_key: "server-host-key"
      }
    end

    def request(type, body = String.new)
      [body.bytesize + 1].pack("N") + [type].pack("C") + body.b
    end

    def strict_read_string(buffer)
      length = buffer.content.byteslice(buffer.position, 4).unpack1("N")
      buffer.position += 4
      value = buffer.content.byteslice(buffer.position, length)
      buffer.position += length
      value
    end

    def sign_request(blob, data)
      request(SIGN_REQUEST, Net::SSH::Buffer.from(:string, blob, :string, data, :long, 0).to_s)
    end

    def userauth_data
      Net::SSH::Buffer.from(
        :string, "session-id",
        :byte, 50,
        :string, "bill",
        :string, "ssh-connection",
        :string, "publickey",
        :bool, true,
        :string, "ssh-ed25519",
        :string, @allowed_key,
        :string, "signature"
      ).to_s
    end

    def malformed_session_bind_request
      body = Net::SSH::Buffer.from(
        :string, Policy::SESSION_BIND_EXTENSION,
        :string, "bad-session",
        :long, 2,
        :string, String.new,
        :string, "server-host-key"
      ).to_s
      request(EXTENSION_REQUEST, body)
    end

    def read_responses(forwarder, count)
      raw = forwarder.read(8192)
      raise "timed out waiting for agent response" if raw.nil?
      parse_packets(raw, count)
    end

    def read_packet_count(raw)
      count = 0
      offset = 0
      while raw.bytesize - offset >= 4
        length = 4.times.map { |index| raw.getbyte(offset + index) }.pack('C4').unpack1('N')
        break unless raw.bytesize - offset >= 4 + length

        offset += 4 + length
        count += 1
      end
      count
    end

    def parse_packets(raw, count)
      offset = 0
      count.times.map do
        length = 4.times.map { |index| raw.getbyte(offset + index) }.pack('C4').unpack1('N')
        packet_start = offset + 4
        packet = raw.byteslice(packet_start...(packet_start + length))
        offset = packet_start + length
        body_data = packet.byteslice(1...packet.bytesize)
        [packet.getbyte(0), Net::SSH::Buffer.new(body_data)]
      end
    end

    class FakeForwardedAgent
      attr_reader :request_types, :signed_requests, :session_bind

      def initialize
        @queue = []
        @request_types = []
        @signed_requests = []
        @session_bind = nil
        @closed = false
      end

      def write(data)
        length = data.unpack1("N")
        packet = data.byteslice(4, length)
        type = packet.getbyte(0)
        body = Net::SSH::Buffer.new(packet.byteslice(1, packet.bytesize - 1))
        @request_types << type

        case type
        when IDENTITIES_REQUEST
          answer = Net::SSH::Buffer.from(
            :long, 2,
            :string, "allowed-public-key", :string, "allowed",
            :string, "denied-public-key", :string, "denied"
          )
          enqueue(IDENTITIES_ANSWER, answer.to_s)
        when SIGN_REQUEST
          @signed_requests << body.read_string
          enqueue(SIGN_RESPONSE, Net::SSH::Buffer.from(:string, "signature").to_s)
        when EXTENSION_REQUEST
          parse_extension(body)
          enqueue(SUCCESS)
        else
          enqueue(FAILURE)
        end
      end

      def send(data, _flags)
        write(data)
      end

      def read(length)
        return nil if @queue.empty?

        chunk = @queue.first.slice!(0, length)
        @queue.shift if @queue.first.empty?
        chunk
      end

      def close
        @closed = true
      end

      def closed?
        @closed
      end

      private

      def parse_extension(body)
        name = body.read_string
        if name == Policy::SESSION_BIND_EXTENSION
          @session_bind = {
            name: name,
            session_id: body.read_string,
            is_forwarding: body.read_long,
            upstream_host_key: body.read_string,
            downstream_host_key: body.read_string
          }
        end
      end

      def enqueue(type, body = String.new)
        @queue << ([body.bytesize + 1].pack("N") + [type].pack("C") + body.b)
      end
    end
  end
end
