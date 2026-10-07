# frozen_string_literal: true

require_relative '../../test/common'
require 'net/ssh/service/forward/agent_proxy'
require 'stringio'

module Service
  class TestAgentProxy < NetSSHTest
    IDENTITIES = 11
    SIGN_REQUEST = 13
    EXTENSION = 27
    FAILURE = 30
    SUCCESS = 6
    SIGN_RESPONSE = 14

    class Policy
      def initialize(sign: true)
        @sign = sign
      end

      def allow_identities_request?(_request)
        true
      end

      def allow_sign?(_request)
        @sign
      end

      def filter_identities(identities)
        identities.reject { |identity| identity[:comment] == "denied" }
      end
    end

    class MemoryPipe
      def initialize
        @feed = StringIO.new
        @agent_writes = StringIO.new
        @channel_writes = StringIO.new
      end

      attr_reader :agent_writes, :channel_writes

      def send(data, *_args)
        @agent_writes.write(data)
      end

      def send_data(data)
        @channel_writes.write(data)
      end

      def on_data(*); end
      def on_extended_data(*); end
      def on_close(*); end
      def close; end

      def read(length)
        @feed.read(length)
      end

      def written
        parse_frames(@channel_writes.string).last
      end

      def sent_to_agent
        parse_frames(@agent_writes.string).last
      end

      def feed(frame)
        @feed.write(frame)
      end

      def parse_frames(data)
        frame_class = Net::SSH::Service::Forward::AgentProxy::Frame
        source = data.dup.force_encoding(Encoding::BINARY)
        frames = []
        until source.empty?
          length = source.unpack1("N")
          break unless length && source.bytesize >= 4 + length

          type = source.getbyte(4)
          payload = source.byteslice(5, length - 1)
          source.replace(source.byteslice(4 + length..-1) || +"")
          frame = frame_class.new(type: type, payload: payload)
          break unless frame

          frames << [frame.type, frame.payload]
        end
        frames
      end
    end

    def frame(type, payload = +"")
      payload = payload.to_s
      [payload.bytesize + 1, type].pack("NC") + payload.b
    end

    def identity_frame
      answer = Net::SSH::Buffer.new
      key = OpenSSL::PKey::RSA.new(512)
      answer.write_long(1)
      answer.write_string(Net::SSH::Buffer.from(:key, key).to_s)
      answer.write_string("allowed")
      [frame(12, answer.to_s), Net::SSH::Buffer.from(:key, key).to_s]
    end

    def sign_request(blob, data = "auth")
      frame(SIGN_REQUEST, Net::SSH::Buffer.from(:string, blob, :string, data, :long, 0))
    end

    def proxy_for(pipe, sign: true, with_binding: true)
      policy = Policy.new(sign: sign)
      binding = with_binding ? {
        host_key_algorithm: "ssh-rsa",
        session_id: "session",
        host_key_blob: Net::SSH::Buffer.from(:key, OpenSSL::PKey::RSA.new(512)).to_s
      } : nil
      Net::SSH::Service::Forward::AgentProxy.new(pipe, pipe, policy,
                                                 session_binding: binding, logger: nil)
    end

    def test_filters_identities_and_identity_responses
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe, with_binding: false)
      _identity_response, key_blob = identity_frame
      denied_key = OpenSSL::PKey::RSA.new(512)
      denied_blob = Net::SSH::Buffer.from(:key, denied_key).to_s

      proxy.receive_remote_data(frame(IDENTITIES))
      combined = Net::SSH::Buffer.new
      combined.write_long(2)
      combined.write_string(key_blob)
      combined.write_string("allowed")
      combined.write_string(denied_blob)
      combined.write_string("denied")
      proxy.receive_agent_data(frame(12, combined.to_s))
      type, payload = pipe.written
      answer = Net::SSH::Buffer.new(payload)
      assert_equal 12, type
      assert_equal 1, answer.read_long
      filtered_blob = answer.read_string
      assert_equal key_blob.b, filtered_blob.b
      assert_equal "allowed", answer.read_string
    end

    def test_signature_allowed_uses_policy_and_identity
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe, with_binding: false)
      identity_response, key_blob = identity_frame
      proxy.receive_remote_data(frame(IDENTITIES))
      proxy.receive_agent_data(identity_response)

      proxy.receive_remote_data(sign_request(key_blob, "ssh-auth"))
      proxy.receive_agent_data(frame(SIGN_RESPONSE, Net::SSH::Buffer.from(:string, "signed")))
      type, = pipe.written
      assert_equal SIGN_RESPONSE, type
    end

    def test_rejects_signatures_when_policy_disallows
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe, sign: false, with_binding: false)
      key_blob = Net::SSH::Buffer.from(:key, OpenSSL::PKey::RSA.new(512)).to_s
      proxy.receive_remote_data(sign_request(key_blob))
      type, = pipe.written
      assert_equal FAILURE, type
    end

    def test_requests_are_rejected_before_session_binding_completes
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe)

      proxy.receive_remote_data(frame(IDENTITIES))
      type, = pipe.written
      assert_equal FAILURE, type
    end

    def test_unknown_and_malformed_operations_return_failure
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe, with_binding: false)

      proxy.receive_remote_data(frame(17, "ignored"))
      type, = pipe.written
      assert_equal FAILURE, type
      proxy.receive_remote_data(frame(30))
      type, = pipe.written
      assert_equal FAILURE, type
    end

    def test_partial_requests_wait_for_complete_frame
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe, with_binding: false)
      request = frame(IDENTITIES)

      proxy.receive_remote_data(request.byteslice(0, 2))
      assert_nil pipe.written
      proxy.receive_remote_data(request.byteslice(2..-1))
      query_type, = pipe.sent_to_agent
      assert_equal IDENTITIES, query_type
    end

    def test_multiple_requests_keep_response_order
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe, with_binding: false)
      identity_response, _key_blob = identity_frame
      proxy.receive_remote_data(frame(IDENTITIES) + frame(IDENTITIES))
      proxy.receive_agent_data(identity_response + identity_response)
      frames = pipe.parse_frames(pipe.channel_writes.string)
      assert_equal [12, 12], frames.map(&:first)
    end

    def test_sends_complete_session_binding_information
      pipe = MemoryPipe.new
      proxy = proxy_for(pipe)
      proxy.start
      query_type, query_payload = pipe.sent_to_agent
      assert_equal EXTENSION, query_type
      assert_equal "query", Net::SSH::Buffer.new(query_payload).read_string
      proxy.receive_agent_data(frame(6, "query\0session-bind@openssh.com\0"))
      bind_type, bind_payload = pipe.sent_to_agent
      assert_equal EXTENSION, bind_type
      buffer = Net::SSH::Buffer.new(bind_payload)
      assert_equal "session-bind@openssh.com", buffer.read_string
      assert_equal "ssh-rsa", buffer.read_string
      assert_equal "session", buffer.read_string
      host_key_blob = buffer.read_string
      forwarded = buffer.read_bool
      assert host_key_blob.bytesize > 0
      assert forwarded
    end
  end
end
