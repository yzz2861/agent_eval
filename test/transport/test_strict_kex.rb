require_relative '../common'
require 'net/ssh/transport/session'
require 'net/ssh/transport/kex/abstract'
require 'socket'
require 'openssl'

module Transport
  # Integration tests for the OpenSSH "strict key exchange" extension.
  # They drive a real Transport::Session (with the real Algorithms,
  # PacketStream and State objects) over a socket pair that is preloaded
  # with a fixed sequence of server packets, so no real SSH server is
  # needed. A fake key-exchange method speaks a trivial, deterministic
  # dialogue (INIT -> REPLY -> NEWKEYS) while reusing the real NEWKEYS
  # handling from Kex::Abstract.
  class TestStrictKex < NetSSHTest
    include Net::SSH::Transport::Constants

    CHANNEL_DATA = 94
    CHANNEL_OPEN = 90

    class FakeKex < Net::SSH::Transport::Kex::Abstract
      FAKE_INIT = 30
      FAKE_REPLY = 31

      def digester
        OpenSSL::Digest::SHA1
      end

      def exchange_keys
        connection.send_message(Net::SSH::Buffer.from(:byte, FAKE_INIT, :string, 'fake kex init'))

        reply = connection.next_message
        raise Net::SSH::Exception, 'expected REPLY' unless reply.type == FAKE_REPLY

        confirm_newkeys

        {
          session_id: 'fake session id',
          server_key: nil,
          shared_secret: OpenSSL::BN.new(42),
          hashing_algorithm: digester
        }
      end

      private

      def generate_key
        nil
      end
    end

    FAKE_KEX_NAME = 'diffie-hellman-group14-sha256'.freeze

    def setup
      @client_socket, @server_socket = Socket.pair(:UNIX, :STREAM, 0)
      @client_socket.define_singleton_method(:peer_ip) { '127.0.0.1' }
      Socket.stubs(:tcp).returns(@client_socket)

      @real_kex = Net::SSH::Transport::Kex::MAP[FAKE_KEX_NAME]
      Net::SSH::Transport::Kex::MAP[FAKE_KEX_NAME] = FakeKex

      @server_version_sent = false
    end

    def teardown
      Net::SSH::Transport::Kex::MAP[FAKE_KEX_NAME] = @real_kex
      @client_socket.close unless @client_socket.closed?
      @server_socket.close unless @server_socket.closed?
    end

    def test_strict_kex_initial_exchange_resets_sequence_numbers_at_newkeys
      write_server_packets kexinit_payload(strict: true), fake_reply_payload, newkeys_payload

      session = new_session

      assert session.algorithms.initialized?
      assert session.algorithms.strict_kex?
      assert_equal 0, session.socket.client.sequence_number
      assert_equal 0, session.socket.server.sequence_number

      # traffic in both directions counts from zero after the NEWKEYS boundary
      session.send_message(ignore_buffer)
      assert_equal 1, session.socket.client.sequence_number

      write_server_packets debug_payload
      session.poll_message(:nonblock)
      assert_equal 1, session.socket.server.sequence_number
    end

    def test_lenient_exchange_when_server_does_not_advertise_strict_kex
      write_server_packets ignore_payload, kexinit_payload(strict: false),
                           ignore_payload, debug_payload,
                           fake_reply_payload, newkeys_payload

      session = new_session

      assert session.algorithms.initialized?
      assert !session.algorithms.strict_kex?
      # sequence numbers are left alone when strict kex is not negotiated
      assert_equal 3, session.socket.client.sequence_number
      assert_equal 6, session.socket.server.sequence_number
    end

    def test_strict_kex_rejects_ignore_injected_during_exchange
      write_server_packets kexinit_payload(strict: true), ignore_payload,
                           fake_reply_payload, newkeys_payload

      error = assert_raises(Net::SSH::Exception) { new_session }
      assert_match(/unexpected packet type 2/, error.message)
    end

    def test_strict_kex_rejects_channel_message_injected_during_exchange
      write_server_packets kexinit_payload(strict: true), channel_open_payload,
                           fake_reply_payload, newkeys_payload

      error = assert_raises(Net::SSH::Exception) { new_session }
      assert_match(/unexpected packet type 90/, error.message)
    end

    def test_strict_kex_rejects_early_newkeys
      write_server_packets kexinit_payload(strict: true), newkeys_payload,
                           fake_reply_payload, newkeys_payload

      error = assert_raises(Net::SSH::Exception) { new_session }
      assert_match(/expected REPLY/, error.message)
    end

    def test_disconnect_during_strict_kex_raises_disconnect
      write_server_packets kexinit_payload(strict: true), disconnect_payload

      assert_raises(Net::SSH::Disconnect) { new_session }
    end

    def test_strict_kex_rekey_resets_sequence_numbers_in_both_directions
      write_server_packets kexinit_payload(strict: true), fake_reply_payload, newkeys_payload
      session = new_session

      # application traffic before the rekey
      session.send_message(ignore_buffer)
      write_server_packets channel_data_payload
      session.wait # enqueues the application packet

      write_server_packets kexinit_payload(strict: true), fake_reply_payload, newkeys_payload
      session.rekey!

      assert session.algorithms.strict_kex?
      assert_equal 0, session.socket.client.sequence_number
      assert_equal 0, session.socket.server.sequence_number

      # the application packet queued before the rekey is not lost
      packet = session.next_message
      assert_equal CHANNEL_DATA, packet.type

      # and new application traffic keeps flowing on the fresh key generation
      write_server_packets channel_data_payload
      packet = session.next_message
      assert_equal CHANNEL_DATA, packet.type
      assert_equal 1, session.socket.server.sequence_number
    end

    def test_strict_kex_rekey_rejects_message_injected_during_exchange
      write_server_packets kexinit_payload(strict: true), fake_reply_payload, newkeys_payload
      session = new_session

      write_server_packets kexinit_payload(strict: true), ignore_payload,
                           fake_reply_payload, newkeys_payload

      error = assert_raises(Net::SSH::Exception) { session.rekey! }
      assert_match(/unexpected packet type 2/, error.message)
    end

    def test_lenient_rekey_queues_application_packets_received_during_exchange
      write_server_packets kexinit_payload(strict: false), fake_reply_payload, newkeys_payload
      session = new_session

      write_server_packets kexinit_payload(strict: false), channel_data_payload,
                           fake_reply_payload, newkeys_payload
      session.rekey!

      # the packet that arrived mid-exchange was queued, not dropped
      packet = session.next_message
      assert_equal CHANNEL_DATA, packet.type
      # no sequence number reset without strict kex
      assert_equal 6, session.socket.client.sequence_number
      assert_equal 7, session.socket.server.sequence_number
    end

    private

    def new_session
      Net::SSH::Transport::Session.new('strict.test', session_options)
    end

    def session_options
      {
        encryption: 'none',
        hmac: 'none',
        verify_host_key: :never,
        user_known_hosts_file: '/dev/null',
        global_known_hosts_file: '/dev/null'
      }
    end

    # Appends the given payloads to the server's side of the socket,
    # framing each of them as an unencrypted, unauthenticated SSH packet
    # (matching the negotiated "none" cipher and hmac).
    def write_server_packets(*payloads)
      unless @server_version_sent
        @server_socket.write "SSH-2.0-StrictKexTestServer\r\n"
        @server_version_sent = true
      end

      payloads.each { |payload| @server_socket.write(frame(payload)) }
    end

    def frame(payload)
      padding_length = 8 - ((payload.bytesize + 5) % 8)
      padding_length += 8 if padding_length < 4
      packet_length = payload.bytesize + padding_length + 1
      if packet_length < 16
        padding_length += 8
        packet_length = payload.bytesize + padding_length + 1
      end
      [packet_length, padding_length, payload, "\0" * padding_length].pack('NCA*A*')
    end

    def kexinit_payload(strict:)
      kex = FAKE_KEX_NAME.dup
      kex += ',kex-strict-s-v00@openssh.com' if strict
      Net::SSH::Buffer.from(
        :byte, KEXINIT,
        :long, [1, 2, 3, 4],
        :string, kex,
        :string, 'ssh-rsa',
        :string, 'none', :string, 'none',
        :string, 'none', :string, 'none',
        :string, 'none', :string, 'none',
        :string, '', :string, '',
        :bool, false, :long, 0
      ).to_s
    end

    def fake_reply_payload
      Net::SSH::Buffer.from(:byte, FakeKex::FAKE_REPLY, :string, 'fake kex reply').to_s
    end

    def newkeys_payload
      Net::SSH::Buffer.from(:byte, NEWKEYS).to_s
    end

    def ignore_payload
      ignore_buffer.to_s
    end

    def ignore_buffer
      Net::SSH::Buffer.from(:byte, IGNORE, :string, 'ignore me')
    end

    def debug_payload
      Net::SSH::Buffer.from(:byte, DEBUG, :bool, false, :string, 'debug', :string, '').to_s
    end

    def disconnect_payload
      Net::SSH::Buffer.from(:byte, DISCONNECT, :long, 2, :string, 'bye', :string, '').to_s
    end

    def channel_data_payload
      Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, 'channel data').to_s
    end

    def channel_open_payload
      Net::SSH::Buffer.from(:byte, CHANNEL_OPEN, :string, 'session',
                            :long, 0, :long, 0x100000, :long, 0x4000).to_s
    end
  end
end
