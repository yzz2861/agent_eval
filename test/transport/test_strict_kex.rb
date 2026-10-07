# encoding: ASCII-8BIT

require_relative '../common'
require 'socket'
require 'net/ssh/transport/session'
require 'net/ssh/transport/kex'
require 'net/ssh/connection/constants'

module Transport
  # Full-stack tests for OpenSSH's "strict key exchange" extension
  # (kex-strict-c-v00@openssh.com / kex-strict-s-v00@openssh.com).
  #
  # Each test drives a real Net::SSH::Transport::Session over an in-memory
  # socket pair; the test itself plays the server side by feeding a fixed
  # sequence of packets into the pipe, so no real SSH server is involved.
  class TestStrictKex < NetSSHTest
    include Net::SSH::Transport::Constants
    include Net::SSH::Connection::Constants

    # A minimal key exchange strategy that speaks just enough of the SSH
    # transport protocol to exercise the state machine: it sends a
    # KEXDH_INIT, expects a KEXDH_REPLY, and then trades NEWKEYS messages.
    # The returned key material is constant, so the keys derived by the
    # transport are fully deterministic.
    class FakeKex
      include Net::SSH::Transport::Constants

      SESSION_ID = "fake-session-id".freeze
      SHARED_SECRET = OpenSSL::BN.new("1234567890", 10).freeze

      def initialize(_algorithms, connection, _data)
        @connection = connection
      end

      def exchange_keys
        @connection.send_message(Net::SSH::Buffer.from(:byte, KEXDH_INIT))

        reply = @connection.next_message
        raise Net::SSH::Exception, "expected KEXDH_REPLY, got type " + reply.type.to_s unless reply.type == KEXDH_REPLY

        @connection.send_message(Net::SSH::Buffer.from(:byte, NEWKEYS))

        newkeys = @connection.next_message
        raise Net::SSH::Exception, "expected NEWKEYS, got type " + newkeys.type.to_s unless newkeys.type == NEWKEYS

        { session_id: SESSION_ID,
          server_key: nil,
          shared_secret: SHARED_SECRET,
          hashing_algorithm: OpenSSL::Digest::SHA1 }
      end
    end

    KEX_NAME = 'strict-kex-test'.freeze
    STRICT_KEX_SERVER = 'kex-strict-s-v00@openssh.com'.freeze

    def setup
      Net::SSH::Transport::Kex::MAP[KEX_NAME] = FakeKex
      Net::SSH::Transport::Algorithms::ALGORITHMS[:kex] << KEX_NAME

      @client_io, @server_io = UNIXSocket.pair
      @server_io.extend(Net::SSH::Transport::PacketStream)
    end

    def teardown
      Net::SSH::Transport::Kex::MAP.delete(KEX_NAME)
      Net::SSH::Transport::Algorithms::ALGORITHMS[:kex].delete(KEX_NAME)

      [@client_io, @server_io].each do |io|
        io.close if io && !io.closed?
      end
    end

    # A legal strict-kex initial exchange: KEXINIT, KEXDH_REPLY, NEWKEYS.
    # Afterwards both directions must have switched to the new key
    # generation with their sequence numbers reset to zero.
    def test_legal_strict_exchange_resets_sequence_numbers_and_switches_both_directions
      start_server(strict: true)
      session = new_session

      assert session.algorithms.strict_kex?
      assert_equal 0, @client_io.client.sequence_number
      assert_equal 0, @client_io.server.sequence_number

      # the client sent KEXINIT, KEXDH_INIT and NEWKEYS in the clear
      read_client_version
      assert_equal KEXINIT, @server_io.next_packet(:block).type
      assert_equal KEXDH_INIT, @server_io.next_packet(:block).type
      assert_equal NEWKEYS, @server_io.next_packet(:block).type

      configure_server_end

      # client -> server under the new key generation; if the client had
      # not reset its sequence number, the server side hmac check would fail
      session.send_message(Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, "ping"))
      packet = @server_io.next_packet(:block)
      assert_equal CHANNEL_DATA, packet.type
      assert_equal 0, packet[:local_id]
      assert_equal "ping", packet[:data]

      # server -> client under the new key generation
      server_send(Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, "pong").to_s)
      packet = session.poll_message(:block)
      assert_equal CHANNEL_DATA, packet.type
      assert_equal 0, packet[:local_id]
      assert_equal "pong", packet[:data]
    end

    # When the server does not advertise strict kex support, the relaxed
    # legacy behavior must be preserved: injected IGNORE messages are
    # silently tolerated and sequence numbers are not reset.
    def test_non_strict_server_keeps_relaxed_compatibility_path
      start_server(strict: false, inject: [Net::SSH::Buffer.from(:byte, IGNORE, :string, "injected").to_s])
      session = new_session

      assert !session.algorithms.strict_kex?
      assert_equal 3, @client_io.client.sequence_number
      assert_equal 4, @client_io.server.sequence_number # KEXINIT, IGNORE, KEXDH_REPLY, NEWKEYS

      read_client_version
      3.times { @server_io.next_packet(:block) }
      configure_server_end(reset: false)

      # a NEWKEYS message outside a key exchange is passed through, not rejected
      server_send(Net::SSH::Buffer.from(:byte, NEWKEYS).to_s)
      assert_equal NEWKEYS, session.poll_message(:block).type
    end

    # Once strict kex is negotiated, unrelated messages injected into the
    # initial key exchange must no longer be silently ignored.
    def test_strict_exchange_rejects_message_injected_into_initial_exchange
      start_server(strict: true, inject: [Net::SSH::Buffer.from(:byte, IGNORE, :string, "injected").to_s])

      error = assert_raises(Net::SSH::Exception) { new_session }
      assert_match(/strict kex/, error.message)
    end

    # A NEWKEYS that arrives before the key exchange has reached its
    # NEWKEYS phase must abort the exchange.
    def test_strict_exchange_rejects_premature_newkeys
      start_server(strict: true, inject: [Net::SSH::Buffer.from(:byte, NEWKEYS).to_s])

      assert_raises(Net::SSH::Exception) { new_session }
    end

    # A NEWKEYS that arrives when no key exchange is pending at all is a
    # protocol violation under strict kex.
    def test_strict_kex_rejects_unexpected_newkeys
      start_server(strict: true)
      session = new_session

      read_client_version
      3.times { @server_io.next_packet(:block) }
      configure_server_end

      server_send(Net::SSH::Buffer.from(:byte, NEWKEYS).to_s)
      error = assert_raises(Net::SSH::Exception) { session.poll_message(:block) }
      assert_match(/NEWKEYS/, error.message)
    end

    # A strict-kex rekey: unrelated packets in flight during the rekey are
    # tolerated (queued, not dropped), and both directions switch to the
    # new key generation with sequence numbers reset to zero again.
    def test_strict_rekey_queues_in_flight_packets_and_resets_sequence_numbers
      start_server(strict: true)
      session = new_session
      assert_equal 0, @client_io.client.sequence_number

      read_client_version
      3.times { @server_io.next_packet(:block) }
      configure_server_end

      # script the rekey: the server KEXINIT, an IGNORE and an application
      # packet that are already in flight, then the kex reply and NEWKEYS
      server_send(server_kexinit(strict: true))
      server_send(Net::SSH::Buffer.from(:byte, IGNORE, :string, "in flight").to_s)
      server_send(Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, "in-flight data").to_s)
      server_send(Net::SSH::Buffer.from(:byte, KEXDH_REPLY).to_s)
      server_send(Net::SSH::Buffer.from(:byte, NEWKEYS).to_s)

      session.rekey!

      # the second NEWKEYS boundary reset both sequence numbers again
      assert_equal 0, @client_io.client.sequence_number
      assert_equal 0, @client_io.server.sequence_number

      # the application packet that arrived mid-rekey was queued, not dropped
      packet = session.poll_message(:block)
      assert_equal CHANNEL_DATA, packet.type
      assert_equal 0, packet[:local_id]
      assert_equal "in-flight data", packet[:data]

      # the client rekey messages went out under the previous key generation
      assert_equal KEXINIT, @server_io.next_packet(:block).type
      assert_equal KEXDH_INIT, @server_io.next_packet(:block).type
      assert_equal NEWKEYS, @server_io.next_packet(:block).type

      configure_server_end

      # both directions work under the new key generation
      session.send_message(Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, "post-rekey ping"))
      packet = @server_io.next_packet(:block)
      assert_equal CHANNEL_DATA, packet.type
      assert_equal 0, packet[:local_id]
      assert_equal "post-rekey ping", packet[:data]

      server_send(Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, "post-rekey pong").to_s)
      packet = session.poll_message(:block)
      assert_equal CHANNEL_DATA, packet.type
      assert_equal 0, packet[:local_id]
      assert_equal "post-rekey pong", packet[:data]
    end

    private

    # Writes the server version line and the initial key exchange packets
    # (KEXINIT, any injected packets, KEXDH_REPLY, NEWKEYS) into the pipe.
    def start_server(strict:, inject: [])
      @server_io.write("SSH-2.0-StrictKexTestServer\r\n")
      server_send(server_kexinit(strict: strict))
      inject.each { |payload| server_send(payload) }
      server_send(Net::SSH::Buffer.from(:byte, KEXDH_REPLY).to_s)
      server_send(Net::SSH::Buffer.from(:byte, NEWKEYS).to_s)
    end

    def server_kexinit(strict:)
      kex = [KEX_NAME]
      kex << STRICT_KEX_SERVER if strict

      Net::SSH::Buffer.from(:byte, KEXINIT,
                            :long, 1, :long, 2, :long, 3, :long, 4,
                            :mstring, kex.join(','),
                            :mstring, 'ssh-rsa',
                            :mstring, 'aes256-ctr', :mstring, 'aes256-ctr',
                            :mstring, 'hmac-sha2-256', :mstring, 'hmac-sha2-256',
                            :mstring, 'none', :mstring, 'none',
                            :mstring, '', :mstring, '',
                            :bool, false, :long, 0).to_s
    end

    def server_send(payload)
      @server_io.send_packet(payload)
    end

    # Reads the client version string from the pipe. Uses recv directly so
    # that the socket does not mix buffered and unbuffered reads.
    def read_client_version
      line = +""
      line << @server_io.recv(1) until line.end_with?("\n")
      line
    end

    def new_session
      client = @client_io
      proxy = Object.new
      proxy.define_singleton_method(:open) { |*_args| client }

      Net::SSH::Transport::Session.new(
        'net.ssh.test',
        proxy: proxy,
        kex: KEX_NAME,
        host_key: 'ssh-rsa',
        encryption: 'aes256-ctr',
        hmac: 'hmac-sha2-256',
        verify_host_key: :never,
        user_known_hosts_file: '/dev/null',
        global_known_hosts_file: '/dev/null'
      )
    end

    # Configures the server end of the pipe with the key material that the
    # transport derives from FakeKex's constant exchange result, mimicking
    # a strict-kex server installing the new key generation.
    def configure_server_end(reset: true)
      key = key_material
      params = { shared: FakeKex::SHARED_SECRET.to_ssh, hash: FakeKex::SESSION_ID, digester: OpenSSL::Digest::SHA1 }

      @server_io.client.set(
        cipher: Net::SSH::Transport::CipherFactory.get('aes256-ctr', params.merge(iv: key['B'], key: key['D'], encrypt: true)),
        hmac: Net::SSH::Transport::HMAC.get('hmac-sha2-256', key['F'], params)
      )
      @server_io.server.set(
        cipher: Net::SSH::Transport::CipherFactory.get('aes256-ctr', params.merge(iv: key['A'], key: key['C'], decrypt: true)),
        hmac: Net::SSH::Transport::HMAC.get('hmac-sha2-256', key['E'], params)
      )

      return unless reset

      @server_io.client.reset_sequence_number
      @server_io.server.reset_sequence_number
    end

    # Mirrors the key derivation in Algorithms#exchange_keys.
    def key_material
      secret = FakeKex::SHARED_SECRET.to_ssh
      digester = OpenSSL::Digest::SHA1
      ->(salt) { digester.digest(secret + FakeKex::SESSION_ID + salt + FakeKex::SESSION_ID) }
    end
  end
end
