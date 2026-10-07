require_relative "../common"
require "net/ssh/connection/session"
require "net/ssh/connection/host_key_rotator"

module Connection
  class TestHostKeyRotator < NetSSHTest
    include Net::SSH::Connection::Constants

    SESSION_ID = "abcxyz123"
    USERNAME = "tester"

    def test_rotates_verified_host_keys
      current_key, new_key = keys
      file = known_hosts_file(current_key)
      session = build_session(file, update_host_keys: true)
      proofs = proof_data([new_key])

      expect_request(session, REQUEST_SUCCESS, proofs, [new_key], REQUEST_SUCCESS)
      process_scripted_packets(session)

      learned = Net::SSH::KnownHosts.new(file.path).keys_for(host)
      assert_equal [current_key.to_blob, new_key.to_blob].sort, learned.map(&:to_blob).sort
    ensure
      file&.close! unless file&.closed?
    end

    def test_rejects_batch_when_one_proof_is_invalid
      current_key, valid_key, invalid_key = keys(3)
      file = known_hosts_file(current_key)
      session = build_session(file, update_host_keys: true)
      original = File.read(file.path)
      proofs = proof_data([valid_key, invalid_key], invalid_key_blob: invalid_key.to_blob)

      expect_request(session, REQUEST_SUCCESS, proofs, [valid_key, invalid_key], REQUEST_FAILURE)
      process_scripted_packets(session)

      assert_equal original, File.read(file.path)
      assert_equal [current_key.to_blob],
                   Net::SSH::KnownHosts.new(file.path).keys_for(host).map(&:to_blob)
    ensure
      file&.close! unless file&.closed?
    end

    def test_preserves_file_when_known_hosts_update_fails
      current_key, new_key = keys
      file = known_hosts_file(current_key)
      session = build_session(file, update_host_keys: :replace)
      proofs = proof_data([new_key])
      original = File.read(file.path)
      Net::SSH::KnownHosts.any_instance.stubs(:write_atomically).raises(Errno::EACCES)

      expect_request(session, REQUEST_SUCCESS, proofs, [new_key], REQUEST_FAILURE)
      process_scripted_packets(session)

      assert_equal original, File.read(file.path)
    ensure
      file&.close! unless file&.closed?
    end

    private

    def keys(count = 2)
      Array.new(count) { OpenSSL::PKey::EC.generate("prime256v1") }
    end

    def process_scripted_packets(session)
      iterations = 0
      session.process(0) { (iterations += 1) < 2 }
    end

    def host
      "net.ssh.test,127.0.0.1"
    end

    def known_hosts_file(current_key)
      file = Tempfile.new("known_hosts")
      file.puts "#{host} #{current_key.ssh_type} #{[current_key.to_blob].pack("m0")}"
      file.flush
      file
    end

    def build_session(file, options)
      socket = Object.new
      socket.extend(Net::SSH::Transport::PacketStream)
      transport = MockTransport.new(socket: socket,
                                   update_host_keys: options.fetch(:update_host_keys),
                                   user_known_hosts_file: [file.path],
                                   global_known_hosts_file: [],
                                   user: USERNAME)
      transport.mock_enqueue = true
      transport.server_host_key = current_key_for(file)
      session = Net::SSH::Connection::Session.new(transport, transport.options)
      Net::SSH::Connection::HostKeyRotator.new(session, USERNAME).install
      session
    end

    def current_key_for(file)
      Net::SSH::KnownHosts.new(file.path).keys_for(host).first.__getobj__
    end

    def expect_request(session, response_type, response_data, announced_new_keys, expected_reply)
      transport = session.transport
      current_key = transport.server_host_key
      announcement = Net::SSH::Buffer.from(
        *([:raw, current_key.to_blob] + announced_new_keys.flat_map { |key| [:raw, key.to_blob] })
      ).to_s

      transport.return(GLOBAL_REQUEST,
                       :string, Net::SSH::Connection::HostKeyRotator::HOSTKEYS_REQUEST,
                       :bool, true,
                       :raw, announcement)
      transport.return(response_type, :raw, response_data)

      transport.expect do |_transport, packet|
        assert_equal GLOBAL_REQUEST, packet.type
        assert_equal Net::SSH::Connection::HostKeyRotator::PROVE_REQUEST, packet[:request_type]
        assert packet[:want_reply]
        data = packet[:request_data]
        assert_equal SESSION_ID, data.read_string
        assert_equal USERNAME, data.read_string
        assert_equal Net::SSH::Connection::HostKeyRotator::SERVICE, data.read_string
        assert data.eof?

        transport.expect do |_reply_transport, reply|
          assert_equal expected_reply, reply.type
        end
      end
    end

    def proof_data(new_keys, invalid_key_blob: nil)
      signed_data = Net::SSH::Buffer.from(
        :string, SESSION_ID,
        :string, USERNAME,
        :string, Net::SSH::Connection::HostKeyRotator::SERVICE,
        :string, Net::SSH::Connection::HostKeyRotator::PROVE_REQUEST
      ).to_s

      Net::SSH::Buffer.from(*new_keys.flat_map do |key|
        signature = key.to_blob == invalid_key_blob ? "invalid-signature" : key.ssh_do_sign(signed_data)
        [:raw, key.to_blob, :string, key.ssh_type, :string, signature]
      end).to_s
    end

  end
end
