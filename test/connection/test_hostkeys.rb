require_relative '../common'
require 'net/ssh/connection/session'
require 'logger'
require 'tmpdir'

module Connection
  class TestHostkeys < NetSSHTest
    include Net::SSH::Connection::Constants

    HOST = 'rotated.example.com'
    SESSION_ID = 'abcxyz123'

    def setup
      @old_key = OpenSSL::PKey::RSA.new(2048)
      @new_key = OpenSSL::PKey::RSA.new(2048)
      @extra_key = OpenSSL::PKey::RSA.new(2048)
      @dir = Dir.mktmpdir('net-ssh-hostkeys')
      @counter = 0
    end

    def teardown
      begin
        File.chmod(0o755, @dir)
        Dir.children(@dir).each do |name|
          path = File.join(@dir, name)
          File.chmod(0o644, path) if File.file?(path)
        end
      rescue SystemCallError
        nil
      end
      FileUtils.remove_entry(@dir)
    end

    # ---- successful rotation (add policy) ----------------------------------

    def test_valid_proofs_update_known_hosts_with_announced_new_keys
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      # Client must request proofs for exactly the announced, not-yet-trusted key.
      hostkeys.announce(announce_data([@old_key, @new_key]))
      captured = @captured_requests.last

      assert_equal 'hostkeys-prove-00@openssh.com', captured[:type]
      assert_equal [@new_key.to_blob], captured[:blobs]
      assert captured[:want_reply]

      transport_of(session).return(REQUEST_SUCCESS, :string, proof_signature(hostkeys, @new_key))
      process_once(session)

      keys = Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
      assert_includes keys, @old_key.to_blob
      assert_includes keys, @new_key.to_blob
    end

    # ---- successful rotation (replace policy) ------------------------------

    def test_replace_policy_removes_announced_keys_and_writes_proven_ones
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :replace, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key, @new_key]))
      transport_of(session).return(REQUEST_SUCCESS, :string, proof_signature(hostkeys, @new_key))
      process_once(session)

      keys = Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
      refute_includes keys, @old_key.to_blob
      assert_equal [@new_key.to_blob], keys
    end

    # ---- partial proof failure: whole batch rejected, file untouched -------

    def test_one_invalid_proof_rejects_the_batch_and_keeps_file
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key, @new_key, @extra_key]))
      good = proof_signature(hostkeys, @new_key)
      wrong = proof_signature(hostkeys, @extra_key, sign_key: @old_key)
      transport_of(session).return(REQUEST_SUCCESS, :string, good, :string, wrong)

      assert_raises(Net::SSH::HostKeyProofFailed) do
        process_once(session)
      end

      keys = Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
      assert_equal [@old_key.to_blob], keys
    end

    def test_missing_proof_rejects_the_batch
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key, @new_key, @extra_key]))
      # Only one signature although two proofs were requested.
      transport_of(session).return(REQUEST_SUCCESS, :string, proof_signature(hostkeys, @new_key))

      assert_raises(Net::SSH::HostKeyProofFailed) do
        process_once(session)
      end

      keys = Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
      assert_equal [@old_key.to_blob], keys
    end

    def test_prove_request_failure_does_not_update_known_hosts
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key, @new_key]))
      transport_of(session).return(REQUEST_FAILURE)
      process_once(session)

      keys = Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
      assert_equal [@old_key.to_blob], keys
    end

    # ---- file write failure propagates and preserves the original file ------

    def test_write_failure_raises_and_preserves_original_file
      skip 'root bypasses file permissions' if Process.uid.zero?

      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key, @new_key]))
      transport_of(session).return(REQUEST_SUCCESS, :string, proof_signature(hostkeys, @new_key))

      File.chmod(0o444, file)
      File.chmod(0o555, File.dirname(file))

      begin
        assert_raises(SystemCallError) { process_once(session) }
      ensure
        File.chmod(0o755, File.dirname(file))
        File.chmod(0o644, file)
      end

      keys = Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
      assert_equal [@old_key.to_blob], keys
    end

    # ---- proofs must be bound to this session id ---------------------------

    def test_proof_signed_for_another_session_is_rejected
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key, @new_key]))
      data = Net::SSH::Buffer.from(
        :string, 'hostkeys-prove-00@openssh.com',
        :string, 'a-different-session-id',
        :string, '1',
        :string, @new_key.to_blob
      ).to_s
      sig = Net::SSH::Buffer.from(:string, @new_key.ssh_signature_type,
                                  :string, @new_key.ssh_do_sign(data))
      transport_of(session).return(REQUEST_SUCCESS, :string, sig.to_s)

      assert_raises(Net::SSH::HostKeyProofFailed) do
        process_once(session)
      end

      assert_equal [@old_key.to_blob],
                   Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
    end

    def test_announcement_with_only_known_keys_requests_no_proofs
      file = write_known_hosts(line_for(HOST, @old_key))
      session = build_session(update_host_keys: :add, known_hosts_file: file)
      hostkeys = session.hostkeys

      hostkeys.announce(announce_data([@old_key]))

      assert_equal [], session.pending_requests
      assert_equal [@old_key.to_blob],
                   Net::SSH::KnownHosts.new(file).keys_for(HOST).map(&:to_blob)
    end

    private

    def build_session(update_host_keys:, known_hosts_file:)
      socket = Object.new
      socket.extend(Net::SSH::Transport::PacketStream)
      socket.define_singleton_method(:enqueue_packet) { |message| enqueue(message.to_s) }

      options = {
        update_host_keys: update_host_keys,
        logger: logger,
        user_known_hosts_file: [known_hosts_file],
        global_known_hosts_file: []
      }
      transport = MockTransport.new(options.merge(socket: socket))
      transport.mock_enqueue = true
      transport.host_as_string = HOST
      session = Net::SSH::Connection::Session.new(transport, options)
      @captured_requests = []
      transport.expect do |_mock, packet|
        next unless packet.type == GLOBAL_REQUEST

        data = packet[:request_data]
        blobs = []
        blobs << data.read_string until data.eof?
        @captured_requests << { type: packet[:request_type], want_reply: packet[:want_reply], blobs: blobs }
      end
      session
    end

    def logger
      @logger ||= ::Logger.new(IO::NULL)
    end

    def transport_of(session)
      session.transport
    end

    # The first iteration dispatches queued packets (including the prove
    # reply); the block only aborts on the second iteration.
    def process_once(session)
      iterations = 0
      session.process { (iterations += 1) < 2 }
    end

    def write_known_hosts(content)
      @counter += 1
      path = File.join(@dir, "known_hosts#{@counter}")
      File.write(path, content)
      path
    end

    def line_for(host, key)
      blob = [key.to_blob].pack('m*').gsub(/\s/, '')
      "#{host} #{key.ssh_type} #{blob}\n"
    end

    def announce_data(keys)
      Net::SSH::Buffer.new(
        Net::SSH::Buffer.from(*keys.flat_map { |key| [:string, key.to_blob] }).to_s
      )
    end

    def proof_signature(hostkeys, key, sign_key: key)
      data = hostkeys.send(:proof_data, key)
      Net::SSH::Buffer.from(:string, key.ssh_signature_type,
                            :string, sign_key.ssh_do_sign(data)).to_s
    end

  end
end
