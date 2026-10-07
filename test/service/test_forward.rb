require_relative '../common'
require 'net/ssh/connection/session'
require 'net/ssh/service/forward'
require 'tempfile'

module Service
  class TestForward < NetSSHTest
    include Net::SSH::Connection::Constants

    # Bypass the packet stream overhead so that outbound messages can be
    # asserted exactly, like the connection/session tests do.
    module PlainEnqueue
      def enqueue_packet(message)
        enqueue(message.to_s)
      end
    end

    def setup
      @transport_socket, @transport_peer = UNIXSocket.pair
      @transport_socket.extend(Net::SSH::Transport::PacketStream)
      @transport_socket.extend(PlainEnqueue)
      @transport = MockTransport.new(socket: @transport_socket)
      @transport.mock_enqueue = true
      @session = Net::SSH::Connection::Session.new(@transport, {})
      @forward = @session.forward
    end

    def teardown
      @transport_peer.close
      @transport_socket.close
    end

    def test_remote_socket_sends_streamlocal_forward_request
      establish_remote_socket("/remote.sock", "/local.sock")

      assert_equal ["/remote.sock"], @forward.active_remote_sockets
      assert_equal({ "/remote.sock" => "/local.sock" }, @forward.active_remote_socket_destinations)
    end

    def test_remote_socket_yields_path_to_block_on_success
      expect_global_request("streamlocal-forward@openssh.com", "/remote.sock")
      yielded = nil
      @forward.remote_socket("/remote.sock", "/local.sock") { |path| yielded = path }
      @transport.return(REQUEST_SUCCESS)
      process_times(2)

      assert_equal "/remote.sock", yielded
    end

    def test_remote_socket_failure_is_not_listed_and_raises
      expect_global_request("streamlocal-forward@openssh.com", "/remote.sock")
      @forward.remote_socket("/remote.sock", "/local.sock")
      @transport.return(REQUEST_FAILURE)

      assert_raises(Net::SSH::Exception) { process_times(2) }
      assert_equal [], @forward.active_remote_sockets
      assert_equal({}, @forward.active_remote_socket_destinations)
    end

    def test_remote_socket_failure_can_be_suppressed_with_block
      expect_global_request("streamlocal-forward@openssh.com", "/remote.sock")
      yielded = nil
      @forward.remote_socket("/remote.sock", "/local.sock") do |result|
        yielded = result
        :no_exception
      end
      @transport.return(REQUEST_FAILURE)
      process_times(2)

      assert_equal :error, yielded
      assert_equal [], @forward.active_remote_sockets
    end

    def test_cancel_remote_socket
      establish_remote_socket("/remote.sock", "/local.sock")

      expect_global_request("cancel-streamlocal-forward@openssh.com", "/remote.sock")
      @forward.cancel_remote_socket("/remote.sock")
      @transport.return(REQUEST_SUCCESS)
      process_times(2)

      assert_equal [], @forward.active_remote_sockets
      assert_equal({}, @forward.active_remote_socket_destinations)
    end

    def test_cancel_remote_socket_failure_keeps_mapping
      establish_remote_socket("/remote.sock", "/local.sock")

      expect_global_request("cancel-streamlocal-forward@openssh.com", "/remote.sock")
      @forward.cancel_remote_socket("/remote.sock")
      @transport.return(REQUEST_FAILURE)

      assert_raises(Net::SSH::Exception) { process_times(2) }
      assert_equal ["/remote.sock"], @forward.active_remote_sockets
    end

    def test_active_remote_sockets_cleared_when_session_closes
      establish_remote_socket("/remote.sock", "/local.sock")
      assert_equal ["/remote.sock"], @forward.active_remote_sockets

      @transport.stubs(:closed?).returns(true)

      assert_equal [], @forward.active_remote_sockets
      assert_equal({}, @forward.active_remote_socket_destinations)
    end

    def test_forwarded_streamlocal_channel_for_unknown_path_is_rejected
      @transport.return(CHANNEL_OPEN, :string, "forwarded-streamlocal@openssh.com",
                        :long, 7, :long, 0x20000, :long, 0x8000,
                        :string, "/remote.sock", :string, "")
      @transport.expect do |_t, packet|
        assert_equal CHANNEL_OPEN_FAILURE, packet.type
        assert_equal 7, packet[:local_id]
        assert_equal 1, packet[:reason_code]
      end
      process_times(2)

      assert_equal({}, @session.channels)
    end

    def test_forwarded_streamlocal_channel_is_rejected_when_local_socket_unreachable
      establish_remote_socket("/remote.sock", "/no/such/local.sock")

      @transport.return(CHANNEL_OPEN, :string, "forwarded-streamlocal@openssh.com",
                        :long, 7, :long, 0x20000, :long, 0x8000,
                        :string, "/remote.sock", :string, "")
      @transport.expect do |_t, packet|
        assert_equal CHANNEL_OPEN_FAILURE, packet.type
        assert_equal 7, packet[:local_id]
        assert_equal 2, packet[:reason_code]
      end
      process_times(2)

      assert_equal({}, @session.channels)
    end

    def test_forwarded_streamlocal_channel_half_close_delivers_all_data
      with_unix_server do |server, local_path|
        establish_remote_socket("/remote.sock", local_path)
        local_id = open_forwarded_streamlocal_channel("/remote.sock")

        accepted = server.accept
        begin
          payload = "item1" + 10.chr
          payload *= 40_000
          received = +""
          reader = Thread.start do
            loop { received << accepted.readpartial(16_384) }
          rescue EOFError
            received
          end

          # The server sends its final data chunk and immediately half-closes
          # the channel; the pending data must be flushed to the local socket
          # before the write side is shut down.
          @transport.return(CHANNEL_DATA, :long, local_id, :string, payload)
          @transport.return(CHANNEL_EOF, :long, local_id)
          @transport.expect do |_t, packet|
            assert_equal CHANNEL_WINDOW_ADJUST, packet.type
          end
          process_times(2)

          assert_equal payload, reader.join(5).value
        ensure
          accepted.close
          reader.kill if reader.alive?
        end
      end
    end

    def test_forwarded_streamlocal_channel_sends_local_data_to_server
      with_unix_server do |server, local_path|
        establish_remote_socket("/remote.sock", local_path)
        open_forwarded_streamlocal_channel("/remote.sock")

        accepted = server.accept
        begin
          accepted.write("ping")

          @transport.expect do |_t, packet|
            assert_equal CHANNEL_DATA, packet.type
            assert_equal 7, packet[:local_id]
            assert_equal "ping", packet[:data]
          end
          # first pass notices the readable socket, second pass delivers the data
          @session.process(0.1)
          @session.process(0.1)
        ensure
          accepted.close
        end
      end
    end

    def test_cancel_remote_socket_rejects_new_channels_but_keeps_accepted_ones
      with_unix_server do |server, local_path|
        establish_remote_socket("/remote.sock", local_path)
        local_id = open_forwarded_streamlocal_channel("/remote.sock")
        accepted = server.accept

        begin
          expect_global_request("cancel-streamlocal-forward@openssh.com", "/remote.sock")
          @forward.cancel_remote_socket("/remote.sock")
          @transport.return(REQUEST_SUCCESS)
          process_times(2)
          assert_equal [], @forward.active_remote_sockets

          # new connections for the cancelled path are rejected
          @transport.return(CHANNEL_OPEN, :string, "forwarded-streamlocal@openssh.com",
                            :long, 8, :long, 0x20000, :long, 0x8000,
                            :string, "/remote.sock", :string, "")
          @transport.expect do |_t, packet|
            assert_equal CHANNEL_OPEN_FAILURE, packet.type
            assert_equal 8, packet[:local_id]
            assert_equal 1, packet[:reason_code]
          end
          process_times(2)

          # the already accepted connection is unaffected and runs to completion
          @transport.return(CHANNEL_DATA, :long, local_id, :string, "still here")
          process_times(2)
          @session.process(0.1)
          assert_equal "still here", accepted.readpartial(1024)
        ensure
          accepted.close
        end
      end
    end

    def test_forwarded_streamlocal_channel_close_closes_local_socket
      with_unix_server do |server, local_path|
        establish_remote_socket("/remote.sock", local_path)
        local_id = open_forwarded_streamlocal_channel("/remote.sock")
        accepted = server.accept

        begin
          @transport.return(CHANNEL_CLOSE, :long, local_id)
          @transport.expect do |_t, packet|
            assert_equal CHANNEL_CLOSE, packet.type
            assert_equal 7, packet[:local_id]
          end
          process_times(2)

          assert_equal({}, @session.channels)
          assert_raises(EOFError) { accepted.readpartial(1024) }
        ensure
          accepted.close
        end
      end
    end

    private

    def process_times(n)
      i = 0
      @session.process { (i += 1) < n }
    end

    def expect_global_request(request_type, path)
      @transport.expect do |_t, packet|
        assert_equal GLOBAL_REQUEST, packet.type
        assert_equal request_type, packet[:request_type]
        assert_equal true, packet[:want_reply]
        assert_equal path, packet[:request_data].read_string
      end
    end

    def establish_remote_socket(remote_path, local_path)
      expect_global_request("streamlocal-forward@openssh.com", remote_path)
      @forward.remote_socket(remote_path, local_path)
      @transport.return(REQUEST_SUCCESS)
      process_times(2)
      assert_equal [remote_path], @forward.active_remote_sockets
    end

    def open_forwarded_streamlocal_channel(remote_path, remote_id = 7)
      @transport.return(CHANNEL_OPEN, :string, "forwarded-streamlocal@openssh.com",
                        :long, remote_id, :long, 0x20000, :long, 0x8000,
                        :string, remote_path, :string, "")
      local_id = nil
      @transport.expect do |_t, packet|
        assert_equal CHANNEL_OPEN_CONFIRMATION, packet.type
        assert_equal remote_id, packet[:local_id]
        local_id = packet[:remote_id]
      end
      process_times(2)
      local_id
    end

    def with_unix_server
      file = Tempfile.new("net_ssh_forward_test")
      path = file.path
      file.close!
      server = begin
        UNIXServer.new(path)
      rescue Errno::EPERM, Errno::EACCES => e
        skip "unix socket files are not permitted in this environment: #{e.message}"
      end
      begin
        yield server, path
      ensure
        server.close
        File.delete(path) if File.exist?(path)
      end
    end
  end
end
