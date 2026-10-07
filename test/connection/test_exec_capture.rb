require_relative '../common'
require 'net/ssh/connection/session'

module Connection
  class TestExecCapture < NetSSHTest
    include Net::SSH::Connection::Constants

    def teardown
      assert session.channels.empty?, "expected all channels to be closed"
    end

    def test_successful_command_collects_stdout_stderr_and_exit_status_separately
      prep_exec_capture("ls") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "file1\nfile2\n")
        t.return(CHANNEL_EXTENDED_DATA, :long, id, :long, 1, :string, "warning: something\n")
        t.return(CHANNEL_REQUEST, :long, id, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_EOF, :long, id)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("ls")
      assert_equal "ls", result.command
      assert_equal "file1\nfile2\n", result.stdout
      assert_equal "warning: something\n", result.stderr
      assert_equal 0, result.exit_status
      assert_nil result.exit_signal
      assert result.exit_known?
      assert result.success?
      assert_equal :success, result.status
      assert !result.rejected?
      assert !result.signaled?
      assert !result.truncated?
    end

    def test_exit_status_arriving_after_eof_is_still_recorded
      prep_exec_capture("ls") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "done\n")
        t.return(CHANNEL_EOF, :long, id)
        t.return(CHANNEL_REQUEST, :long, id, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("ls")
      assert_equal 0, result.exit_status
      assert result.success?
      assert_equal "done\n", result.stdout
    end

    def test_nonzero_exit_status_is_reported_as_failed_with_output_intact
      prep_exec_capture("grep foo /etc/motd") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "partial match\n")
        t.return(CHANNEL_EXTENDED_DATA, :long, id, :long, 1, :string, "grep: warning\n")
        t.return(CHANNEL_REQUEST, :long, id, :string, "exit-status", :bool, false, :long, 3)
        t.return(CHANNEL_EOF, :long, id)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("grep foo /etc/motd")
      assert_equal 3, result.exit_status
      assert_equal :failed, result.status
      assert !result.success?
      assert result.exit_known?
      assert_equal "partial match\n", result.stdout
      assert_equal "grep: warning\n", result.stderr
    end

    def test_exit_signal_is_distinguished_from_exit_status
      prep_exec_capture("sleep 100") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "started\n")
        t.return(CHANNEL_REQUEST, :long, id, :string, "exit-signal", :bool, false,
                 :string, "KILL", :bool, false, :string, "", :string, "")
        t.return(CHANNEL_EOF, :long, id)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("sleep 100")
      assert_equal "KILL", result.exit_signal
      assert_nil result.exit_status
      assert result.signaled?
      assert result.exit_known?
      assert_equal :signaled, result.status
      assert !result.success?
      assert_equal "started\n", result.stdout
    end

    def test_close_without_any_exit_information_is_explicitly_unknown
      prep_exec_capture("ls") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "partial output")
        t.return(CHANNEL_EOF, :long, id)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("ls")
      assert_nil result.exit_status
      assert_nil result.exit_signal
      assert !result.exit_known?
      assert_equal :unknown, result.status
      assert !result.success?
      assert_equal "partial output", result.stdout
    end

    def test_rejected_exec_request_closes_channel_and_reports_rejection
      prep_exec_capture("ls") do |t, id|
        t.return(CHANNEL_FAILURE, :long, id)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("ls")
      assert result.rejected?
      assert_equal :rejected, result.status
      assert !result.success?
      assert !result.exit_known?
      assert_equal "", result.stdout
      assert_equal "", result.stderr
    end

    def test_output_can_be_redirected_to_caller_provided_sinks
      prep_exec_capture("ls") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "to stdout\n")
        t.return(CHANNEL_EXTENDED_DATA, :long, id, :long, 1, :string, "to stderr\n")
        t.return(CHANNEL_REQUEST, :long, id, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      out = String.new
      err_chunks = []
      result = session.exec_capture("ls", stdout: out, stderr: ->(data) { err_chunks << data })
      assert_equal "to stdout\n", out
      assert_equal ["to stderr\n"], err_chunks
      assert_equal "", result.stdout
      assert_equal "", result.stderr
      assert !result.truncated?
      assert result.success?
    end

    def test_default_collection_is_capped_at_the_given_limit
      prep_exec_capture("ls") do |t, id|
        t.return(CHANNEL_SUCCESS, :long, id)
        t.return(CHANNEL_DATA, :long, id, :string, "abcdefgh")
        t.return(CHANNEL_EXTENDED_DATA, :long, id, :long, 1, :string, "xy")
        t.return(CHANNEL_REQUEST, :long, id, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_CLOSE, :long, id)
      end

      result = session.exec_capture("ls", limit: 4)
      assert_equal "abcd", result.stdout
      assert_equal "xy", result.stderr
      assert result.truncated?
      assert result.success?
    end

    private

    # Scripts the channel open and exec request for +command+. The given
    # block receives the mock transport and the channel's local id, and
    # queues the server's protocol events (exec confirmation, data,
    # exit-status/exit-signal, eof, close) in the exact order they should
    # arrive. The client is always expected to finish by sending its own
    # CHANNEL_CLOSE.
    def prep_exec_capture(command, &script)
      IO.expects(:select).with([socket], [], nil, 0).returns([[], [], []])
      transport.mock_enqueue = true
      transport.expect do |t, p|
        assert_equal CHANNEL_OPEN, p.type
        t.return(CHANNEL_OPEN_CONFIRMATION, :long, p[:remote_id], :long, 0, :long, 0x20000, :long, 0x10000)
        t.expect do |t2, p2|
          assert_equal CHANNEL_REQUEST, p2.type
          assert_equal "exec", p2[:request]
          assert_equal true, p2[:want_reply]
          assert_equal command, p2.read_string
          script.call(t2, p[:remote_id])
          t2.expect { |_t3, p3| assert_equal CHANNEL_CLOSE, p3.type }
        end
      end
    end

    module MockSocket
      # so that we can easily test the contents that were enqueued, without
      # worrying about all the packet stream overhead
      def enqueue_packet(message)
        enqueue(message.to_s)
      end
    end

    def socket
      @socket ||= begin
        socket = Object.new
        socket.extend(Net::SSH::Transport::PacketStream)
        socket.extend(MockSocket)
        socket
      end
    end

    def transport(options = {})
      @transport ||= MockTransport.new(options.merge(socket: socket))
    end

    def session(options = {})
      @session ||= Net::SSH::Connection::Session.new(transport, options)
    end
  end
end
