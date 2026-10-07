require 'common'
require 'net/ssh/connection/session'

module Connection
  class TestExecCapture < NetSSHTest
    include Net::SSH::Connection::Constants

    def test_output_collector_collects_up_to_limit
      collector = Net::SSH::Connection::OutputCollector.new(10)
      collector << "hello"
      collector << " world"
      assert_equal "hello worl", collector.to_s
      assert_equal 10, collector.bytesize
      assert collector.truncated?
      assert_equal 1, collector.dropped_bytes
    end

    def test_output_collector_drops_everything_once_full
      collector = Net::SSH::Connection::OutputCollector.new(3)
      collector.append("abc")
      collector.append("def")
      assert_equal "abc", collector.to_s
      assert collector.truncated?
      assert_equal 3, collector.dropped_bytes
    end

    def test_output_collector_is_not_truncated_below_limit
      collector = Net::SSH::Connection::OutputCollector.new(5)
      collector.call("abc")
      assert_equal "abc", collector.to_s
      refute collector.truncated?
      assert_equal 0, collector.dropped_bytes
    end

    def test_output_collector_requires_non_negative_integer_limit
      assert_raises(ArgumentError) { Net::SSH::Connection::OutputCollector.new(-1) }
      assert_raises(ArgumentError) { Net::SSH::Connection::OutputCollector.new("10") }
    end

    def test_result_is_not_complete_until_close_even_after_eof_and_exit_status
      result = new_result
      refute result.complete?

      result.receive_exit_status(0)
      result.receive_eof
      assert result.eof?
      refute result.complete?, "EOF and exit-status must not complete the result"

      result.receive_close
      assert result.complete?
    end

    def test_result_exit_is_unknown_until_status_or_signal_arrives
      result = new_result
      refute result.exit_known?
      assert_nil result.exit_status
      assert_nil result.exit_signal
      refute result.success?

      result.receive_eof
      result.receive_close
      assert result.complete?
      refute result.exit_known?, "close without exit information must remain unknown"
      refute result.success?
    end

    def test_result_records_exit_events_in_any_order
      by_status = new_result
      by_status.receive_exit_status(3)
      by_status.receive_eof
      by_status.receive_close
      assert by_status.exit_known?
      assert_equal 3, by_status.exit_status
      refute by_status.success?

      by_signal = new_result
      by_signal.receive_eof
      by_signal.receive_exit_signal("KILL")
      by_signal.receive_close
      assert by_signal.exit_known?
      assert_equal "KILL", by_signal.exit_signal
      assert_nil by_signal.exit_status
      refute by_signal.success?
    end

    def test_result_success_requires_zero_status_without_signal
      result = new_result
      result.receive_exit_status(0)
      result.receive_close
      assert result.success?

      signaled = new_result
      signaled.receive_exit_status(0)
      signaled.receive_exit_signal("TERM")
      signaled.receive_close
      refute signaled.success?
    end

    def test_exec_capture_collects_stdout_and_stderr_separately
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "out-data")
        t.return(CHANNEL_EXTENDED_DATA, :long, rid, :long, 1, :string, "err-data")
        t.return(CHANNEL_REQUEST, :long, rid, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls")

      assert_equal "out-data", result.stdout
      assert_equal "err-data", result.stderr
      assert result.complete?
      assert result.exit_known?
      assert_equal 0, result.exit_status
      assert_nil result.exit_signal
      assert result.success?
      assert_no_open_channels
    end

    def test_exec_capture_keeps_collecting_after_eof_until_close
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "before-")
        t.return(CHANNEL_EOF, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "after")
        t.return(CHANNEL_REQUEST, :long, rid, :string, "exit-status", :bool, false, :long, 7)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls")

      assert_equal "before-after", result.stdout
      assert result.eof?
      assert result.complete?
      assert_equal 7, result.exit_status
      refute result.success?
      assert_no_open_channels
    end

    def test_exec_capture_records_exit_signal
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "partial")
        t.return(CHANNEL_REQUEST, :long, rid, :string, "exit-signal", :bool, false,
                 :string, "TERM", :bool, false, :string, "terminated", :string, "en")
        t.return(CHANNEL_EOF, :long, rid)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls")

      assert_equal "partial", result.stdout
      assert result.exit_known?
      assert_equal "TERM", result.exit_signal
      assert_nil result.exit_status
      refute result.success?
      assert_no_open_channels
    end

    def test_exec_capture_marks_exit_unknown_when_server_reports_nothing
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "some output")
        t.return(CHANNEL_EOF, :long, rid)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls")

      assert_equal "some output", result.stdout
      assert result.complete?
      refute result.exit_known?
      assert_nil result.exit_status
      assert_nil result.exit_signal
      refute result.success?
      assert_no_open_channels
    end

    def test_exec_capture_preserves_output_when_command_fails
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "partial stdout")
        t.return(CHANNEL_EXTENDED_DATA, :long, rid, :long, 1, :string, "boom")
        t.return(CHANNEL_REQUEST, :long, rid, :string, "exit-status", :bool, false, :long, 42)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls")

      refute result.success?
      assert_equal 42, result.exit_status
      assert_equal "partial stdout", result.stdout
      assert_equal "boom", result.stderr
      assert_no_open_channels
    end

    def test_exec_capture_closes_channel_when_exec_is_rejected
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_FAILURE, :long, rid)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls")

      assert result.exec_rejected?
      refute result.success?
      refute result.exit_known?
      assert_equal "", result.stdout
      assert_equal "", result.stderr
      assert_no_open_channels
    end

    def test_exec_capture_truncates_default_collection_at_limit
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "0123456789")
        t.return(CHANNEL_EXTENDED_DATA, :long, rid, :long, 1, :string, "stderr!")
        t.return(CHANNEL_REQUEST, :long, rid, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      result = session.exec_capture("ls", max_capture_size: 4)

      assert_equal "0123", result.stdout
      assert result.stdout_truncated?
      assert_equal "stde", result.stderr
      assert result.stderr_truncated?
      assert_no_open_channels
    end

    def test_exec_capture_streams_to_custom_sinks
      prep_exec_capture("ls") do |t, rid|
        t.return(CHANNEL_SUCCESS, :long, rid)
        t.return(CHANNEL_DATA, :long, rid, :string, "chunk1")
        t.return(CHANNEL_DATA, :long, rid, :string, "chunk2")
        t.return(CHANNEL_EXTENDED_DATA, :long, rid, :long, 1, :string, "oops")
        t.return(CHANNEL_REQUEST, :long, rid, :string, "exit-status", :bool, false, :long, 0)
        t.return(CHANNEL_CLOSE, :long, rid)
        expect_channel_close(t)
      end

      stdout_chunks = []
      stderr_buffer = String.new
      result = session.exec_capture("ls",
                                    stdout: ->(data) { stdout_chunks << data },
                                    stderr: stderr_buffer)

      assert_equal %w[chunk1 chunk2], stdout_chunks
      assert_equal "oops", stderr_buffer
      assert_nil result.stdout
      assert_nil result.stderr
      refute result.stdout_truncated?
      assert result.success?
      assert_no_open_channels
    end

    def test_exec_capture_rejects_invalid_sinks_before_sending_anything
      assert_raises(ArgumentError) { session.exec_capture("ls", stdout: Object.new) }
      assert_raises(ArgumentError) { session.exec_capture("ls", stderr: Object.new) }
      assert_no_open_channels
    end

    private

    def new_result(command = "ls")
      Net::SSH::Connection::ExecResult.new(command,
                                           Net::SSH::Connection::OutputCollector.new,
                                           Net::SSH::Connection::OutputCollector.new)
    end

    def assert_no_open_channels
      assert session.channels.empty?, "expected no channels to be left open"
    end

    def expect_channel_close(transport)
      transport.expect { |_t, packet| assert_equal CHANNEL_CLOSE, packet.type }
    end

    # Sets up the transport expectations for a single exec_capture call: the
    # channel open and the exec request are verified, and the given block
    # scripts the exact order of the protocol events the server sends next.
    def prep_exec_capture(command, &server_script)
      IO.expects(:select).with([socket], [], nil, 0).returns([[], [], []])
      transport.mock_enqueue = true
      transport.expect do |t, packet|
        assert_equal CHANNEL_OPEN, packet.type
        t.return(CHANNEL_OPEN_CONFIRMATION, :long, packet[:remote_id], :long, 0, :long, 0x20000, :long, 0x10000)
        t.expect do |t2, request|
          assert_equal CHANNEL_REQUEST, request.type
          assert_equal "exec", request[:request]
          assert_equal true, request[:want_reply]
          assert_equal command, request.read_string
          server_script.call(t2, packet[:remote_id])
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
