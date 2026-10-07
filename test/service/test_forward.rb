require_relative '../common'
require 'socket'
require 'net/ssh/test'

class ServiceForwardTest < NetSSHTest
  include Net::SSH::Test

  REMOTE_SOCKET_PATH = '/tmp/net-ssh-remote.sock'
  CHANNEL_TYPE = 'forwarded-streamlocal@openssh.com'

  def test_remote_socket_is_registered_only_after_server_confirms_listening
    story do |script|
      script.sends(:global_request, 'streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
    end

    assert_scripted do
      result = connection.forward.remote_socket(REMOTE_SOCKET_PATH, '/tmp/local.sock')
      assert_equal REMOTE_SOCKET_PATH, result
      assert_empty connection.forward.active_remote_sockets

      process_until { connection.forward.active_remote_sockets.any? }
      assert_equal [REMOTE_SOCKET_PATH], connection.forward.active_remote_sockets
    end
  end

  def test_rejected_remote_socket_is_not_listed_as_active
    story do |script|
      script.sends(:global_request, 'streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_failure)
    end

    assert_scripted do
      connection.forward.remote_socket(REMOTE_SOCKET_PATH, '/tmp/local.sock')
      error = assert_raises(Net::SSH::Exception) do
        process_until { connection.pending_requests.empty? }
      end
      assert_equal 'remote socket forwarding request failed', error.message
      assert_empty connection.forward.active_remote_sockets
    end
  end

  def test_cancel_removes_mapping_but_keeps_accepted_channel_open
    local_socket, target = ::Socket.pair(:UNIX, :STREAM, 0)
    local_socket.extend(Net::SSH::BufferedIo)
    local_socket.extend(Net::SSH::ForwardedBufferedIo)
    UNIXSocket.stubs(:open).with('/tmp/local.sock').returns(local_socket)

    story do |script|
      script.sends(:global_request, 'streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
      script.gets(:channel_open, CHANNEL_TYPE, 777, 0x20000, 0x10000, REMOTE_SOCKET_PATH, nil, 0)
      script.sends(:channel_open_confirmation, 777, 0, 0x20000, 0x8000)
      script.gets(:channel_data, 0, 'ping')
      script.sends(:global_request, 'cancel-streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
    end

    assert_scripted do
      connection.stubs(:listen_to)
      connection.stubs(:stop_listening_to)
      connection.forward.remote_socket(REMOTE_SOCKET_PATH, '/tmp/local.sock')
      process_until { connection.forward.active_remote_sockets.any? }
      process_until { connection.channels.any? }
      process_once

      connection.forward.cancel_remote_socket(REMOTE_SOCKET_PATH)
      process_until { connection.forward.active_remote_sockets.empty? }
      assert_empty connection.forward.active_remote_sockets
      assert_equal [0], connection.channels.keys
      refute local_socket.closed?
      local_socket.send_pending
      assert_equal 'ping', target.recv_nonblock(4)
    end
  ensure
    local_socket.close unless local_socket.closed?
    target.close unless target.closed?
  end

  def test_new_channel_after_cancel_is_rejected
    story do |script|
      script.sends(:global_request, 'streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
      script.sends(:global_request, 'cancel-streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
      script.gets(:channel_open, CHANNEL_TYPE, 777, 0x20000, 0x10000, REMOTE_SOCKET_PATH, nil, 0)
      script.sends(:channel_open_failure, 777, 1, "unknown request from remote forwarded socket #{REMOTE_SOCKET_PATH}", '')
    end

    assert_scripted do
      connection.forward.remote_socket(REMOTE_SOCKET_PATH, '/tmp/not-used.sock')
      process_until { connection.forward.active_remote_sockets.any? }
      connection.forward.cancel_remote_socket(REMOTE_SOCKET_PATH)
      process_until { connection.forward.active_remote_sockets.empty? }
      process_until { socket.script.events.empty? }
      assert_empty connection.channels
    end
  end

  def test_eof_drains_buffered_data_before_half_closing_local_socket
    local_socket, target = ::Socket.pair(:UNIX, :STREAM, 0)
    local_socket.extend(Net::SSH::BufferedIo)
    local_socket.extend(Net::SSH::ForwardedBufferedIo)
    UNIXSocket.stubs(:open).with('/tmp/local.sock').returns(local_socket)

    story do |script|
      script.sends(:global_request, 'streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
      script.gets(:channel_open, CHANNEL_TYPE, 777, 0x20000, 0x10000, REMOTE_SOCKET_PATH, nil, 0)
      script.sends(:channel_open_confirmation, 777, 0, 0x20000, 0x8000)
      script.gets(:channel_data, 0, 'ping')
      script.gets(:channel_data, 0, 'pong')
      script.gets(:channel_eof, 0)
    end

    assert_scripted do
      connection.stubs(:listen_to)
      connection.stubs(:stop_listening_to)
      connection.forward.remote_socket(REMOTE_SOCKET_PATH, '/tmp/local.sock')
      process_until { connection.forward.active_remote_sockets.any? }
      process_until { connection.channels.any? }
      process_once
      process_once
      assert_equal 'pingpong', target.recv_nonblock(8)
      assert local_socket.write_shutdown?
      refute local_socket.closed?
    end
  ensure
    local_socket.close unless local_socket.closed?
    target.close unless target.closed?
  end

  def test_shutdown_clears_remote_forwarding_mappings
    story do |script|
      script.sends(:global_request, 'streamlocal-forward@openssh.com', true, nil, REMOTE_SOCKET_PATH)
      script.gets(:request_success)
    end

    assert_scripted do
      connection.forward.remote_socket(REMOTE_SOCKET_PATH, '/tmp/local.sock')
      process_until { connection.forward.active_remote_sockets.any? }
      connection.forward.shutdown!
      assert_empty connection.forward.active_remote_sockets
    end
  end

  private

  def process_once
    connection.process(0)
    connection.process(0)
  end

  def process_until
    100.times do
      connection.process(0)
      connection.process(0)
      return if yield
    end

    flunk 'condition was not reached while processing scripted connection'
  end

end
