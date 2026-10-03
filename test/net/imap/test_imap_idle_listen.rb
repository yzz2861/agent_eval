# frozen_string_literal: true

require_relative "../../lib/helper"

class IMAPIdleListenTest < Net::IMAP::TestCase
  include Net::IMAP::TestCase::SimpleTCPServerHelper

  # Runs a controllable server script in a thread.  The script block receives
  # the accepted socket and a Queue that records every line the client sends,
  # so tests can verify the exact order of commands on the wire.
  def start_scripted_server(&script)
    server = create_tcp_server
    port = server.addr[1]
    requests = Queue.new
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        script.call(sock, requests)
      ensure
        sock.close unless sock.closed?
        server.close
      end
    end
    [port, requests]
  end

  def pop_request(requests, timeout: 5)
    Timeout.timeout(timeout) { requests.pop }
  end

  def test_command_waits_for_idle_tagged_completion_and_resumes
    allow_done = Queue.new
    port, requests = start_scripted_server do |sock, recorded|
      idle_tag = nil
      loop do
        line = sock.gets or break
        recorded << line
        case line
        when /\A(RUBY\d+) IDLE\r\n\z/
          idle_tag = $1
          sock.print("+ idling\r\n")
        when "DONE\r\n"
          allow_done.pop
          sock.print("#{idle_tag} OK IDLE terminated\r\n")
        when /\A(RUBY\d+) FETCH/
          sock.print("#{$1} OK FETCH completed\r\n")
        end
      end
    end

    imap = Net::IMAP.new(server_addr, port: port)
    begin
      notifications = Queue.new
      listener = Thread.new do
        imap.idle_listen { |resp| notifications << resp }
      end
      @threads << listener
      assert_equal "RUBY0001 IDLE\r\n", pop_request(requests)
      assert_instance_of Net::IMAP::ContinuationRequest, notifications.pop

      fetch_result = nil
      fetcher = Thread.new { fetch_result = imap.fetch(1, "FLAGS") }
      @threads << fetcher

      assert_equal "DONE\r\n", pop_request(requests)
      sleep 0.2
      assert requests.empty?,
             "FETCH must not be sent before the IDLE tagged completion"

      allow_done << true
      assert_equal "RUBY0002 FETCH 1 FLAGS\r\n", pop_request(requests)
      assert fetcher.join(5), "FETCH should complete"
      assert_equal [], fetch_result
      assert_equal "RUBY0003 IDLE\r\n", pop_request(requests),
                   "listening should resume after the command completes"

      allow_done << true
      assert imap.stop_idle_listen
      assert listener.join(5), "listener should stop"
      assert_equal "DONE\r\n", pop_request(requests)
    ensure
      imap.disconnect if imap
    end
  end

  def test_done_handshake_failure_wakes_waiting_commands
    port, requests = start_scripted_server do |sock, recorded|
      loop do
        line = sock.gets or break
        recorded << line
        case line
        when /\A(RUBY\d+) IDLE\r\n\z/
          sock.print("+ idling\r\n")
        when "DONE\r\n"
          # Never confirm DONE: the handshake fails.
        when /\A(RUBY\d+) FETCH/
          sock.print("#{$1} OK FETCH completed\r\n")
        when /\A(RUBY\d+) NOOP\r\n\z/
          sock.print("#{$1} OK NOOP completed\r\n")
        end
      end
    end

    imap = Net::IMAP.new(server_addr, port: port, idle_response_timeout: 1)
    begin
      listener_error = nil
      listener = Thread.new do
        begin
          imap.idle_listen { |resp| }
        rescue => error
          listener_error = error
        end
      end
      @threads << listener
      assert_equal "RUBY0001 IDLE\r\n", pop_request(requests)

      fetch_result = nil
      fetcher = Thread.new { fetch_result = imap.fetch(1, "FLAGS") }
      @threads << fetcher

      assert_equal "DONE\r\n", pop_request(requests)
      # The server never confirms DONE.  After idle_response_timeout the
      # handshake fails: the listener stops and the waiting FETCH is woken.
      assert_equal "RUBY0002 FETCH 1 FLAGS\r\n", pop_request(requests)
      assert fetcher.join(5), "FETCH should be woken by the handshake failure"
      assert_equal [], fetch_result
      assert listener.join(5), "listener should stop after handshake failure"
      assert_instance_of Net::IMAP::Error, listener_error

      # The connection itself is still usable.
      assert_equal "OK", imap.noop.name
    ensure
      imap.disconnect if imap
    end
  end

  def test_bye_wakes_listener_and_waiting_commands
    port, requests = start_scripted_server do |sock, recorded|
      loop do
        line = sock.gets or break
        recorded << line
        case line
        when /\A(RUBY\d+) IDLE\r\n\z/
          sock.print("+ idling\r\n")
        when "DONE\r\n"
          sock.print("* BYE server is going away\r\n")
          break
        end
      end
    end

    imap = Net::IMAP.new(server_addr, port: port)
    begin
      listener_error = nil
      listener = Thread.new do
        begin
          imap.idle_listen { |resp| }
        rescue => error
          listener_error = error
        end
      end
      @threads << listener
      assert_equal "RUBY0001 IDLE\r\n", pop_request(requests)

      fetch_error = nil
      fetcher = Thread.new do
        begin
          imap.fetch(1, "FLAGS")
        rescue => error
          fetch_error = error
        end
      end
      @threads << fetcher

      assert_equal "DONE\r\n", pop_request(requests)
      assert listener.join(5), "BYE should wake the listener"
      assert fetcher.join(5), "BYE should wake the waiting FETCH"
      assert_instance_of Net::IMAP::ByeResponseError, listener_error
      assert_instance_of Net::IMAP::ByeResponseError, fetch_error
    ensure
      imap.disconnect if imap
    end
  end

  def test_stop_idle_listen_keeps_connection_usable
    port, requests = start_scripted_server do |sock, recorded|
      idle_tag = nil
      loop do
        line = sock.gets or break
        recorded << line
        case line
        when /\A(RUBY\d+) IDLE\r\n\z/
          idle_tag = $1
          sock.print("+ idling\r\n")
        when "DONE\r\n"
          sock.print("#{idle_tag} OK IDLE terminated\r\n")
        when /\A(RUBY\d+) NOOP\r\n\z/
          sock.print("#{$1} OK NOOP completed\r\n")
        end
      end
    end

    imap = Net::IMAP.new(server_addr, port: port)
    begin
      listener = Thread.new { imap.idle_listen { |resp| } }
      @threads << listener
      assert_equal "RUBY0001 IDLE\r\n", pop_request(requests)

      assert imap.stop_idle_listen
      assert listener.join(5), "listener should stop"
      assert_equal "DONE\r\n", pop_request(requests)

      refute imap.disconnected?
      assert_equal "OK", imap.noop.name
      assert_equal false, imap.stop_idle_listen
    ensure
      imap.disconnect if imap
    end
  end

  def test_response_handler_cannot_send_commands
    port, requests = start_scripted_server do |sock, recorded|
      idle_tag = nil
      first_idle = true
      loop do
        line = sock.gets or break
        recorded << line
        case line
        when /\A(RUBY\d+) IDLE\r\n\z/
          idle_tag = $1
          sock.print("+ idling\r\n")
          if first_idle
            first_idle = false
            sock.print("* 1 EXISTS\r\n")
          end
        when "DONE\r\n"
          sock.print("#{idle_tag} OK IDLE terminated\r\n")
        end
      end
    end

    imap = Net::IMAP.new(server_addr, port: port)
    begin
      handler_error = nil
      notified = Queue.new
      listener = Thread.new do
        imap.idle_listen do |resp|
          if resp.name == "EXISTS"
            begin
              imap.fetch(1, "FLAGS")
            rescue => error
              handler_error = error
            end
            notified << true
          end
        end
      end
      @threads << listener
      assert_equal "RUBY0001 IDLE\r\n", pop_request(requests)
      Timeout.timeout(5) { notified.pop }
      sleep 0.2
      assert_instance_of Net::IMAP::Error, handler_error
      assert requests.empty?,
             "no command may be sent from the response handler"

      assert imap.stop_idle_listen
      assert listener.join(5), "listener should still stop cleanly"
    ensure
      imap.disconnect if imap
    end
  end

  def test_idle_listen_requires_a_block
    port, _requests = start_scripted_server do |sock, _recorded|
      sock.gets
    end

    imap = Net::IMAP.new(server_addr, port: port)
    begin
      assert_raise(LocalJumpError) { imap.idle_listen }
      assert_equal false, imap.stop_idle_listen
    ensure
      imap.disconnect if imap
    end
  end

  def test_idle_listen_allows_only_one_listener
    port, requests = start_scripted_server do |sock, recorded|
      idle_tag = nil
      loop do
        line = sock.gets or break
        recorded << line
        case line
        when /\A(RUBY\d+) IDLE\r\n\z/
          idle_tag = $1
          sock.print("+ idling\r\n")
        when "DONE\r\n"
          sock.print("#{idle_tag} OK IDLE terminated\r\n")
        end
      end
    end

    imap = Net::IMAP.new(server_addr, port: port)
    begin
      listener = Thread.new { imap.idle_listen { |resp| } }
      @threads << listener
      assert_equal "RUBY0001 IDLE\r\n", pop_request(requests)

      assert_raise(Net::IMAP::Error) { imap.idle_listen { |resp| } }

      assert imap.stop_idle_listen
      assert listener.join(5), "listener should stop"
    ensure
      imap.disconnect if imap
    end
  end

end
