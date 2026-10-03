# frozen_string_literal: true

require_relative "../../lib/helper"

class IMAPIdleListenTest < Net::IMAP::TestCase
  include Net::IMAP::TestCase::SimpleTCPServerHelper

  def test_commands_wait_for_done_confirmation_before_sending
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    premature = false
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        # FETCH must not be sent before the IDLE tagged completion.
        premature = !IO.select([sock], nil, nil, 0.5).nil?
        sock.print("RUBY0001 OK IDLE terminated\r\n")
        requests.push(sock.gets) # RUBY0002 FETCH
        sock.print("* 1 FETCH (FLAGS (\\Seen))\r\n")
        sock.print("RUBY0002 OK FETCH completed\r\n")
        requests.push(sock.gets) # RUBY0003 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        sock.print("RUBY0003 OK IDLE terminated\r\n")
        requests.push(sock.gets) # RUBY0004 LOGOUT
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0004 OK LOGOUT completed\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      notifications = []
      imap.idle_listen {|resp| notifications.push(resp) }
      assert imap.idle_listening?
      fetched = imap.fetch(1, "FLAGS")
      assert_equal [:Seen], fetched.first.attr["FLAGS"]
      # wait until the listener has re-entered IDLE
      wait_until { requests.length >= 4 }
      imap.stop_idle_listen
      assert(!imap.idle_listening?)
      imap.logout
      assert_equal false, premature
      assert_equal "RUBY0001 IDLE\r\n",          requests[0]
      assert_equal "DONE\r\n",                   requests[1]
      assert_equal "RUBY0002 FETCH 1 FLAGS\r\n", requests[2]
      assert_equal "RUBY0003 IDLE\r\n",          requests[3]
      assert_equal "DONE\r\n",                   requests[4]
      assert_equal "RUBY0004 LOGOUT\r\n",        requests[5]
      assert notifications.any? {|resp|
        Net::IMAP::ContinuationRequest === resp
      }
    ensure
      imap.disconnect if imap
    end
  end

  def test_handler_may_send_commands_on_the_same_connection
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        sock.print("* 1 EXISTS\r\n")
        requests.push(sock.gets) # DONE
        sock.print("RUBY0001 OK IDLE terminated\r\n")
        requests.push(sock.gets) # RUBY0002 FETCH
        sock.print("* 1 FETCH (FLAGS (\\Seen))\r\n")
        sock.print("RUBY0002 OK FETCH completed\r\n")
        requests.push(sock.gets) # RUBY0003 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        sock.print("RUBY0003 OK IDLE terminated\r\n")
        requests.push(sock.gets) # RUBY0004 LOGOUT
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0004 OK LOGOUT completed\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      fetched = nil
      imap.idle_listen do |resp|
        if Net::IMAP::UntaggedResponse === resp && resp.name == "EXISTS"
          fetched = imap.fetch(1, "FLAGS")
        end
      end
      # wait until the listener has re-entered IDLE
      wait_until { requests.length >= 4 }
      imap.stop_idle_listen
      imap.logout
      assert_equal [:Seen], fetched.first.attr["FLAGS"]
      assert_equal "RUBY0001 IDLE\r\n",          requests[0]
      assert_equal "DONE\r\n",                   requests[1]
      assert_equal "RUBY0002 FETCH 1 FLAGS\r\n", requests[2]
      assert_equal "RUBY0003 IDLE\r\n",          requests[3]
      assert_equal "DONE\r\n",                   requests[4]
      assert_equal "RUBY0004 LOGOUT\r\n",        requests[5]
    ensure
      imap.disconnect if imap
    end
  end

  def test_stop_idle_listen_keeps_the_session_connected
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        sock.print("RUBY0001 OK IDLE terminated\r\n")
        requests.push(sock.gets) # RUBY0002 NOOP
        sock.print("RUBY0002 OK NOOP completed\r\n")
        requests.push(sock.gets) # RUBY0003 LOGOUT
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0003 OK LOGOUT completed\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      imap.idle_listen {|resp| }
      imap.stop_idle_listen
      assert(!imap.idle_listening?)
      assert(!imap.disconnected?)
      imap.noop
      imap.logout
      assert_equal "RUBY0001 IDLE\r\n",   requests[0]
      assert_equal "DONE\r\n",            requests[1]
      assert_equal "RUBY0002 NOOP\r\n",   requests[2]
      assert_equal "RUBY0003 LOGOUT\r\n", requests[3]
    ensure
      imap.disconnect if imap
    end
  end

  def test_bye_wakes_waiting_commands_and_stop
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        sock.print("* BYE server is done\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      imap.idle_listen {|resp| }
      assert_raise(Net::IMAP::ByeResponseError) do
        imap.fetch(1, "FLAGS")
      end
      assert_raise(Net::IMAP::ByeResponseError) do
        imap.stop_idle_listen
      end
      assert(!imap.idle_listening?)
      assert_equal "RUBY0001 IDLE\r\n", requests[0]
      assert_equal "DONE\r\n",          requests[1]
    ensure
      imap.disconnect if imap
    end
  end

  def test_unconfirmed_done_wakes_waiting_commands_and_stop
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        sock.gets # never confirm DONE; wait for the client to disconnect
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port, idle_response_timeout: 1)
      imap.idle_listen {|resp| }
      error = assert_raise(Net::IMAP::Error) { imap.fetch(1, "FLAGS") }
      assert_match(/did not confirm IDLE DONE/, error.message)
      error = assert_raise(Net::IMAP::Error) { imap.stop_idle_listen }
      assert_match(/did not confirm IDLE DONE/, error.message)
      assert(!imap.idle_listening?)
      assert_equal "RUBY0001 IDLE\r\n", requests[0]
      assert_equal "DONE\r\n",          requests[1]
    ensure
      imap.disconnect if imap
    end
  end

  def test_disconnect_wakes_waiting_commands_and_stop
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
      ensure
        sock.close # abrupt close: no tagged completion for DONE
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      imap.idle_listen {|resp| }
      assert_raise(EOFError) { imap.fetch(1, "FLAGS") }
      assert_raise(EOFError) { imap.stop_idle_listen }
      assert(!imap.idle_listening?)
      assert_equal "RUBY0001 IDLE\r\n", requests[0]
      assert_equal "DONE\r\n",          requests[1]
    ensure
      imap.disconnect if imap
    end
  end

  def test_idle_listen_guards
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets) # RUBY0001 IDLE
        sock.print("+ idling\r\n")
        requests.push(sock.gets) # DONE
        sock.print("RUBY0001 OK IDLE terminated\r\n")
        requests.push(sock.gets) # RUBY0002 LOGOUT
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0002 OK LOGOUT completed\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      assert_raise(LocalJumpError) { imap.idle_listen }
      imap.idle_listen {|resp| }
      assert_raise(Net::IMAP::Error) { imap.idle_listen {|resp| } }
      assert_raise(Net::IMAP::Error) { imap.idle {|resp| } }
      imap.stop_idle_listen
      assert_raise(Net::IMAP::Error) { imap.stop_idle_listen }
      assert_raise(Net::IMAP::Error) { imap.idle_done }
      imap.logout
      assert_equal "RUBY0001 IDLE\r\n",   requests[0]
      assert_equal "DONE\r\n",            requests[1]
      assert_equal "RUBY0002 LOGOUT\r\n", requests[2]
    ensure
      imap.disconnect if imap
    end
  end

  def test_idle_listen_timeout_cycles_for_keep_alive
    server = create_tcp_server
    port = server.addr[1]
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        tag = nil
        while (line = sock.gets)
          requests.push(line)
          case line
          when /\A(\S+) IDLE/   then tag = $1
            sock.print("+ idling\r\n")
          when "DONE\r\n"       then sock.print("#{tag} OK IDLE terminated\r\n")
          when /\A(\S+) LOGOUT/
            sock.print("* BYE terminating connection\r\n")
            sock.print("#{$1} OK LOGOUT completed\r\n")
            break
          end
        end
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, port: port)
      imap.idle_listen(0.1) {|resp| }
      wait_until { requests.count {|line| line.end_with?(" IDLE\r\n") } >= 2 }
      imap.stop_idle_listen
      imap.logout
      idle_count = requests.count {|line| line.end_with?(" IDLE\r\n") }
      done_count = requests.count {|line| line == "DONE\r\n" }
      assert_operator idle_count, :>=, 2
      assert_equal idle_count, done_count
      assert_equal "RUBY%04d LOGOUT\r\n" % (idle_count + 1), requests.last
    ensure
      imap.disconnect if imap
    end
  end

  private

  def wait_until(timeout: 5)
    deadline = Time.now + timeout
    until yield
      flunk "timed out waiting for condition" if Time.now > deadline
      sleep 0.005
    end
  end

end
