# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "socket"

class FXPTest < Test::Unit::TestCase
  SERVER_ADDR = "127.0.0.1"

  def setup
    @threads = []
    @servers = []
  end

  def teardown
    @threads.each { |thread| thread.join(10) }
    @servers.each { |server| server.close unless server.closed? }
  end

  def start_server(&script)
    server = TCPServer.new(SERVER_ADDR, 0)
    @servers << server
    def server.port
      addr[1]
    end
    @threads << Thread.start do
      sock = server.accept
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_OOBINLINE, 1)
      begin
        script.call(sock)
      ensure
        sock.close rescue nil
      end
    end
    server
  end

  def login_sequence(sock, commands)
    sock.print("220 (fake fxp server)\r\n")
    commands << sock.gets
    sock.print("331 Please specify the password.\r\n")
    commands << sock.gets
    sock.print("230 Login successful.\r\n")
    commands << sock.gets
    sock.print("200 Switching to Binary mode.\r\n")
  end

  def pasv_reply(port)
    quads = SERVER_ADDR.tr(".", ",")
    "227 Entering Passive Mode (#{quads},#{port / 256},#{port % 256}).\r\n"
  end

  def parse_port_command(line)
    m = /\APORT (\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\r\n\z/.match(line)
    return nil unless m
    [[m[1], m[2], m[3], m[4]].join("."), m[5].to_i * 256 + m[6].to_i]
  end

  def open_logged_in_ftp(port)
    ftp = Net::FTP.new
    ftp.connect(SERVER_ADDR, port)
    ftp.login("user", "pass")
    ftp
  end

  def test_fxp_success
    target_commands = []
    target_data = nil
    target = start_server { |sock|
      login_sequence(sock, target_commands)
      target_commands << sock.gets # PASV
      listener = TCPServer.new(SERVER_ADDR, 0)
      begin
        sock.print(pasv_reply(listener.addr[1]))
        target_commands << sock.gets # STOR
        sock.print("150 Opening data connection.\r\n")
        data_sock = listener.accept
        target_data = data_sock.read
        data_sock.close
        sock.print("226 Transfer complete.\r\n")
      ensure
        listener.close
      end
    }
    source_commands = []
    source = start_server { |sock|
      login_sequence(sock, source_commands)
      port_line = sock.gets # PORT
      source_commands << port_line
      host, port = parse_port_command(port_line)
      sock.print("200 PORT command successful.\r\n")
      source_commands << sock.gets # RETR
      sock.print("150 Opening data connection.\r\n")
      data_sock = TCPSocket.new(host, port)
      data_sock.write("fxp-payload")
      data_sock.close
      sock.print("226 Transfer complete.\r\n")
    }
    ftp_target = open_logged_in_ftp(target.port)
    ftp_source = open_logged_in_ftp(source.port)
    begin
      negotiated_port = nil
      policy = ->(host, port) {
        negotiated_port = port
        host == SERVER_ADDR
      }
      result = Net::FTP.fxp(ftp_source, ftp_target, "src.bin", "dst.bin",
                            address_policy: policy)
      assert_match(/\A150 /, result.target_preliminary_response)
      assert_match(/\A226 /, result.target_final_response)
      assert_match(/\A150 /, result.source_preliminary_response)
      assert_match(/\A226 /, result.source_final_response)
      assert_equal("fxp-payload", target_data)
      # The source received exactly the address the target negotiated.
      port_line = source_commands.find { |cmd| cmd&.start_with?("PORT ") }
      assert_equal([SERVER_ADDR, negotiated_port],
                   parse_port_command(port_line))
      assert_equal("PASV\r\n", target_commands[3])
      assert_equal("STOR dst.bin\r\n", target_commands[4])
      assert_equal("RETR src.bin\r\n", source_commands[4])
    ensure
      ftp_target.close
      ftp_source.close
    end
  end

  def test_fxp_target_refuses_stor
    target = start_server { |sock|
      commands = []
      login_sequence(sock, commands)
      sock.gets # PASV
      listener = TCPServer.new(SERVER_ADDR, 0)
      sock.print(pasv_reply(listener.addr[1]))
      sock.gets # STOR
      sock.print("550 Permission denied.\r\n")
      listener.close
    }
    source_commands = []
    source = start_server { |sock|
      login_sequence(sock, source_commands)
      source_commands << sock.gets # PORT
      sock.print("200 PORT command successful.\r\n")
      # RETR must never arrive; the client stops after STOR is refused.
      source_commands << sock.gets
    }
    ftp_target = open_logged_in_ftp(target.port)
    ftp_source = open_logged_in_ftp(source.port)
    begin
      error = assert_raise(Net::FTP::FXPError) do
        Net::FTP.fxp(ftp_source, ftp_target, "src.bin", "dst.bin",
                     address_policy: ->(host, port) { host == SERVER_ADDR })
      end
      assert_include(error.message, "target refused STOR")
      assert_include(error.message, "partial file")
      assert_match(/\A550 /, error.result.target_preliminary_response)
      assert_nil(error.result.source_preliminary_response)
      ftp_target.close
      ftp_source.close
      @threads.each { |thread| thread.join(10) }
      assert_nil(source_commands.find { |cmd| cmd&.start_with?("RETR") })
    ensure
      ftp_target.close unless ftp_target.closed?
      ftp_source.close unless ftp_source.closed?
    end
  end

  def test_fxp_source_aborts_mid_transfer
    target_data = nil
    target = start_server { |sock|
      commands = []
      login_sequence(sock, commands)
      sock.gets # PASV
      listener = TCPServer.new(SERVER_ADDR, 0)
      begin
        sock.print(pasv_reply(listener.addr[1]))
        sock.gets # STOR
        sock.print("150 Opening data connection.\r\n")
        data_sock = listener.accept
        target_data = data_sock.read
        data_sock.close
        sock.print("226 Transfer complete.\r\n")
      ensure
        listener.close
      end
    }
    source = start_server { |sock|
      commands = []
      login_sequence(sock, commands)
      host, port = parse_port_command(sock.gets) # PORT
      sock.print("200 PORT command successful.\r\n")
      sock.gets # RETR
      sock.print("150 Opening data connection.\r\n")
      data_sock = TCPSocket.new(host, port)
      data_sock.write("partial-")
      data_sock.close
      sock.print("426 Connection closed; transfer aborted.\r\n")
    }
    ftp_target = open_logged_in_ftp(target.port)
    ftp_source = open_logged_in_ftp(source.port)
    begin
      error = assert_raise(Net::FTP::FXPError) do
        Net::FTP.fxp(ftp_source, ftp_target, "src.bin", "dst.bin",
                     address_policy: ->(host, port) { host == SERVER_ADDR })
      end
      assert_include(error.message, "source reported failure")
      assert_include(error.message, "partial file")
      assert_match(/\A226 /, error.result.target_final_response)
      assert_match(/\A426 /, error.result.source_final_response)
      assert_equal("partial-", target_data)
    ensure
      ftp_target.close
      ftp_source.close
    end
  end

  def test_fxp_address_policy_rejects
    target = start_server { |sock|
      commands = []
      login_sequence(sock, commands)
      sock.gets # PASV
      listener = TCPServer.new(SERVER_ADDR, 0)
      sock.print(pasv_reply(listener.addr[1]))
      sock.gets # nothing more should arrive
      listener.close
    }
    source_commands = []
    source = start_server { |sock|
      login_sequence(sock, source_commands)
      source_commands << sock.gets # PORT must never arrive
    }
    ftp_target = open_logged_in_ftp(target.port)
    ftp_source = open_logged_in_ftp(source.port)
    begin
      error = assert_raise(Net::FTPError) do
        Net::FTP.fxp(ftp_source, ftp_target, "src.bin", "dst.bin",
                     address_policy: ->(host, port) { false })
      end
      assert_not_kind_of(Net::FTP::FXPError, error)
      assert_include(error.message, "address policy")
      ftp_target.close
      ftp_source.close
      @threads.each { |thread| thread.join(10) }
      assert_nil(source_commands.find { |cmd| cmd&.start_with?("PORT") })
    ensure
      ftp_target.close unless ftp_target.closed?
      ftp_source.close unless ftp_source.closed?
    end
  end

  def test_fxp_source_refuses_retr_stops_target
    target_commands = []
    target = start_server { |sock|
      login_sequence(sock, target_commands)
      target_commands << sock.gets # PASV
      listener = TCPServer.new(SERVER_ADDR, 0)
      begin
        sock.print(pasv_reply(listener.addr[1]))
        target_commands << sock.gets # STOR
        sock.print("150 Opening data connection.\r\n")
        target_commands << sock.gets # ABOR
        sock.print("226 Abort successful.\r\n")
      ensure
        listener.close
      end
    }
    source = start_server { |sock|
      commands = []
      login_sequence(sock, commands)
      sock.gets # PORT
      sock.print("200 PORT command successful.\r\n")
      sock.gets # RETR
      sock.print("550 No such file or directory.\r\n")
    }
    ftp_target = open_logged_in_ftp(target.port)
    ftp_source = open_logged_in_ftp(source.port)
    begin
      error = assert_raise(Net::FTP::FXPError) do
        Net::FTP.fxp(ftp_source, ftp_target, "src.bin", "dst.bin",
                     address_policy: ->(host, port) { host == SERVER_ADDR })
      end
      assert_include(error.message, "source refused RETR")
      assert_include(error.message, "partial file")
      assert_match(/\A550 /, error.result.source_preliminary_response)
      assert_match(/\A226 /, error.result.target_final_response)
      @threads.each { |thread| thread.join(10) }
      assert_equal("ABOR\r\n", target_commands[5])
    ensure
      ftp_target.close
      ftp_source.close
    end
  end

  def test_fxp_requires_address_policy
    assert_raise(ArgumentError) do
      Net::FTP.fxp(Net::FTP.new, Net::FTP.new, "a", "b",
                   address_policy: "10.0.0.1")
    end
  end

  def test_fxp_reverse_transfers_do_not_deadlock
    # Each server acts as both source and target; the two transfers run in
    # opposite directions concurrently and must serialize on the stable
    # control-connection lock order instead of deadlocking.
    payload_a_to_b = "from-a"
    payload_b_to_a = "from-b"
    server_a = start_fxp_server(payload_a_to_b)
    server_b = start_fxp_server(payload_b_to_a)
    ftp_a = open_logged_in_ftp(server_a[:tcp].port)
    ftp_b = open_logged_in_ftp(server_b[:tcp].port)
    policy = ->(host, port) { host == SERVER_ADDR }
    begin
      results = {}
      workers = []
      workers << Thread.start do
        results[:a_to_b] = Net::FTP.fxp(ftp_a, ftp_b, "a.bin", "b.bin",
                                        address_policy: policy)
      end
      workers << Thread.start do
        results[:b_to_a] = Net::FTP.fxp(ftp_b, ftp_a, "b.bin", "a.bin",
                                        address_policy: policy)
      end
      workers.each { |thread| assert(thread.join(30), "fxp deadlocked") }
      assert_match(/\A226 /, results[:a_to_b].target_final_response)
      assert_match(/\A226 /, results[:b_to_a].target_final_response)
      @threads.each { |thread| thread.join(10) }
      assert_equal(payload_a_to_b, server_b[:stored])
      assert_equal(payload_b_to_a, server_a[:stored])
    ensure
      ftp_a.close
      ftp_b.close
    end
  end

  def start_fxp_server(payload)
    state = { stored: nil }
    tcp = start_server { |sock|
      commands = []
      login_sequence(sock, commands)
      port_addr = nil
      listener = nil
      4.times do
        cmd = sock.gets
        case cmd
        when nil
          break
        when /\APORT /
          port_addr = parse_port_command(cmd)
          sock.print("200 PORT command successful.\r\n")
        when /\APASV\r\n\z/
          listener = TCPServer.new(SERVER_ADDR, 0)
          sock.print(pasv_reply(listener.addr[1]))
        when /\ARETR /
          sock.print("150 Opening data connection.\r\n")
          data_sock = TCPSocket.new(*port_addr)
          data_sock.write(payload)
          data_sock.close
          sock.print("226 Transfer complete.\r\n")
        when /\ASTOR /
          sock.print("150 Opening data connection.\r\n")
          data_sock = listener.accept
          state[:stored] = data_sock.read
          data_sock.close
          sock.print("226 Transfer complete.\r\n")
        end
      end
      listener&.close
    }
    state[:tcp] = tcp
    state
  end
  private :start_fxp_server
end
