# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "timeout"

class FXPTest < Test::Unit::TestCase
  # A scripted, command-driven fake FTP server good enough for FXP
  # testing: it speaks USER/PASS/TYPE/PASV/PORT/STOR/RETR/ABOR on one
  # control connection and moves a small payload over the negotiated
  # data connection.
  class FakeServer
    PAYLOAD = "fxp payload \x00\x01\x02\xff".b

    attr_reader :commands, :stored_data

    def initialize(stor_reply: "150 Opening data connection\r\n",
                   retr_final: "226 Transfer complete\r\n",
                   truncate_retr: false)
      @stor_reply = stor_reply
      @retr_final = retr_final
      @truncate_retr = truncate_retr
      @commands = []
      @stored_data = +"".b
      @server = TCPServer.new("127.0.0.1", 0)
      @thread = Thread.start { serve }
    end

    def port
      @server.local_address.ip_port
    end

    def close
      @server.close
      unless @thread.join(10)
        @thread.kill
        @thread.join
      end
    end

    private

    def serve
      sock = nil
      data_listener = nil
      port_addr = nil
      sock = @server.accept
      sock.print("220 fake server ready\r\n")
      while (line = sock.gets)
        @commands << line
        case line
        when /\AUSER /
          sock.print("331 Password required\r\n")
        when /\APASS /
          sock.print("230 Login successful\r\n")
        when /\ATYPE /
          sock.print("200 Type set\r\n")
        when /\APASV\r\n/
          data_listener = TCPServer.new("127.0.0.1", 0)
          sock.printf("227 Entering Passive Mode (127,0,0,1,%s)\r\n",
                      data_listener.local_address.ip_port.divmod(256).join(","))
        when /\APORT (.+)\r\n/
          octets = $1.split(",").map(&:to_i)
          port_addr = [octets[0, 4].join("."), octets[4] * 256 + octets[5]]
          sock.print("200 PORT command successful\r\n")
        when /\ASTOR /
          sock.print(@stor_reply)
          if @stor_reply.start_with?("1")
            conn = data_listener.accept
            begin
              while (chunk = conn.readpartial(4096))
                @stored_data << chunk
              end
            rescue EOFError, IOError, SystemCallError
            end
            conn.close
            sock.print("226 Transfer complete\r\n")
          end
        when /\ARETR /
          sock.print("150 Opening data connection\r\n")
          conn = TCPSocket.new(*port_addr)
          data = PAYLOAD
          data = data[0, data.size / 2] if @truncate_retr
          conn.write(data)
          conn.close
          sock.print(@retr_final)
        when /\AABOR\r\n/
          sock.print("226 Abort successful\r\n")
        else
          sock.print("502 Command not implemented\r\n")
        end
      end
    rescue IOError, SystemCallError
    ensure
      sock&.close
      data_listener&.close
    end
  end

  TRUST_LOCALHOST = ->(host, _port) { host == "127.0.0.1" }

  # Polls until the block returns true; used where the fake server
  # threads observe commands asynchronously from the client.
  def wait_for(message, timeout: 10)
    Timeout.timeout(timeout) do
      sleep 0.01 until yield
    end
  rescue Timeout::Error
    flunk("timed out waiting for: #{message}")
  end

  def with_fxp_pair(target_opts = {}, source_opts = {})
    target_server = FakeServer.new(**target_opts)
    source_server = FakeServer.new(**source_opts)
    target = Net::FTP.new
    source = Net::FTP.new
    target.connect("127.0.0.1", target_server.port)
    source.connect("127.0.0.1", source_server.port)
    target.login
    source.login
    yield source, target, source_server, target_server
  ensure
    source.close if source
    target.close if target
    source_server.close if source_server
    target_server.close if target_server
  end

  def test_fxp_success
    policy_calls = []
    policy = ->(host, port) { policy_calls << [host, port]; host == "127.0.0.1" }
    with_fxp_pair do |source, target, source_server, target_server|
      result = Net::FTP.fxp(source, target, "from.bin", "to.bin",
                            address_policy: policy)
      assert_kind_of(Net::FTP::FXPResult, result)
      assert_match(/\A150/, result.target_preliminary_response)
      assert_match(/\A226/, result.target_final_response)
      assert_match(/\A150/, result.source_preliminary_response)
      assert_match(/\A226/, result.source_final_response)
      assert_equal(FakeServer::PAYLOAD, target_server.stored_data)

      assert_equal("PASV\r\n", target_server.commands.find { |c| c.start_with?("PASV") })
      assert_include(target_server.commands, "STOR to.bin\r\n")
      assert_include(source_server.commands, "RETR from.bin\r\n")

      # Only the address actually negotiated via PASV is relayed, and the
      # policy saw exactly that address.
      port_cmd = source_server.commands.find { |c| c.start_with?("PORT ") }
      assert_match(/\APORT 127,0,0,1,\d+,\d+\r\n\z/, port_cmd)
      octets = port_cmd.scan(/\d+/).map(&:to_i)
      assert_equal([["127.0.0.1", octets[4] * 256 + octets[5]]], policy_calls)
    end
  end

  def test_fxp_default_target_file
    with_fxp_pair do |source, target, _source_server, target_server|
      Net::FTP.fxp(source, target, "dir/from.bin", address_policy: TRUST_LOCALHOST)
      assert_include(target_server.commands, "STOR from.bin\r\n")
    end
  end

  def test_fxp_requires_address_policy
    source = Net::FTP.new
    target = Net::FTP.new
    assert_raise(ArgumentError) do
      Net::FTP.fxp(source, target, "from.bin")
    end
    assert_raise(ArgumentError) do
      Net::FTP.fxp(source, target, "from.bin", address_policy: "10.0.0.0/8")
    end
  end

  def test_fxp_policy_rejects_address
    with_fxp_pair do |source, target, source_server, target_server|
      error = assert_raise(Net::FXPError) do
        Net::FTP.fxp(source, target, "from.bin",
                     address_policy: ->(_host, _port) { false })
      end
      assert_match(/rejected by the address policy/, error.message)
      assert_include(target_server.commands, "PASV\r\n")
      # The rejected address is never turned into a PORT command.
      assert_nil(source_server.commands.find { |c| c.start_with?("PORT ") })
      assert_nil(source_server.commands.find { |c| c.start_with?("RETR ") })
      assert_nil(target_server.commands.find { |c| c.start_with?("STOR ") })
    end
  end

  def test_fxp_target_refuses_stor
    with_fxp_pair({ stor_reply: "550 Permission denied\r\n" }) do |source, target, source_server, target_server|
      error = assert_raise(Net::FXPError) do
        Net::FTP.fxp(source, target, "from.bin", "to.bin",
                     address_policy: TRUST_LOCALHOST)
      end
      assert_match(/may be a partial file/, error.message)
      assert_kind_of(Net::FTPPermError, error.cause)
      # STOR is never retried, and the source is never started.
      assert_equal(1, target_server.commands.count { |c| c.start_with?("STOR ") })
      assert_nil(source_server.commands.find { |c| c.start_with?("RETR ") })
    end
  end

  def test_fxp_source_interrupted
    source_opts = { truncate_retr: true,
                    retr_final: "426 Connection closed; transfer aborted\r\n" }
    with_fxp_pair({}, source_opts) do |source, target, source_server, target_server|
      error = assert_raise(Net::FXPError) do
        Net::FTP.fxp(source, target, "from.bin", "to.bin",
                     address_policy: TRUST_LOCALHOST)
      end
      assert_match(/may be a partial file/, error.message)
      assert_kind_of(Net::FTPTempError, error.cause)
      # The target received only the truncated payload and was then
      # stopped with ABOR.
      wait_for("partial payload") {
        target_server.stored_data == FakeServer::PAYLOAD[0, FakeServer::PAYLOAD.size / 2]
      }
      wait_for("ABOR") { target_server.commands.include?("ABOR\r\n") }
    end
  end

  def test_fxp_concurrent_reverse_transfers
    with_fxp_pair do |source, target, source_server, target_server|
      results = {}
      threads = {
        forward: Thread.start {
          results[:forward] = Net::FTP.fxp(source, target, "a.bin",
                                           address_policy: TRUST_LOCALHOST)
        },
        reverse: Thread.start {
          results[:reverse] = Net::FTP.fxp(target, source, "b.bin",
                                           address_policy: TRUST_LOCALHOST)
        },
      }
      Timeout.timeout(30) { threads.each_value(&:join) }
      assert_kind_of(Net::FTP::FXPResult, results[:forward])
      assert_kind_of(Net::FTP::FXPResult, results[:reverse])
      assert_equal(FakeServer::PAYLOAD, target_server.stored_data)
      assert_equal(FakeServer::PAYLOAD, source_server.stored_data)
    end
  end
end
