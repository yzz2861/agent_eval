# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPAppendTest < Net::IMAP::TestCase
  TEST_FIXTURE_PATH = File.join(__dir__, "fixtures/response_parser")

  # TODO: convert all tests to use Net::IMAP::FakeServer::TestHelper
  include Net::IMAP::TestCase::SimpleTCPServerHelper
  include Net::IMAP::FakeServer::TestHelper

  test "#append" do
    server = create_tcp_server
    port = server.addr[1]
    mail = <<~EOF.gsub(/\n/, "\r\n")
      From: shugo@example.com
      To: matz@example.com
      Subject: hello

      hello world
    EOF
    requests = []
    received_mail = nil
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        line = sock.gets
        requests.push(line)
        size = line.slice(/{(\d+)}\r\n/, 1).to_i
        sock.print("+ Ready for literal data\r\n")
        received_mail = sock.read(size)
        sock.gets
        sock.print("RUBY0001 OK APPEND completed\r\n")
        requests.push(sock.gets)
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0002 OK LOGOUT completed\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, :port => port)
      imap.append("INBOX", mail)
      assert_equal(1, requests.length)
      assert_equal("RUBY0001 APPEND INBOX {#{mail.size}}\r\n", requests[0])
      assert_equal(mail, received_mail)
      imap.logout
      assert_equal(2, requests.length)
      assert_equal("RUBY0002 LOGOUT\r\n", requests[1])
    ensure
      imap.disconnect if imap
    end
  end

  test "#append failed with 'NO'" do
    server = create_tcp_server
    port = server.addr[1]
    mail = <<~EOF.gsub(/\n/, "\r\n")
      From: shugo@example.com
      To: matz@example.com
      Subject: hello

      hello world
    EOF
    requests = []
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        requests.push(sock.gets)
        sock.print("RUBY0001 NO Mailbox doesn't exist\r\n")
        requests.push(sock.gets)
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0002 OK LOGOUT completed\r\n")
      ensure
        sock.close
        server.close
      end
    end

    begin
      imap = Net::IMAP.new(server_addr, :port => port)
      assert_raise(Net::IMAP::NoResponseError) do
        imap.append("INBOX", mail)
      end
      assert_equal(1, requests.length)
      assert_equal("RUBY0001 APPEND INBOX {#{mail.size}}\r\n", requests[0])
      imap.logout
      assert_equal(2, requests.length)
      assert_equal("RUBY0002 LOGOUT\r\n", requests[1])
    ensure
      imap.disconnect if imap
    end
  end

  test "#append with binary data" do
    png = File.binread(File.join(TEST_FIXTURE_PATH, "ruby.png"))
    mail = <<~EOF.b.gsub(/\n/, "\r\n")
      From: nick@example.com
      To: shugo@example.com
      Subject: Binary append support
      MIME-Version: 1.0
      Content-Transfer-Encoding: binary
      Content-Type: image/png

    EOF
    mail << png
    mail.freeze
    with_fake_server do |server, imap|
      server.on "APPEND", &:done_ok

      time = Time.new(2026, 2, 20, 10, 00, in: "-0500")
      imap.append "Drafts", mail, %i[Draft Seen], time
      assert_equal 'Drafts (\\Draft \\Seen) "20-Feb-2026 10:00:00 -0500" ' \
                   "~{#{mail.bytesize}}\r\n#{mail}",
                   server.commands.pop.args
    end
  end

  test "#append_multi sends one APPEND command with all messages" do
    with_fake_server(with_extensions: %i[MULTIAPPEND UIDPLUS]) do |server, imap|
      server.on("APPEND") do |resp|
        resp.done_ok code: "APPENDUID 38505 3955:3956,3960"
      end

      time = Time.new(2026, 2, 20, 10, 00, in: "-0500")
      uids = imap.append_multi("INBOX", [
        {message: "msg1", flags: %i[Seen], date_time: time},
        {message: "msg2", flags: %i[Draft]},
        "msg3",
      ])

      assert_equal [3955, 3956, 3960], uids
      command = server.commands.pop
      assert_equal "APPEND", command.name
      assert_equal %(INBOX (\\Seen) "20-Feb-2026 10:00:00 -0500" {4}\r\nmsg1 ) +
                   %((\\Draft) {4}\r\nmsg2 {4}\r\nmsg3),
                   command.args
      assert server.commands.empty?
    end
  end

  test "#append_multi returns nil without an APPENDUID response code" do
    with_fake_server(with_extensions: %i[MULTIAPPEND]) do |server, imap|
      server.on("APPEND", &:done_ok)
      assert_nil imap.append_multi("INBOX", ["msg1", "msg2"])
    end
  end

  test "#append_multi raises when MULTIAPPEND is unsupported, sending nothing" do
    with_fake_server do |server, imap|
      error = assert_raise(Net::IMAP::Error) do
        imap.append_multi("INBOX", ["msg1", "msg2"])
      end
      assert_match(/MULTIAPPEND/, error.message)
      imap.noop
      assert_equal "NOOP", server.commands.pop.name
      assert server.commands.empty?
    end
  end

  test "#append_multi raises when APPENDUID assigns the wrong number of UIDs" do
    with_fake_server(with_extensions: %i[MULTIAPPEND UIDPLUS]) do |server, imap|
      server.on("APPEND") { _1.done_ok code: "APPENDUID 38505 3955:3956" }
      error = assert_raise(Net::IMAP::Error) do
        imap.append_multi("INBOX", ["msg1", "msg2", "msg3"])
      end
      assert_match(/2 UIDs for 3 appended messages/, error.message)
    end
  end

  test "#append_multi stops sending when a literal continuation is rejected" do
    with_fake_server(with_extensions: %i[MULTIAPPEND]) do |server, imap|
      server.literal_acceptor = ->(_buf, size) { size <= 4 }
      assert_raise(Net::IMAP::NoResponseError) do
        imap.append_multi("INBOX", ["a much larger message", "msg2"])
      end
      # the remaining messages were not sent, and the connection still works
      imap.noop
      assert_equal "NOOP", server.commands.pop.name
      assert server.commands.empty?
    end
  end

  test "#append_multi uses non-synchronizing literals only when permitted" do
    with_fake_server(with_extensions: %i[MULTIAPPEND LITERAL+]) do |server, imap|
      server.on("APPEND", &:done_ok)
      imap.append_multi("INBOX", ["msg1", "msg2"])
      assert_equal "INBOX {4+}\r\nmsg1 {4+}\r\nmsg2",
                   server.commands.pop.args
    end
  end

  test "#append_multi validates input before sending anything" do
    with_fake_server(with_extensions: %i[MULTIAPPEND]) do |server, imap|
      assert_raise(ArgumentError) { imap.append_multi("INBOX", []) }
      assert_raise(TypeError) do
        imap.append_multi("INBOX", [{message: 42}])
      end
      assert_raise(ArgumentError) do
        imap.append_multi("INBOX", [{flags: %i[Seen]}])
      end
      assert_raise(ArgumentError) do
        imap.append_multi("INBOX", [{message: "msg1", flag: %i[Seen]}])
      end
      assert_raise(Net::IMAP::DataFormatError) do
        imap.append_multi("INBOX", [{message: "msg1", flags: [:"bad flag"]}])
      end
      imap.noop
      assert_equal "NOOP", server.commands.pop.name
      assert server.commands.empty?
    end
  end

end
