# frozen_string_literal: true

require "net/imap"
require "socket"
require "test/unit"

class IMAPMultiAppendTest < Net::IMAP::TestCase
  MESSAGE1 = "Subject: first\r\n\r\nfirst body\r\n".b
  MESSAGE2 = "Subject: second\r\n\r\nsecond body\r\n".b
  MESSAGE3 = "Subject: third\r\n\r\nthird body\r\n".b
  MESSAGE4 = "Subject: fourth\r\n\r\nfourth body\r\n".b
  DATE_TIME = Time.new(2026, 2, 20, 10, 0, in: "-0500")
  DATE_TIME_DATA = '"20-Feb-2026 10:00:00 -0500"'

  def with_multiappend_server(capabilities: %w[MULTIAPPEND UIDPLUS],
                              non_synchronizing_literal: false,
                              reject_continuation: nil,
                              append_uid: "10:13")
    client_io, server_io = Socket.pair(:UNIX, :STREAM)
    requests = []
    continuation_count = 0
    rejected = false
    server_thread = Thread.new do
      server_io.print("* OK [CAPABILITY IMAP4rev1 #{capabilities.join(" ")}] ready\r\n")
      loop do
        request = +"".b
        line = server_io.gets("\r\n") or break
        request << line
        while line =~ /~?\{(\d+)(\+)?\}\r\n\z/n
          bytes = Integer($1)
          if $2
            request << server_io.read(bytes)
            line = server_io.gets("\r\n") or break
            request << line
          else
            continuation_count += 1
            if reject_continuation&.call(continuation_count, request, bytes)
              tag = request[/\A(\S+)/, 1]
              server_io.print("#{tag} NO literal rejected\r\n")
              rejected = true
              break
            end
            server_io.print("+ continue\r\n")
            request << server_io.read(bytes)
            line = server_io.gets("\r\n") or break
            request << line
          end
        end
        tag = request[/\A(\S+)/, 1]
        requests << request
        case request
        when /\ARUBY\d+ MULTIAPPEND/
          unless rejected
            code = " [APPENDUID 38505 #{append_uid}]" if append_uid
            server_io.print("#{tag} OK#{code} done\r\n")
          end
        when /\ARUBY\d+ NOOP/
          server_io.print("#{tag} OK done\r\n")
        end
        rejected = false
      end
    ensure
      server_io.close
    end

    client_class = Class.new(Net::IMAP) do
      define_method(:tcp_socket) {|*| client_io }
    end
    config = {max_non_synchronizing_literal: non_synchronizing_literal ? 4096 : -1}
    IO.select([client_io], nil, nil, 1)
    imap = client_class.new("localhost", ssl: false,
                            config: Net::IMAP::Config.new(**config))
    yield imap, -> { requests.last.to_s }, -> { continuation_count }
  ensure
    client_io&.close
    server_thread&.join(1)
    server_io&.close
    server_thread&.join(1)
  end

  test "sends all messages in one MULTIAPPEND command and maps APPENDUIDs" do
    with_multiappend_server do |imap, request, _|
      uids = imap.multiappend(
        "Drafts",
        [
          MESSAGE1,
          [[:Seen], MESSAGE2],
          [[:Draft, :Seen], DATE_TIME, MESSAGE3],
          [DATE_TIME, MESSAGE4]
        ]
      )

      assert_equal [10, 11, 12, 13], uids
      assert_equal(
        "Drafts " \
        "{#{MESSAGE1.bytesize}}\r\n#{MESSAGE1}" \
        " (\\Seen) {#{MESSAGE2.bytesize}}\r\n#{MESSAGE2}" \
        " (\\Draft \\Seen) #{DATE_TIME_DATA} {#{MESSAGE3.bytesize}}\r\n#{MESSAGE3}" \
        " #{DATE_TIME_DATA} {#{MESSAGE4.bytesize}}\r\n#{MESSAGE4}",
        request.call.sub(/\A\S+ MULTIAPPEND /, "")
          .sub(/\r\n\z/, "").force_encoding("UTF-8")
      )
    end
  end

  test "returns nil when APPENDUID is absent" do
    with_multiappend_server(capabilities: %w[MULTIAPPEND], append_uid: nil) do |imap, request, _|
      assert_nil imap.multiappend("Drafts", [MESSAGE1, MESSAGE2])
      assert_match(/\A\S+ MULTIAPPEND/, request.call)
    end
  end

  test "sends binary messages with BINARY" do
    binary_message = "Subject: binary\r\n\r\nhello\0world\r\n".b
    with_multiappend_server(capabilities: %w[MULTIAPPEND UIDPLUS BINARY],
                            append_uid: "40") do |imap, request, _|
      assert_equal [40], imap.multiappend("Drafts", [binary_message])
      assert_equal(
        "Drafts ~{#{binary_message.bytesize}}\r\n#{binary_message}",
        request.call.sub(/\A\S+ MULTIAPPEND /, "").sub(/\r\n\z/, "")
      )
    end
  end

  test "uses non-synchronizing literals only with server permission" do
    with_multiappend_server(capabilities: %w[MULTIAPPEND UIDPLUS LITERAL+],
                            non_synchronizing_literal: true,
                            append_uid: "10:11") do |imap, request, continuations|
      uids = imap.multiappend("Drafts", [MESSAGE1, [[:Seen], MESSAGE2]])

      assert_equal [10, 11], uids
      assert_match(/\A\S+ MULTIAPPEND Drafts \{#{MESSAGE1.bytesize}\+\}\r\n/m,
                   request.call)
      assert_match(/ \(\\Seen\) \{#{MESSAGE2.bytesize}\+\}\r\n#{Regexp.escape(MESSAGE2)}\r\n\z/m,
                   request.call)
      assert_equal 0, continuations.call
    end
  end

  test "uses synchronizing literals without non-synchronizing literal capability" do
    with_multiappend_server(append_uid: "10:11") do |imap, request, continuations|
      assert_equal [10, 11], imap.multiappend("Drafts", [MESSAGE1, [[:Seen], MESSAGE2]])
      assert_match(/\A\S+ MULTIAPPEND Drafts \{#{MESSAGE1.bytesize}\}\r\n/m,
                   request.call)
      assert_equal 2, continuations.call
    end
  end

  test "stops after rejection before the next continuation" do
    rejected = false
    with_multiappend_server(
      reject_continuation: ->(count, _request, _bytes) { count == 2 }
    ) do |imap, request, _|
      assert_raise(Net::IMAP::NoResponseError) do
        imap.multiappend("Drafts", [MESSAGE1, [[:Seen], MESSAGE2]])
      end

      rejected = true
      sent = request.call
      assert_match(/Subject: first.*\(\\Seen\) \{#{MESSAGE2.bytesize}\}\r\n\z/m, sent)
      assert_not_match(/Subject: second/, sent)
      imap.noop
      assert_match(/\A\S+ NOOP/, request.call)
    end
    assert rejected
  end

  test "does not fall back to APPEND without MULTIAPPEND capability" do
    with_multiappend_server(capabilities: %w[IMAP4rev1]) do |imap, _request, _|
      error = assert_raise(ArgumentError) do
        imap.multiappend("Drafts", [MESSAGE1, MESSAGE2])
      end
      assert_match(/MULTIAPPEND capability/, error.message)
    end
  end

  test "does not query capabilities when they are not already cached" do
    imap = Net::IMAP.allocate
    def imap.capabilities_cached? = false
    def imap.capability(*)
      raise "capability command must not be sent"
    end

    assert_raise(ArgumentError) do
      imap.multiappend("Drafts", [MESSAGE1])
    end
  end

  test "validates arguments before sending the command" do
    imap = Net::IMAP.allocate
    assert_raise(ArgumentError) do
      imap.multiappend(:Drafts, [MESSAGE1])
    end
    assert_raise(ArgumentError) do
      imap.multiappend(nil, [MESSAGE1])
    end
    assert_raise(ArgumentError) do
      imap.multiappend("Drafts", MESSAGE1)
    end
    [
      [],
      [[:Seen, :Draft, MESSAGE1]],
      [Object.new],
      [nil],
      [[:Seen, Date.today, MESSAGE1]],
      [[:Seen, 1], MESSAGE1],
    ].each do |messages|
      assert_raise(ArgumentError) do
        imap.multiappend("Drafts", messages)
      end
    end
  end

  test "raises when APPENDUID count does not match message count" do
    with_multiappend_server(append_uid: "30") do |imap, request, _|
      error = assert_raise(Net::IMAP::InvalidResponseError) do
        imap.multiappend("Drafts", [MESSAGE1, MESSAGE2])
      end
      assert_match(/1 UIDs for 2 appended messages/, error.message)
      assert_match(/\A\S+ MULTIAPPEND/, request.call)
      imap.noop
      assert_match(/\A\S+ NOOP/, request.call)
    end
  end

end
