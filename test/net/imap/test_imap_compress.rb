# frozen_string_literal: true

require "zlib"
require_relative "../../lib/helper"

class IMAPCompressTest < Net::IMAP::TestCase
  def test_compress_deflate_with_preread_chunked_responses_literal_and_idle
    requests = Queue.new
    client, server = imap_pair do |sock|
      sock.print("* OK [CAPABILITY IMAP4rev1 COMPRESS=DEFLATE] ready\r\n")
      requests << read_line(sock)

      deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      preloaded = [
        "* 1 EXISTS\r\n",
        "* 2 RECENT\r\n",
      ].join
      sock.write(
        "RUBY0001 OK COMPRESS done\r\n" +
          deflater.deflate(preloaded, Zlib::SYNC_FLUSH)
      )
      assert_equal "RUBY0002 NOOP\r\n", read_compressed_line(sock)
      write_chunks(
        sock,
        deflater.deflate("RUBY0002 OK NOOP done\r\n", Zlib::SYNC_FLUSH),
        8
      )

      literal = "compressed literal\r\nsecond line"
      assert_equal "RUBY0003 NOOP\r\n", read_compressed_line(sock)
      write_chunks(
        sock,
        deflater.deflate(
          [
            "* 1 FETCH (BODY[] {#{literal.bytesize}}\r\n#{literal})\r\n",
            "RUBY0003 OK NOOP done\r\n",
          ].join,
          Zlib::SYNC_FLUSH
        ),
        8
      )

      assert_equal "RUBY0004 IDLE\r\n", read_compressed_line(sock)
      write_chunks(
        sock,
        deflater.deflate("+ idling\r\n* 3 EXISTS\r\n", Zlib::SYNC_FLUSH),
        8
      )
      assert_equal "DONE\r\n", read_compressed_line(sock)
      write_chunks(
        sock,
        deflater.deflate("RUBY0004 OK IDLE terminated\r\n", Zlib::SYNC_FLUSH),
        8
      )
    end

    begin
      assert client.compress
      assert client.compressed?
      assert_equal "RUBY0001 COMPRESS DEFLATE\r\n", requests.pop
      wait_for_response_count(client, type: "RECENT", count: 1)
      assert_equal 1, client.responses("EXISTS").last
      assert_equal 2, client.responses("RECENT").last

      client.noop

      client.noop
      fetched = client.responses("FETCH").last
      assert_equal "compressed literal\r\nsecond line", fetched.attr["BODY[]"]

      idle_responses = []
      client.idle do |response|
        idle_responses << response
        client.idle_done if response.name == "EXISTS"
      end
      assert_equal 2, idle_responses.length
      assert_instance_of Net::IMAP::ContinuationRequest, idle_responses[0]
      assert_equal "EXISTS", idle_responses[1].name
      assert_equal 3, idle_responses[1].data
    ensure
      client.disconnect
      server.join
    end
  end

  test "does not switch streams after tagged failure" do
    client, server = imap_pair do |sock|
      sock.print("* OK [CAPABILITY IMAP4rev1 COMPRESS=DEFLATE] ready\r\n")
      assert_equal "RUBY0001 COMPRESS DEFLATE\r\n", read_line(sock)
      sock.print("RUBY0001 NO compression unavailable\r\n")
      assert_equal "RUBY0002 NOOP\r\n", read_line(sock)
      sock.print("* 1 EXISTS\r\nRUBY0002 OK NOOP done\r\n")
    end

    begin
      assert_raise(Net::IMAP::NoResponseError) { client.compress }
      refute client.compressed?
      client.noop
      assert_equal 1, client.responses("EXISTS").last
    ensure
      client.disconnect
      server.join
    end
  end

  test "rejects enabling compression twice" do
    requests = Queue.new
    client, server = imap_pair do |sock|
      sock.print("* OK [CAPABILITY IMAP4rev1 COMPRESS=DEFLATE] ready\r\n")
      requests << read_line(sock)
      sock.print("RUBY0001 OK COMPRESS done\r\n")
    end

    begin
      assert client.compress
      error = assert_raise(Net::IMAP::Error) { client.compress }
      assert_match(/already been enabled/, error.message)
      assert_equal "RUBY0001 COMPRESS DEFLATE\r\n", requests.pop
    ensure
      client.disconnect
      server.join
    end
  end

  private

  def imap_pair
    client_io, server_io = Socket.pair(:UNIX, :STREAM)
    server = Thread.start do
      Thread.current.report_on_exception = false
      begin
        yield server_io
      ensure
        server_io.close
      end
    end
    imap = Net::IMAP.allocate
    def imap.tcp_socket(*) = @socket
    imap.instance_variable_set(:@socket, client_io)
    imap.send(:initialize, "localhost")
    [imap, server]
  end

  def read_line(socket)
    line = String.new.b
    line << socket.readpartial(1) until line.end_with?("\r\n")
    line
  end

  def read_compressed_line(socket, inflater = (@inflater ||= Zlib::Inflate.new(-Zlib::MAX_WBITS)))
    line = String.new.b
    until line.end_with?("\r\n")
      chunk = socket.readpartial(1)
      begin
        line << inflater.inflate(chunk)
      rescue Zlib::BufError
      end
    end
    line
  end

  def write_chunks(socket, data, size = 8)
    data.bytes.each_slice(size) do |bytes|
      socket.write(bytes.pack("C*"))
    end
  end
end
