# frozen_string_literal: true

require_relative "../../lib/helper"
require "timeout"
require "zlib"

# Tests for the COMPRESS=DEFLATE extension (RFC 4978).
#
# The tests use a Socket.pair rather than a TCP server, so the server side can
# carefully control chunk boundaries and pipeline bytes at the exact
# compression switch point.
class IMAPCompressTest < Net::IMAP::TestCase

  RAW_WBITS = -Zlib::MAX_WBITS
  CRLF = "\r\n"

  # Net::IMAP client whose transport is one end of a socket pair.
  class PairIMAP < Net::IMAP
    def initialize(socket, **opts)
      @pair_socket = socket
      super("localhost", port: 0, ssl: false, **opts)
    end

    private def tcp_socket(_host, _port) = @pair_socket
  end

  # A minimal compressed-IMAP server end of a socket pair.
  class DeflateServer
    attr_reader :commands

    def initialize(socket)
      @sock       = socket
      @deflater   = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, RAW_WBITS)
      @inflater   = Zlib::Inflate.new(RAW_WBITS)
      @inbuf      = String.new(encoding: Encoding::ASCII_8BIT)
      @compressed = false
      @commands   = []
    end

    def greet = @sock.write("* OK ready\r\n")
    def compressed? = @compressed
    def last_tag
      @commands.last && @commands.last[/\A\S+/]
    end

    def plain(data)
      raise "already compressed" if @compressed
      @sock.write(data)
    end

    # Write a deflated response using +chunks+ transport writes.
    def send_deflated(data, chunks: 1)
      payload = @deflater.deflate(data, Zlib::SYNC_FLUSH)
      write_chunked(payload, chunks)
    end

    # Send the COMPRESS OK; optionally pipeline already-compressed bytes in
    # the same transport message (the pre-read-at-switch-point case).
    def accept_compress(tag, pipeline_after: nil, chunks: 1)
      prelude = +"#{tag} OK COMPRESS completed\r\n"
      if pipeline_after
        prelude << @deflater.deflate(pipeline_after, Zlib::SYNC_FLUSH)
      end
      write_chunked(prelude, chunks)
      @compressed = true
    end

    def reject_compress(tag, status = "NO")
      @sock.write("#{tag} #{status} COMPRESS not available\r\n")
    end

    def respond_ok(tag, text = "done")
      response = "#{tag} OK #{text}\r\n"
      @compressed ? send_deflated(response) : plain(response)
    end

    # Read one complete command, honoring literal continuations.
    def read_command
      line, = read_command_with_literal
      line
    end

    # Like #read_command, but returns [command_line, literal_size] where
    # literal_size is non-nil for a synchronizing literal awaiting a
    # continuation response.
    def read_command_with_literal
      line = read_line
      if (m = line.match(/\{(\d+)\+?\}\r\n\z/))
        size = m[1].to_i
        if line.include?("{#{size}+}\r\n")
          line << read_n(size)
          @commands << line
          [line, nil]
        else
          [line, size]
        end
      else
        @commands << line
        [line, nil]
      end
    end

    # Read the literal body the client sends after a continuation request.
    def read_literal_tail(n)
      body = read_n(n)
      trailing = read_line
      @commands << body + trailing
      [body, trailing]
    end

    def close
      @sock.close unless @sock.closed?
    end

    private

    def write_chunked(payload, chunks)
      size = (payload.bytesize.to_f / chunks).ceil
      offset = 0
      while offset < payload.bytesize
        @sock.write(payload.byteslice(offset, size))
        offset += size
      end
    end

    def read_more
      chunk = @sock.readpartial(1 << 16)
      @inbuf << (@compressed ? @inflater.inflate(chunk) : chunk)
    end

    def read_line
      read_more until @inbuf.include?(CRLF)
      take(@inbuf.index(CRLF) + 2)
    end

    def read_n(n)
      read_more until @inbuf.bytesize >= n
      take(n)
    end

    def take(n)
      result = @inbuf.byteslice(0, n)
      @inbuf = @inbuf.byteslice(n..) || String.new(encoding: Encoding::ASCII_8BIT)
      result
    end
  end

  # Drives the client in one block and the server in another, using a socket
  # pair; waits for both and surfaces failures from either side.
  def run_pair(timeout: 5)
    client_io, server_io = Socket.pair(:UNIX, :STREAM)
    server = DeflateServer.new(server_io)
    server.greet
    client = PairIMAP.new(client_io)
    errors = []
    server_thread = Thread.start do
      begin
        Timeout.timeout(timeout) { yield :server, server }
      rescue Exception => e
        errors << [:server, e]
      end
    end
    begin
      Timeout.timeout(timeout) { yield :client, client }
    rescue Exception => e
      errors << [:client, e]
    ensure
      server_thread.join(timeout)
      client.disconnect rescue nil
      server.close rescue nil
      client_io.close rescue nil
      server_io.close rescue nil
    end
    failure = errors.first
    raise failure.last if failure
  end

  # Wait for the receiver thread to record +expected+ as the latest +type+
  # response (responses pipelined before a command returns may be processed a
  # moment later).
  def wait_for(client, type, expected, timeout: 2)
    deadline = Time.now + timeout
    loop do
      actual = client.responses(type) { _1.last }
      return actual if actual == expected
      raise "timed out waiting for #{type}=#{expected}" if Time.now > deadline
      sleep 0.005
    end
  end

  def test_compress_switches_after_ok
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
      when :client
        assert_equal "OK", peer.compress.name
        assert peer.compressed?
      end
    end
  end

  def test_rejects_unknown_algorithm
    run_pair do |side, peer|
      case side
      when :server
        # no command is expected
        sleep 0.05
      when :client
        assert_raise ArgumentError do
          peer.compress("LZS")
        end
        refute peer.compressed?
      end
    end
  end

  def test_compress_failure_keeps_plain_session
    run_pair do |side, peer|
      case side
      when :server
        peer.reject_compress(peer.read_command[/\A\S+/], "NO")
        cmd = peer.read_command
        peer.respond_ok(cmd[/\A\S+/], "NOOP done")
      when :client
        assert_raise Net::IMAP::NoResponseError do
          peer.compress
        end
        refute peer.compressed?
        peer.noop
      end
    end
  end

  def test_compress_twice_is_rejected
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
      when :client
        peer.compress
        assert_raise Net::IMAP::Error do
          peer.compress
        end
      end
    end
  end

  def test_pipelined_compressed_bytes_after_ok_are_not_lost
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(
          peer.read_command[/\A\S+/],
          pipeline_after: "* 23 EXISTS\r\n"
        )
      when :client
        peer.compress
        wait_for(peer, "EXISTS", 23)
      end
    end
  end

  def test_switch_point_pipelined_with_chunked_transfer
    [1, 2, 3, 5, 8].each do |chunks|
      run_pair do |side, peer|
        case side
        when :server
          peer.accept_compress(
            peer.read_command[/\A\S+/],
            pipeline_after: "* 1 EXISTS\r\n* 2 EXISTS\r\n",
            chunks: chunks
          )
        when :client
          peer.compress
          wait_for(peer, "EXISTS", 2)
          assert_equal [1, 2], peer.responses("EXISTS") { _1.last(2) }
        end
      end
    end
  end

  def test_capability_roundtrip_after_compression
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
        cmd = peer.read_command
        peer.send_deflated("* CAPABILITY IMAP4REV1 COMPRESS=DEFLATE\r\n")
        peer.respond_ok(cmd[/\A\S+/], "CAPABILITY done")
      when :client
        peer.compress
        assert_include peer.capability, "COMPRESS=DEFLATE"
      end
    end
  end

  def test_literal_response_works_after_compression
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
        peer.read_command
        body = "line one\r\nline two"
        peer.send_deflated(
          "* 1 FETCH (BODY[TEXT] {#{body.bytesize}}\r\n#{body})\r\n"
        )
        peer.respond_ok(peer.last_tag, "FETCH done")
      when :client
        peer.compress
        fetched = peer.fetch(1, "BODY[TEXT]")
        assert_equal "line one\r\nline two", fetched.first.attr["BODY[TEXT]"]
      end
    end
  end

  def test_literal_request_works_after_compression
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
        first, literal_size = peer.read_command_with_literal
        assert_equal 5, literal_size
        peer.send_deflated("+ Ready for literal data\r\n")
        body, trailing = peer.read_literal_tail(literal_size)
        assert_equal "hello", body
        assert_equal CRLF, trailing
        peer.respond_ok(first[/\A\S+/], "APPEND done")
      when :client
        peer.compress
        peer.append("INBOX", "hello")
      end
    end
  end

  def test_idle_works_after_compression
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
        idle = peer.read_command
        peer.send_deflated("* 5 EXISTS\r\n")
        assert_equal "DONE\r\n", peer.read_command
        peer.respond_ok(idle[/\A\S+/], "IDLE terminated")
      when :client
        peer.compress
        peer.idle(2) do |resp|
          peer.idle_done if resp.respond_to?(:name) && resp.name == "EXISTS"
        end
        assert_equal 5, peer.responses("EXISTS") { _1.last }
      end
    end
  end

  def test_multiple_responses_in_single_deflate_block
    run_pair do |side, peer|
      case side
      when :server
        peer.accept_compress(peer.read_command[/\A\S+/])
        peer.read_command
        peer.send_deflated(
          "* 1 EXISTS\r\n* 2 RECENT\r\n* 3 UNSEEN\r\n" \
          "#{peer.last_tag} OK done\r\n"
        )
      when :client
        peer.compress
        peer.noop
        assert_equal 1, peer.responses("EXISTS") { _1.last }
        assert_equal 2, peer.responses("RECENT") { _1.last }
        assert_equal 3, peer.responses("UNSEEN") { _1.last }
      end
    end
  end

  def test_chunked_deflate_responses
    [1, 2, 4, 7, 32].each do |chunks|
      run_pair do |side, peer|
        case side
        when :server
          peer.accept_compress(peer.read_command[/\A\S+/])
          peer.read_command
          peer.send_deflated(
            "* 9 EXISTS\r\n#{peer.last_tag} OK done\r\n", chunks: chunks
          )
        when :client
          peer.compress
          peer.noop
          assert_equal 9, peer.responses("EXISTS") { _1.last }
        end
      end
    end
  end

end
