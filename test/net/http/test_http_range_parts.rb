# coding: US-ASCII
# frozen_string_literal: false
require 'net/http'
require 'test/unit'
require 'stringio'
require_relative 'utils'

class HTTPRangePartsTest < Test::Unit::TestCase
  BOUNDARY = 'range-boundary-XYZ'

  # An IO that serves its data in small pieces, simulating network
  # chunks that may split MIME boundaries at arbitrary positions.
  class DripIO
    def initialize(str, piece)
      @str = str
      @pos = 0
      @piece = piece
    end

    def read_nonblock(maxlen, buf = nil, exception: false)
      return nil if @pos >= @str.bytesize
      n = [maxlen, @piece, @str.bytesize - @pos].min
      data = @str.byteslice(@pos, n)
      @pos += n
      buf ? buf.replace(data) : data
    end

    def closed?
      false
    end
  end

  def response_io(str, piece: nil)
    io = piece ? DripIO.new(str.b, piece) : StringIO.new(str.b)
    Net::BufferedIO.new(io)
  end

  def read_response(str, piece: nil)
    io = response_io(str, piece: piece)
    res = Net::HTTPResponse.read_new(io)
    res.reading_body(io, true) do
      yield res
    end
  end

  def collect_parts(str, piece: nil)
    parts = []
    read_response(str, piece: piece) do |res|
      res.each_range_part do |part|
        parts << [part.first, part.last, part.total, part.body]
      end
    end
    parts
  end

  def multipart_response(object, ranges, boundary: BOUNDARY, status: '206 Partial Content', chunked: false)
    body = +''.b
    ranges.each do |first, last|
      body << "--#{boundary}\r\n"
      body << "Content-Type: application/octet-stream\r\n"
      body << "Content-Range: bytes #{first}-#{last}/#{object.bytesize}\r\n"
      body << "\r\n"
      body << object.byteslice(first..last)
      body << "\r\n"
    end
    body << "--#{boundary}--\r\n"
    str = +"HTTP/1.1 #{status}\r\n"
    str << "Content-Type: multipart/byteranges; boundary=#{boundary}\r\n"
    if chunked
      str << "Transfer-Encoding: chunked\r\n"
      str << "\r\n"
      until body.empty?
        chunk = body.slice!(0, 7)
        str << chunk.bytesize.to_s(16) << "\r\n" << chunk << "\r\n"
      end
      str << "0\r\n\r\n"
    else
      str << "Content-Length: #{body.bytesize}\r\n"
      str << "\r\n"
      str << body
    end
    str
  end

  def test_each_range_part_multipart
    object = (0...1000).map {|i| (i * 31 % 251).chr }.join.b
    ranges = [[0, 99], [200, 299], [500, 999]]
    parts = collect_parts(multipart_response(object, ranges))
    assert_equal 3, parts.size
    ranges.each_with_index do |(first, last), i|
      assert_equal first, parts[i][0]
      assert_equal last, parts[i][1]
      assert_equal 1000, parts[i][2]
      assert_equal object.byteslice(first..last), parts[i][3]
    end
  end

  def test_each_range_part_multipart_boundary_like_content
    # The object contains byte sequences that look exactly like the
    # boundary delimiter; they must be treated as content, because part
    # bodies are read by the length Content-Range declares.
    object = +"prefix\r\n--#{BOUNDARY}\r\nmiddle\r\n--#{BOUNDARY}--\r\nsuffix"
    object << "--#{BOUNDARY}\r\n"
    ranges = [[0, 40], [41, object.bytesize - 1]]
    parts = collect_parts(multipart_response(object, ranges))
    assert_equal 2, parts.size
    assert_equal object.byteslice(0..40), parts[0][3]
    assert_equal object.byteslice(41..-1), parts[1][3]
    assert_equal [0, 41], [parts[0][0], parts[1][0]]
    assert_equal object.bytesize, parts[0][2]
  end

  def test_each_range_part_multipart_split_across_chunks
    # Serve the response a few bytes at a time so that boundaries and
    # part headers are split across network chunks.
    object = (0...500).map {|i| (i * 17 % 253).chr }.join.b
    ranges = [[0, 199], [250, 499]]
    str = multipart_response(object, ranges)
    [1, 3, 13].each do |piece|
      parts = collect_parts(str, piece: piece)
      assert_equal ranges.map {|first, last| [first, last, 500, object.byteslice(first..last)] },
                   parts,
                   "failed with #{piece}-byte chunks"
    end
  end

  def test_each_range_part_multipart_chunked
    object = (0...300).map {|i| (i * 13 % 241).chr }.join.b
    ranges = [[0, 149], [150, 299]]
    parts = collect_parts(multipart_response(object, ranges, chunked: true))
    assert_equal ranges.map {|first, last| [first, last, 300, object.byteslice(first..last)] },
                 parts
  end

  def test_each_range_part_multipart_without_content_length
    object = 'hello world, hello range'.b
    ranges = [[0, 4], [6, 10]]
    str = multipart_response(object, ranges)
    str = str.sub(/Content-Length: \d+\r\n/, '')
    str = str.sub("HTTP/1.1 206 Partial Content\r\n",
                  "HTTP/1.1 206 Partial Content\r\nConnection: close\r\n")
    parts = collect_parts(str)
    assert_equal [[0, 4, 24, 'hello'], [6, 10, 24, 'world']], parts
  end

  def test_each_range_part_single_range_206
    object = (0...100).map {|i| (i * 7 % 251).chr }.join.b
    str = +"HTTP/1.1 206 Partial Content\r\n"
    str << "Content-Type: application/octet-stream\r\n"
    str << "Content-Range: bytes 10-29/100\r\n"
    str << "Content-Length: 20\r\n"
    str << "\r\n"
    str << object.byteslice(10..29)
    parts = collect_parts(str)
    assert_equal [[10, 29, 100, object.byteslice(10..29)]], parts
  end

  def test_each_range_part_single_range_206_length_mismatch
    str = +"HTTP/1.1 206 Partial Content\r\n"
    str << "Content-Range: bytes 10-29/100\r\n"
    str << "Content-Length: 5\r\n"
    str << "\r\n"
    str << '12345'
    assert_raise(Net::HTTPBadResponse) { collect_parts(str) }
  end

  def test_each_range_part_full_object_200
    object = 'the server ignored the Range request'.b
    str = +"HTTP/1.1 200 OK\r\n"
    str << "Content-Type: application/octet-stream\r\n"
    str << "Content-Length: #{object.bytesize}\r\n"
    str << "\r\n"
    str << object
    parts = collect_parts(str)
    assert_equal [[0, object.bytesize - 1, object.bytesize, object]], parts
  end

  def test_each_range_part_unexpected_status
    str = +"HTTP/1.1 404 Not Found\r\n"
    str << "Content-Length: 9\r\n"
    str << "\r\n"
    str << 'not found'
    assert_raise(Net::HTTPBadResponse) { collect_parts(str) }
  end

  def test_each_range_part_overlap
    object = ('a'..'z').to_a.join.b * 10
    assert_raise(Net::HTTPBadResponse) do
      collect_parts(multipart_response(object, [[0, 99], [50, 149]]))
    end
  end

  def test_each_range_part_duplicate
    object = ('a'..'z').to_a.join.b * 10
    assert_raise(Net::HTTPBadResponse) do
      collect_parts(multipart_response(object, [[0, 99], [200, 299], [0, 99]]))
    end
  end

  def test_each_range_part_content_range_larger_than_body
    # The declared range is longer than the actual part content.
    object = ('a'..'z').to_a.join.b
    str = multipart_response(object, [[0, 9]])
    str = str.sub('Content-Range: bytes 0-9/', 'Content-Range: bytes 0-19/')
    assert_raise(Net::HTTPBadResponse) { collect_parts(str) }
  end

  def test_each_range_part_content_range_smaller_than_body
    # The declared range is shorter than the actual part content.
    object = ('a'..'z').to_a.join.b
    str = multipart_response(object, [[0, 9]])
    str = str.sub('Content-Range: bytes 0-9/', 'Content-Range: bytes 0-4/')
    assert_raise(Net::HTTPBadResponse) { collect_parts(str) }
  end

  def test_each_range_part_missing_content_range
    str = +"HTTP/1.1 206 Partial Content\r\n"
    str << "Content-Type: multipart/byteranges; boundary=#{BOUNDARY}\r\n"
    str << "Content-Length: 40\r\n"
    str << "\r\n"
    str << "--#{BOUNDARY}\r\n\r\nhello\r\n--#{BOUNDARY}--\r\n"
    assert_raise(Net::HTTPBadResponse) { collect_parts(str) }
  end

  def test_each_range_part_lazy_skip
    # A part that is never read is discarded when iteration advances.
    object = (0...300).map {|i| (i * 11 % 247).chr }.join.b
    ranges = [[0, 99], [100, 199], [200, 299]]
    seen = []
    read_response(multipart_response(object, ranges)) do |res|
      res.each_range_part.with_index do |part, i|
        seen << [part.first, part.last, part.total]
        seen << part.body if i == 1
      end
    end
    assert_equal [[0, 99, 300], [100, 199, 300], [200, 299, 300]],
                 seen.select {|e| e.size == 3 }
    assert_equal object.byteslice(100..199), seen.find {|e| e.is_a?(String) }
  end

  def test_each_range_part_read_body_with_block
    object = (0...100).map {|i| (i * 5 % 239).chr }.join.b
    chunks = []
    read_response(multipart_response(object, [[0, 99]])) do |res|
      res.each_range_part do |part|
        part.read_body {|chunk| chunks << chunk }
      end
    end
    assert_equal object, chunks.join
  end

  def test_each_range_part_read_body_into_dest
    object = (0...50).map {|i| (i * 3 % 233).chr }.join.b
    dest = +''.b
    read_response(multipart_response(object, [[0, 49]])) do |res|
      res.each_range_part do |part|
        part.read_body(dest)
      end
    end
    assert_equal object, dest
  end

  def test_each_range_part_enumerator
    object = ('a'..'z').to_a.join.b
    read_response(multipart_response(object, [[0, 9], [10, 25]])) do |res|
      parts = res.each_range_part.map {|part| [part.first, part.last, part.body] }
      assert_equal [[0, 9, object.byteslice(0..9)], [10, 25, object.byteslice(10..25)]], parts
    end
  end

  def test_range_part_not_readable_after_iteration_advanced
    object = ('a'..'z').to_a.join.b
    stale = nil
    read_response(multipart_response(object, [[0, 9], [10, 25]])) do |res|
      res.each_range_part do |part|
        stale ||= part
      end
    end
    assert_raise(IOError) { stale.read_body }
  end

  def test_each_range_part_after_body_was_read
    object = ('a'..'z').to_a.join.b
    read_response(multipart_response(object, [[0, 9]])) do |res|
      res.read_body
      assert_raise(IOError) { res.each_range_part.to_a }
    end
  end

  def test_each_range_part_out_of_block
    object = ('a'..'z').to_a.join.b
    io = response_io(multipart_response(object, [[0, 9]]))
    res = Net::HTTPResponse.read_new(io)
    assert_raise(IOError) { res.each_range_part.to_a }
  end

  def test_each_range_part_boundary_like_content_over_tcp
    object = (+"start\r\n--#{BOUNDARY}\r\n" * 3 << 'end').b
    ranges = [[0, 29], [30, object.bytesize - 1]]
    body = +''.b
    ranges.each do |first, last|
      body << "--#{BOUNDARY}\r\n"
      body << "Content-Range: bytes #{first}-#{last}/#{object.bytesize}\r\n"
      body << "\r\n"
      body << object.byteslice(first..last)
      body << "\r\n"
    end
    body << "--#{BOUNDARY}--\r\n"

    server = TestNetHTTPUtils::HTTPServer.new('host' => '127.0.0.1') {|_, _, _, _| }
    server.mount_proc('/ranges') do |req, res|
      res.status = 206
      res['Content-Type'] = "multipart/byteranges; boundary=#{BOUNDARY}"
      res.body = body
    end
    server.start
    begin
      parts = []
      Net::HTTP.start('127.0.0.1', server.port) do |http|
        req = Net::HTTP::Get.new('/ranges')
        req['Range'] = "bytes=#{ranges.map {|f, l| "#{f}-#{l}" }.join(',')}"
        http.request(req) do |res|
          res.each_range_part do |part|
            parts << [part.first, part.last, part.total, part.body]
          end
        end
      end
      assert_equal ranges.map {|first, last| [first, last, object.bytesize, object.byteslice(first..last)] },
                   parts
    ensure
      server.shutdown
    end
  rescue Errno::EPERM
    omit 'TCP server not permitted in this environment'
  end
end
