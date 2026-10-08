# frozen_string_literal: true
require_relative 'helper'

require 'stringio'
require 'xmlrpc/base64'
require 'xmlrpc/client'

class StreamingBase64Test < Test::Unit::TestCase
  class BoundedReader < StringIO
    def initialize(data, limit = 7)
      super(data)
      @limit = limit
    end

    def read(length = nil, outbuf = nil)
      raise "unbounded read" if length.nil? || length > @limit
      super
    end
  end

  class BoundedWriter < StringIO
    def initialize(limit = 3)
      super(String.new)
      @limit = limit
    end

    def write(data)
      raise "unbounded write" if data.to_s.bytesize > @limit
      super
    end
  end

  class FailingWriter < StringIO
    def initialize
      super(String.new)
    end

    def write(_data)
      raise "sink failure"
    end
  end

  def setup
    @create = XMLRPC::Create.new
    @parser = XMLRPC::XMLParser::REXMLStreamParser.new
    @data = ("\x00".."\xff").map(&:chr).join * 12
  end

  def test_streaming_request_matches_small_path
    body = @create.methodCall("stream", BoundedReader.new(@data))
    chunks = read_body(body, 13)
    expected = @create.methodCall("stream", XMLRPC::Base64.new(@data))

    assert_equal expected, chunks.join
    assert chunks.map(&:bytesize).max <= 13
  end

  def test_streaming_response_nested_sink
    value = ["before", {"binary" => [BoundedReader.new(@data), "after"]}]
    body = @create.methodResponse(true, value)
    sink = BoundedWriter.new
    parsed = @parser.parseMethodResponse(
      body,
      base64_sinks: {[1, "binary", 0] => sink}
    )

    assert_equal true, parsed.first
    assert_equal "before", parsed.last[0]
    assert_kind_of XMLRPC::Base64::Sink, parsed.last[1]["binary"][0]
    assert_same sink, parsed.last[1]["binary"][0].io
    assert_equal "after", parsed.last[1]["binary"][1]
    assert_equal @data, sink.string
  end

  def test_response_sink_with_split_xml_events
    encoded = [@data].pack("m").scan(/.{1,3}/m)
    xml = response(encoded.join("\n"))
    sink = BoundedWriter.new

    parsed = @parser.parseMethodResponse(
      BoundedReader.new(xml),
      base64_sinks: {[] => sink}
    )

    assert_equal true, parsed.first
    assert_kind_of XMLRPC::Base64::Sink, parsed.last
    assert_same sink, parsed.last.io
    assert_equal @data, sink.string
  end

  def test_method_call_nested_sink_path
    request = @create.methodCall(
      "stream",
      "first",
      {"binary" => ["before", XMLRPC::Base64.new(@data)]}
    )
    sink = BoundedWriter.new

    method, params = @parser.parseMethodCall(
      request,
      base64_sinks: {[1, "binary", 1] => sink}
    )

    assert_equal "stream", method
    assert_equal "first", params.first
    assert_kind_of XMLRPC::Base64::Sink, params.last["binary"][1]
    assert_equal @data, sink.string
  end

  def test_malformed_base64_stops_and_closes_owned_sink
    sink_io = StringIO.new
    sink = XMLRPC::Base64::Sink.new(sink_io, close: true)

    assert_raise(RuntimeError) do
      @parser.parseMethodResponse(response("QQ!!"), base64_sinks: {[] => sink})
    end
    assert sink_io.closed?
  end

  def test_sink_write_failure_closes_owned_sink
    failing_io = FailingWriter.new
    sink = XMLRPC::Base64::Sink.new(failing_io, close: true)

    assert_raise(RuntimeError) do
      @parser.parseMethodResponse(response("QQ=="), base64_sinks: {[] => sink})
    end
    assert failing_io.closed?
  end

  def test_caller_owned_io_is_not_closed
    input = BoundedReader.new(@data)
    sink_io = StringIO.new
    body = @create.methodResponse(true, input)

    @parser.parseMethodResponse(body, base64_sinks: {[] => sink_io})

    refute input.closed?
    refute sink_io.closed?
  end

  def test_cancellation_closes_owned_resources
    input = BoundedReader.new(@data)
    sink_io = StringIO.new
    body = @create.methodResponse(
      true,
      XMLRPC::Base64::Stream.new(input, close: true)
    )
    sink = XMLRPC::Base64::Sink.new(sink_io, close: true)

    assert_raise(XMLRPC::CancelledError) do
      @parser.parseMethodResponse(body, base64_sinks: {[] => sink}) do |listener|
        listener.cancel
      end
    end
    assert input.closed?
    assert sink_io.closed?
  end

  def test_client_streams_request_and_response
    request_io = BoundedReader.new(@data)
    sink = BoundedWriter.new
    response_body = streaming_response_body
    http = StreamingHTTP.new(response_body)
    client = streaming_client(http)

    result = client.call(
      "stream",
      request_io,
      base64_sinks: {[] => sink}
    )

    assert_kind_of XMLRPC::Base64::Sink, result
    assert_same sink, result.io
    assert_equal @data, sink.string
    assert http.max_request_chunk <= 7
    assert http.request_body.include?("<base64>")
    expected_request = @create.methodCall("stream", XMLRPC::Base64.new(@data))
    assert_equal expected_request, http.request_body
  end

  def test_client_cancellation_closes_owned_request_and_sink
    input = BoundedReader.new(@data)
    sink_io = StringIO.new
    http = StreamingHTTP.new(streaming_response_body)
    client = streaming_client(http)
    chunks = 0

    assert_raise(IOError, RuntimeError) do
      client.call(
        "stream",
        XMLRPC::Base64::Stream.new(input, close: true),
        base64_sinks: {[] => XMLRPC::Base64::Sink.new(sink_io, close: true)},
        on_cancel: ->(_) { (chunks += 1) > 0 }
      )
    end

    assert input.closed?
    assert sink_io.closed?
  end

  def test_client_rejects_response_before_sink
    sink = BoundedWriter.new
    http = StreamingHTTP.new(streaming_response_body, "text/plain")
    client = streaming_client(http)

    assert_raise(RuntimeError) do
      client.call("stream", BoundedReader.new(@data), base64_sinks: {[] => sink})
    end
    assert sink.string.empty?
  end

  private

  def read_body(body, length)
    chunks = []
    while chunk = body.read(length)
      chunks << chunk
    end
    chunks
  end

  def response(base64)
    "<?xml version=\"1.0\" ?>" \
      "<methodResponse><params><param><value><base64>" \
      "#{base64}</base64></value></param></params></methodResponse>\n"
  end

  def streaming_client(http)
    client_class = Class.new(XMLRPC::Client) do
      define_method(:net_http) { |*_| http }
    end
    client_class.new2("http://example.org/RPC2")
  end

  def streaming_response_body
    body = @create.methodResponse(true, BoundedReader.new(@data))
    chunks = []
    while chunk = body.read(7)
      chunks << chunk
    end
    chunks.compact.join
  end

  class StreamingHTTP
    attr_reader :request_body, :max_request_chunk

  def initialize(response_body, content_type = "text/xml")
    @response_body = response_body
    @content_type = content_type
      @request_body = String.new
      @request_body.force_encoding(Encoding::BINARY)
      @max_request_chunk = 0
    end

    def started?
      true
    end

    def start
      yield self
    end

    def use_ssl?
      false
    end

    def read_timeout
      30
    end

    def read_timeout=(*)
    end

    alias open_timeout read_timeout
    alias open_timeout= read_timeout=

    def request(request)
      consume(request.body_stream || request.body)
      response = StreamingResponse.new(@response_body, @content_type)
      yield response if block_given?
      response
    end

    def request_post(path, body, headers)
      consume(body)
      StreamingResponse.new(@response_body, @content_type)
    end

    private

    def consume(body)
      if body.respond_to?(:read)
        while chunk = body.read(7)
          raise "unbounded request read" if chunk.bytesize > 7
          @max_request_chunk = [@max_request_chunk, chunk.bytesize].max
          @request_body << chunk
        end
      else
        @request_body << body.to_s
      end
    end
  end

  class StreamingResponse
    def initialize(body, content_type = "text/xml")
      @body = body
      @content_type = content_type
    end

    def code
      "200"
    end

    def message
      "OK"
    end

    def [](name)
      {"Content-Type" => @content_type}[name]
    end

    def get_fields(_name)
      nil
    end

    def read_body
      offset = 0
      while offset < @body.bytesize
        chunk = @body.byteslice(offset, 5)
        yield chunk
        offset += chunk.bytesize
      end
    end
  end
end
