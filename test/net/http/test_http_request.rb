# frozen_string_literal: false
require 'net/http'
require 'test/unit'
require 'stringio'

class HTTPRequestTest < Test::Unit::TestCase

  def test_initialize_GET
    req = Net::HTTP::Get.new '/'

    assert_equal 'GET', req.method
    assert_not_predicate req, :request_body_permitted?
    assert_predicate req, :response_body_permitted?

    expected = {
      'accept'     => %w[*/*],
      'user-agent' => %w[Ruby],
    }

    expected['accept-encoding'] = %w[gzip;q=1.0,deflate;q=0.6,identity;q=0.3] if
      Net::HTTP::HAVE_ZLIB

    assert_equal expected, req.to_hash
  end

  def test_initialize_GET_range
    req = Net::HTTP::Get.new '/', 'Range' => 'bytes=0-9'

    assert_equal 'GET', req.method
    assert_not_predicate req, :request_body_permitted?
    assert_predicate req, :response_body_permitted?

    expected = {
      'accept'     => %w[*/*],
      'user-agent' => %w[Ruby],
      'range'      => %w[bytes=0-9],
    }

    assert_equal expected, req.to_hash
  end

  def test_initialize_HEAD
    req = Net::HTTP::Head.new '/'

    assert_equal 'HEAD', req.method
    assert_not_predicate req, :request_body_permitted?
    assert_not_predicate req, :response_body_permitted?

    expected = {
      'accept'          => %w[*/*],
      "accept-encoding" => %w[gzip;q=1.0,deflate;q=0.6,identity;q=0.3],
      'user-agent'      => %w[Ruby],
    }

    assert_equal expected, req.to_hash
  end

  def test_initialize_accept_encoding
    req1 = Net::HTTP::Get.new '/'

    assert req1.decode_content, 'Bug #7831 - automatically decode content'

    req2 = Net::HTTP::Get.new '/', 'accept-encoding' => 'identity'

    assert_not_predicate req2, :decode_content,
                         'Bug #7381 - do not decode content if the user overrides'
  end if Net::HTTP::HAVE_ZLIB

  def test_initialize_GET_uri
    req = Net::HTTP::Get.new(URI("http://example.com/foo"))
    assert_equal "/foo", req.path
    assert_equal "example.com", req['Host']

    req = Net::HTTP::Get.new(URI("https://example.com/foo"))
    assert_equal "/foo", req.path
    assert_equal "example.com", req['Host']

    req = Net::HTTP::Get.new(URI("https://203.0.113.1/foo"))
    assert_equal "/foo", req.path
    assert_equal "203.0.113.1", req['Host']

    req = Net::HTTP::Get.new(URI("https://203.0.113.1:8000/foo"))
    assert_equal "/foo", req.path
    assert_equal "203.0.113.1:8000", req['Host']

    req = Net::HTTP::Get.new(URI("https://[2001:db8::1]:8000/foo"))
    assert_equal "/foo", req.path
    assert_equal "[2001:db8::1]:8000", req['Host']

    assert_raise(ArgumentError){ Net::HTTP::Get.new(URI("urn:ietf:rfc:7231")) }
    assert_raise(ArgumentError){ Net::HTTP::Get.new(URI("http://")) }
  end

  def test_header_set
    req = Net::HTTP::Get.new '/'

    assert req.decode_content, 'Bug #7831 - automatically decode content'

    req['accept-encoding'] = 'identity'

    assert_not_predicate req, :decode_content,
                         'Bug #7831 - do not decode content if the user overrides'
  end if Net::HTTP::HAVE_ZLIB

  def test_update_uri
    req = Net::HTTP::Get.new(URI.parse("http://203.0.113.1"))
    req.update_uri("test", 8080, false)
    assert_equal "203.0.113.1", req.uri.host
    assert_equal 8080, req.uri.port

    req = Net::HTTP::Get.new(URI.parse("http://203.0.113.1:2020"))
    req.update_uri("test", 8080, false)
    assert_equal "203.0.113.1", req.uri.host
    assert_equal 8080, req.uri.port

    req = Net::HTTP::Get.new(URI.parse("http://[2001:db8::1]"))
    req.update_uri("test", 8080, false)
    assert_equal "[2001:db8::1]", req.uri.host
    assert_equal 8080, req.uri.port

    req = Net::HTTP::Get.new(URI.parse("http://[2001:db8::1]:2020"))
    req.update_uri("test", 8080, false)
    assert_equal "[2001:db8::1]", req.uri.host
    assert_equal 8080, req.uri.port
  end

  def test_body_factory_default
    req = Net::HTTP::Put.new('/')
    assert_nil req.body_factory
  end

  def test_body_factory_assignment
    factory = proc { [StringIO.new('abc'), 3] }
    req = Net::HTTP::Put.new('/')
    req.body = 'xyz'
    req.body_factory = factory
    assert_same factory, req.body_factory
    assert_nil req.body
    assert_nil req.body_stream
  end

  def test_body_factory_cleared_by_body_assignment
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { [StringIO.new('abc'), 3] }
    req.body = 'xyz'
    assert_nil req.body_factory
    assert_equal 'xyz', req.body
  end

  def test_body_factory_cleared_by_body_stream_assignment
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { [StringIO.new('abc'), 3] }
    req.body_stream = StringIO.new('xyz')
    assert_nil req.body_factory
    assert_not_nil req.body_stream
  end

  def test_body_factory_cleared_by_set_form
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { [StringIO.new('abc'), 3] }
    req.set_form([['field', 'value']], 'multipart/form-data')
    assert_nil req.body_factory
  end

  def test_body_factory_must_respond_to_call
    req = Net::HTTP::Put.new('/')
    assert_raise(ArgumentError) { req.body_factory = 123 }
  end

  def test_body_factory_mutual_exclusion_with_request_body_argument
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { [StringIO.new('abc'), 3] }
    assert_raise(ArgumentError) { req.set_body_internal('xyz') }
  end

  def test_exec_with_body_factory_validates_result
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { StringIO.new('abc') }
    assert_raise(ArgumentError) do
      req.send(:send_request_with_body_factory, nil, '1.1', '/', nil)
    end
  end

  def test_exec_with_body_factory_validates_length
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { [StringIO.new('abc'), 'many'] }
    assert_raise(ArgumentError) do
      req.send(:send_request_with_body_factory, nil, '1.1', '/', nil)
    end
  end

  def test_exec_with_body_factory_validates_stream
    req = Net::HTTP::Put.new('/')
    req.body_factory = proc { [Object.new, 3] }
    assert_raise(ArgumentError) do
      req.send(:send_request_with_body_factory, nil, '1.1', '/', nil)
    end
  end
end
