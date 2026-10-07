# frozen_string_literal: true

require_relative 'helper'

require 'xmlrpc/server'
require 'xmlrpc/datetime'

class TestXMLRPCSignature < Test::Unit::TestCase
  include TestHelper

  class CountingHandler
    attr_reader :calls

    def initialize
      @calls = 0
    end

    def call(*args)
      @calls += 1
      args.first
    end
  end

  def strict_server
    XMLRPC::BasicServer.new(".", enforce_signatures: true)
  end

  def call(server, name, *args)
    server.send(:call_method, name, *args)
  end

  def fault(server, name, *args)
    ok, result = call(server, name, *args)
    assert_equal(false, ok)
    result
  end

  def test_default_keeps_arity_dispatch
    server = XMLRPC::BasicServer.new
    handler = CountingHandler.new

    server.add_handler("demo.two", %w(string int int)) { |a, b| [a, b] }
    server.add_handler("demo.count") { |*args| handler.call(*args) }

    # parameters do not match the declared types, but the legacy
    # arity-based dispatch ignores signatures
    ok, result = call(server, "demo.two", 1, 2)
    assert_equal([true, [1, 2]], [ok, result])

    ok, result = call(server, "demo.count", "x")
    assert_equal(true, ok)
    assert_equal(1, handler.calls)
  end

  def test_enforce_signatures_matching_call
    server = strict_server
    server.add_handler("demo.add", %w(int int int)) { |a, b| a + b }

    ok, result = call(server, "demo.add", 3, 4)
    assert_equal([true, 7], [ok, result])
  end

  def test_non_matching_parameters_do_not_invoke_handler
    server = strict_server
    handler = CountingHandler.new

    # two signatures: int,int and double,double
    server.add_handler("demo.any",
      [%w(int int int), %w(double double double)]) { |*args| handler.call(*args) }

    e = fault(server, "demo.any", "1", "2")
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
    assert_equal(0, handler.calls)

    # wrong arity also does not run the handler
    e = fault(server, "demo.any", 1)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
    assert_equal(0, handler.calls)

    # mixed int/double matches neither signature
    e = fault(server, "demo.any", 1, 2.0)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
    assert_equal(0, handler.calls)

    ok, result = call(server, "demo.any", 1, 2)
    assert(ok)
    assert_equal(1, handler.calls)

    ok, result = call(server, "demo.any", 1.5, 2.5)
    assert(ok)
    assert_equal(2, handler.calls)
  end

  def test_types_are_matched_strictly
    server = strict_server
    server.add_handler("t.int",    %w(int int))        { |a| a }
    server.add_handler("t.float",  %w(double double))  { |a| a }
    server.add_handler("t.bool",   %w(boolean boolean)) { |a| a }
    server.add_handler("t.string", %w(string string))   { |a| a }
    server.add_handler("t.array",  %w(array array))     { |a| a }
    server.add_handler("t.struct", %w(struct struct))   { |a| a }
    server.add_handler("t.date",   %w(dateTime.iso8601 dateTime.iso8601)) { |a| a }
    server.add_handler("t.b64",    %w(base64 base64))   { |a| a }

    # String is not an int even though it responds to #to_i
    e = fault(server, "t.int", "5")
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)

    # Integer is not a double even though it responds to #to_f
    e = fault(server, "t.float", 5)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)

    # booleans are neither int nor string
    e = fault(server, "t.int", true)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
    e = fault(server, "t.string", false)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)

    assert_equal([true, true],  call(server, "t.bool", true))
    assert_equal([true, "x"],   call(server, "t.string", "x"))
    assert_equal([true, [1]],   call(server, "t.array", [1]))
    assert_equal([true, ({"a" => 1})], call(server, "t.struct", {"a" => 1}))

    dt = XMLRPC::DateTime.new(2026, 10, 8, 12, 0, 0)
    assert_equal([true, dt], call(server, "t.date", dt))
    e = fault(server, "t.date", "2026-10-08")
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)

    b64 = XMLRPC::Base64.new("raw")
    assert_equal([true, b64], call(server, "t.b64", b64))
    # a plain String must not be accepted as base64
    e = fault(server, "t.b64", "raw")
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
  end

  def test_ambiguous_signatures
    # signatures differing only in the declared return type are ambiguous
    server2 = strict_server
    server2.add_handler("demo.ret",
      [%w(int int), %w(double int)]) { |a| a }
    e = fault(server2, "demo.ret", 1)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_AMBIGUOUS, e.faultCode)

    # a typed signature and an untyped handler accepting the same call are
    # also ambiguous
    server3 = strict_server
    handler3 = CountingHandler.new
    server3.add_handler("demo.mix", %w(int int)) { |a| a }
    server3.add_handler("demo.mix") { |*args| handler3.call(*args) }
    e = fault(server3, "demo.mix", 1)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_AMBIGUOUS, e.faultCode)
    assert_equal(0, handler3.calls)
  end

  def test_reregistering_same_signature_overrides_handler
    server = strict_server
    server.add_handler("demo.ov", %w(int int)) { |a| a + 1 }
    server.add_handler("demo.ov", %w(int int)) { |a| a + 100 }

    ok, result = call(server, "demo.ov", 1)
    assert_equal([true, 101], [ok, result])
  end

  def test_reregistering_distinct_signature_adds_overload
    server = strict_server
    server.add_handler("demo.poly", %w(int int))    { |a| a }
    server.add_handler("demo.poly", %w(string string)) { |a| "s:#{a}" }

    assert_equal([true, 5],        call(server, "demo.poly", 5))
    assert_equal([true, "s:x"],   call(server, "demo.poly", "x"))
    e = fault(server, "demo.poly", 1.5)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
  end

  def test_wrong_return_value
    server = strict_server
    server.add_handler("demo.ret", %w(int int)) { |a| "result: #{a}" }

    e = fault(server, "demo.ret", 1)
    assert_equal(XMLRPC::BasicServer::ERR_RETURN_TYPE_MISMATCH, e.faultCode)

    server.add_handler("demo.b64", %w(base64 base64)) { |a| a.decoded }
    b64 = XMLRPC::Base64.new("raw")
    e = fault(server, "demo.b64", b64)
    assert_equal(XMLRPC::BasicServer::ERR_RETURN_TYPE_MISMATCH, e.faultCode)
  end

  def test_correct_base64_return_value
    server = strict_server
    server.add_handler("demo.b64", %w(base64 base64)) { |a| a }
    b64 = XMLRPC::Base64.new("raw")
    assert_equal([true, b64], call(server, "demo.b64", b64))
  end

  def test_method_signature_introspection
    XMLRPC::Config.enable_introspection = true
    server = strict_server
    server.add_handler("demo.poly",
      [%w(i4 int), %w(string string)]) { |a| a }

    ok, sigs = call(server, "system.methodSignature", "demo.poly")
    assert(ok)
    assert_equal([%w(int int), %w(string string)], sigs)
  ensure
    XMLRPC::Config.enable_introspection = false
  end

  def test_multicall_uses_same_validation
    XMLRPC::Config.enable_multicall = true
    server = strict_server
    handler = CountingHandler.new
    server.add_handler("demo.add", %w(int int int)) { |a, b| a + b }
    server.add_handler("demo.count",
      [%w(int int)]) { |*args| handler.call(*args) }

    calls = [
      {"methodName" => "demo.add", "params" => [1, 2]},
      {"methodName" => "demo.count", "params" => ["x"]}
    ]
    ok, results = call(server, "system.multicall", calls)
    assert(ok)
    assert_equal([3], results[0])
    assert_kind_of(Hash, results[1])
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH,
                 results[1]["faultCode"])
    assert_equal(0, handler.calls)
  ensure
    XMLRPC::Config.enable_multicall = false
  end

  def test_missing_method_is_still_distinct
    server = strict_server
    e = fault(server, "demo.unknown", 1)
    assert_equal(XMLRPC::BasicServer::ERR_METHOD_MISSING, e.faultCode)
  end

  def test_service_interface
    interface = XMLRPC::interface("calc") do
      meth 'int add(int, int)', 'sums', 'add'
      meth 'string echo(string)', 'echoes', 'echo'
    end

    obj = Object.new
    def obj.add(a, b); a + b; end
    def obj.echo(a); a; end

    server = strict_server
    server.add_handler(interface, obj)

    assert_equal([true, 3],  call(server, "calc.add", 1, 2))
    assert_equal([true, "x"], call(server, "calc.echo", "x"))
    e = fault(server, "calc.add", "1", "2")
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, e.faultCode)
  end

  def test_xml_roundtrip_base64_and_string_are_distinct
    server = strict_server
    server.add_handler("demo.b64", %w(base64 base64)) { |a| a }
    server.add_handler("demo.str", %w(string string))   { |a| a }

    writer = XMLRPC::Config.default_writer.new

    response = server.send(:process,
      XMLRPC::Create.new(writer).methodCall("demo.b64", XMLRPC::Base64.new("hello")))
    ok, value = parser.parseMethodResponse(response)
    assert(ok)
    assert_equal(XMLRPC::Base64.new("hello"), value)

    response2 = server.send(:process,
      XMLRPC::Create.new(writer).methodCall("demo.str", "hello"))
    _, value = parser.parseMethodResponse(response2)
    assert_equal("hello", value)

    # the wire-level base64 cannot be accepted as a plain string, and the
    # wire-level string cannot be accepted as base64
    response3 = server.send(:process,
      XMLRPC::Create.new(writer).methodCall("demo.str", XMLRPC::Base64.new("hello")))
    _, fault = parser.parseMethodResponse(response3)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, fault.faultCode)
  end

end
