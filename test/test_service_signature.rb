# frozen_string_literal: true

require_relative "helper"

require "xmlrpc/server"

class TestServiceSignature < Test::Unit::TestCase
  include TestHelper

  class SignatureServer < XMLRPC::BasicServer
  end

  class PublicHandler
    def echo(value)
      value
    end
  end

  def setup
    @server = SignatureServer.new
    @server.set_parser(parser)
    @calls = 0
  end

  def test_multiple_signatures_select_by_xmlrpc_type
    @server.add_handler("value", [["int", "int"], ["double", "double"],
                                  ["boolean", "boolean"], ["string", "string"],
                                  ["base64", "base64"],
                                  ["dateTime.iso8601", "dateTime.iso8601"],
                                  ["array", "array"], ["struct", "struct"]]) do |value|
      @calls += 1
      value
    end

    assert_equal(1, call("value", 1))
    assert_in_delta(1.5, call("value", 1.5))
    assert_equal(true, call("value", true))
    assert_equal("1", call("value", "1"))
    assert_instance_of(XMLRPC::Base64, call("value", XMLRPC::Base64.new("abc")))
    assert_instance_of(XMLRPC::DateTime, call("value", XMLRPC::DateTime.new(2026, 10, 8, 12, 0, 0)))
    assert_equal([1], call("value", [1]))
    assert_equal({"a" => 1}, call("value", {"a" => 1}))
    assert_equal(8, @calls)
  end

  def test_no_candidate_does_not_invoke_handler
    @server.add_handler("value", [["int", "int"], ["double", "double"]]) do |value|
      @calls += 1
      value
    end

    fault = fault_for("value", "1")
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, fault.faultCode)
    assert_equal(0, @calls)
  end

  def test_ambiguous_candidate_does_not_invoke_handler
    @server.add_handler("value", %w(int int)) { @calls += 1; 1 }
    @server.add_handler("value", %w(double int)) { @calls += 1; 1 }

    fault = fault_for("value", 1)
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_AMBIGUOUS, fault.faultCode)
    assert_equal(0, @calls)
  end

  def test_return_value_mismatch
    @server.add_handler("value", %w(int string)) do |value|
      @calls += 1
      value
    end

    fault = fault_for("value", "not an int")
    assert_equal(XMLRPC::BasicServer::ERR_RETURN_VALUE_MISMATCH, fault.faultCode)
    assert_equal(1, @calls)
  end

  def test_return_value_uses_exact_xmlrpc_type
    @server.add_handler("value", %w(string int)) { |_| :symbol }

    assert_equal(XMLRPC::BasicServer::ERR_RETURN_VALUE_MISMATCH,
                 fault_for("value", 1).faultCode)
  end

  def test_method_signature_reflects_enforced_contract
    @server.add_introspection
    @server.add_handler("value", [["int", "int"], ["string", "dateTime"]]) { |value| value }

    assert_equal([["int", "int"], ["string", "dateTime.iso8601"]],
                 call("system.methodSignature", "value"))
  end

  def test_legacy_arity_dispatch_remains_default
    @server.add_handler("value") do |value|
      @calls += 1
      value
    end

    assert_equal("abc", call("value", XMLRPC::Base64.new("abc")))
    assert_equal(1, @calls)
  end

  def test_legacy_arity_overloading_remains_default
    @server.add_handler("value") { |value| value }
    @server.add_handler("value") { |first, second| [first, second] }

    assert_equal(1, call("value", 1))
    assert_equal([1, 2], call("value", 1, 2))
  end

  def test_default_handler_uses_legacy_xmlrpc_values
    @server.set_default_handler { |_method, value| value }

    assert_equal("abc", call("missing", XMLRPC::Base64.new("abc")))
  end

  def test_multicall_uses_signature_dispatch
    @server.add_multicall
    @server.add_handler("value", %w(int int)) { |value| value }
    @server.add_handler("invalid", %w(int int)) do
      @calls += 1
      1
    end

    result = call("system.multicall", [
      {"methodName" => "value", "params" => [1]},
      {"methodName" => "invalid", "params" => ["1"]}
    ])

    assert_equal([[1], {"faultCode" => XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH,
                        "faultString" => "No matching method signature for method invalid!"}],
                 result)
    assert_equal(0, @calls)
  end

  def test_multicall_wrong_outer_argument_type
    @server.add_multicall

    fault = fault_for("system.multicall", {"methodName" => "value", "params" => []})
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH, fault.faultCode)
  end

  def test_handler_registration_overrides_matching_signature
    @server.add_introspection
    @server.add_handler("value", %w(int int)) { @calls += 1; 1 }
    @server.add_handler("value", %w(int int)) { @calls += 1; 2 }

    assert_equal(2, call("value", 1))
    assert_equal(1, @calls)
    assert_equal([["int", "int"]], call("system.methodSignature", "value"))
  end

  def test_handler_registration_overrides_only_matching_signature
    @server.add_handler("value", [["int", "int"], ["string", "string"]]) { |value| value }
    @server.add_handler("value", %w(int int)) { |value| value + 10 }

    assert_equal(11, call("value", 1))
    assert_equal("a", call("value", "a"))
  end

  def test_interface_registration_enforces_signatures
    service = XMLRPC::interface("sample") do
      meth "int echo(int)", "Echo an integer", "echo"
    end

    object = Object.new
    def object.echo(value)
      value
    end

    @server.add_handler(service, object)

    assert_equal(1, call("sample.echo", 1))
    assert_equal(XMLRPC::BasicServer::ERR_SIGNATURE_MISMATCH,
                 fault_for("sample.echo", "1").faultCode)
  end

  def test_public_instance_methods_keep_legacy_dispatch
    @server.add_handler(XMLRPC::iPIMethods("sample"), PublicHandler.new)

    assert_equal("abc", call("sample.echo", XMLRPC::Base64.new("abc")))
  end

  private

  def call(method, *args)
    ok, result = request(method, *args)
    raise result unless ok
    result
  end

  def fault_for(method, *args)
    ok, result = request(method, *args)
    refute(ok)
    result
  end

  def request(method, *args)
    request_writer = XMLRPC::Create.new
    response_parser = parser.class.new
    response_parser.preserve_xmlrpc_types = true
    data = @server.process(request_writer.methodCall(method, *args))
    response_parser.parseMethodResponse(data)
  end
end
