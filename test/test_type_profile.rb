# frozen_string_literal: false
require 'test/unit'
require 'bigdecimal'
require 'xmlrpc/client'
require 'xmlrpc/server'
require 'xmlrpc/type_profile'

class TestTypeProfile < Test::Unit::TestCase

  # In-process client which delivers requests to a local server instance,
  # so no socket is needed.
  class LoopbackClient < XMLRPC::Client
    attr_accessor :backend

    private

    def do_rpc(request, async=false)
      @backend.process(request)
    end
  end

  def setup
    @standard = XMLRPC::TypeProfile.standard
    @extended = XMLRPC::TypeProfile.extended
  end

  def create(profile=nil)
    XMLRPC::Create.new(nil, type_profile: profile)
  end

  def parser(profile=nil)
    parser = XMLRPC::XMLParser::REXMLStreamParser.new
    parser.type_profile = profile
    parser
  end

  def roundtrip(value, profile)
    xml = create(profile).methodCall("echo", value)
    parser(profile).parseMethodCall(xml)[1][0]
  end

  # --- profile definition --------------------------------------------------

  def test_profile_capabilities
    assert_false(@standard.nil_value?)
    assert_false(@standard.big_integer?)
    assert_false(@standard.decimal?)
    assert_true(@standard.reject_unknown_extensions?)

    assert_true(@extended.nil_value?)
    assert_true(@extended.big_integer?)
    assert_true(@extended.decimal?)
    assert_true(@extended.reject_unknown_extensions?)

    custom = XMLRPC::TypeProfile.new(:mine, nil_value: true,
                                     unknown_extension: :preserve)
    assert_true(custom.nil_value?)
    assert_false(custom.big_integer?)
    assert_true(custom.preserve_unknown_extensions?)

    assert_raise(ArgumentError) do
      XMLRPC::TypeProfile.new(:broken, unknown_extension: :explode)
    end
  end

  # --- integer range handling ----------------------------------------------

  def test_integer_tag_selected_by_range_and_profile
    assert_include(create(@extended).methodCall("m", 2**31 - 1), "<i4>2147483647</i4>")
    assert_include(create(@extended).methodCall("m", -(2**31)), "<i4>-2147483648</i4>")

    # 64-bit values use the i8 extension, never an out-of-range i4
    xml = create(@extended).methodCall("m", 2**31)
    assert_include(xml, "<i8>2147483648</i8>")
    assert_not_include(xml, "<i4>2147483648</i4>")

    assert_include(create(@extended).methodCall("m", 2**63 - 1),
                   "<i8>9223372036854775807</i8>")
    assert_include(create(@extended).methodCall("m", -(2**63)),
                   "<i8>-9223372036854775808</i8>")
  end

  def test_integer_out_of_range_raises
    # standard profile: no i8, 32-bit only
    assert_raise(RuntimeError) { create(@standard).methodCall("m", 2**31) }
    # extended profile: beyond 64-bit is rejected, not squeezed into i8
    assert_raise(RuntimeError) { create(@extended).methodCall("m", 2**63) }
    assert_raise(RuntimeError) { create(@extended).methodCall("m", -(2**63) - 1) }
  end

  def test_i8_roundtrip
    assert_equal(2**40, roundtrip(2**40, @extended))
    assert_equal(-(2**40), roundtrip(-(2**40), @extended))
  end

  def test_i8_parse_rejected_by_standard_profile
    xml = create(@extended).methodCall("m", 2**40)
    assert_include(xml, "<i8>")
    error = assert_raise(RuntimeError) { parser(@standard).parseMethodCall(xml) }
    assert_include(error.message, "i8")
  end

  # --- nil -----------------------------------------------------------------

  def test_nil_roundtrip_with_extended_profile
    assert_nil(roundtrip(nil, @extended))
    assert_equal([nil, 1], roundtrip([nil, 1], @extended))
  end

  def test_nil_rejected_by_standard_profile
    error = assert_raise(RuntimeError) { create(@standard).methodCall("m", nil) }
    assert_include(error.message, "params[0]")

    xml = create(@extended).methodCall("m", nil)
    assert_raise(RuntimeError) { parser(@standard).parseMethodCall(xml) }
  end

  # --- decimal -------------------------------------------------------------

  def test_decimal_encoded_exactly_without_float
    xml = create(@extended).methodCall("m", BigDecimal("0.1"))
    assert_include(xml, "<bigdecimal>0.1</bigdecimal>")
    xml = create(@extended).methodCall("m", BigDecimal("123456789.987654321"))
    assert_include(xml, "<bigdecimal>123456789.987654321</bigdecimal>")
  end

  def test_decimal_roundtrip_stays_exact
    value = roundtrip(BigDecimal("0.1"), @extended)
    assert_instance_of(BigDecimal, value)
    assert_equal(BigDecimal("0.1"), value)

    # more digits than a Float can hold: any detour through Float would
    # lose precision here
    value = roundtrip(BigDecimal("123456789.987654321"), @extended)
    assert_instance_of(BigDecimal, value)
    assert_equal("123456789.987654321", value.to_s("F"))
  end

  def test_decimal_rejected_by_standard_profile
    assert_raise(RuntimeError) { create(@standard).methodCall("m", BigDecimal("1.5")) }

    xml = create(@extended).methodCall("m", BigDecimal("1.5"))
    assert_raise(RuntimeError) { parser(@standard).parseMethodCall(xml) }
  end

  # --- unknown extensions --------------------------------------------------

  UNKNOWN_XML = <<~XML
    <?xml version="1.0" ?>
    <methodCall>
      <methodName>m</methodName>
      <params>
        <param><value><frobnicate>blub</frobnicate></value></param>
      </params>
    </methodCall>
  XML

  def test_unknown_extension_rejected_by_default
    error = assert_raise(RuntimeError) { parser(@standard).parseMethodCall(UNKNOWN_XML) }
    assert_include(error.message, "frobnicate")
    assert_include(error.message, "params[0]")

    assert_raise(RuntimeError) { parser(@extended).parseMethodCall(UNKNOWN_XML) }
  end

  def test_unknown_extension_preserved_as_controlled_value
    profile = XMLRPC::TypeProfile.new(:lax, unknown_extension: :preserve)
    value = parser(profile).parseMethodCall(UNKNOWN_XML)[1][0]

    # kept as a controlled value, never instantiated as a Ruby class by tag name
    assert_instance_of(XMLRPC::UnknownValue, value)
    assert_equal("frobnicate", value.tag)
    assert_equal("blub", value.content)

    # and it can be re-encoded with the same profile
    xml = create(profile).methodCall("m", value)
    assert_include(xml, "<frobnicate>blub</frobnicate>")
  end

  def test_unknown_extension_rejected_without_preserve
    profile = XMLRPC::TypeProfile.new(:strict)
    assert_raise(RuntimeError) { parser(profile).parseMethodCall(UNKNOWN_XML) }
    assert_raise(RuntimeError) do
      create(profile).methodCall("m", XMLRPC::UnknownValue.new("frobnicate", "blub"))
    end
  end

  # --- value paths in errors -----------------------------------------------

  def test_encoder_error_carries_value_path
    error = assert_raise(RuntimeError) do
      create(@standard).methodCall("m", {"a" => [1, nil]})
    end
    assert_include(error.message, 'params[0]["a"][1]')

    error = assert_raise(RuntimeError) do
      create(@standard).methodCall("m", 1, {"deep" => [{"x" => 2**31}]})
    end
    assert_include(error.message, 'params[1]["deep"][0]["x"]')
  end

  def test_parser_error_carries_value_path
    xml = <<~XML
      <?xml version="1.0" ?>
      <methodCall>
        <methodName>m</methodName>
        <params>
          <param>
            <value>
              <struct>
                <member>
                  <name>key</name>
                  <value>
                    <array>
                      <data>
                        <value><i4>1</i4></value>
                        <value><boolean>2</boolean></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
          </param>
        </params>
      </methodCall>
    XML

    error = assert_raise(RuntimeError) { parser(@extended).parseMethodCall(xml) }
    assert_include(error.message, 'params[0]["key"][1]')
  end

  # --- default behavior without a profile ----------------------------------

  def test_default_instances_behave_like_standard_mode
    create = XMLRPC::Create.new
    assert_nil(create.type_profile)
    assert_raise(RuntimeError) { create.methodCall("m", nil) }
    assert_raise(RuntimeError) { create.methodCall("m", 2**31) }
    assert_include(create.methodCall("m", 42), "<i4>42</i4>")

    # the i8 tag is still accepted for backwards compatibility
    xml = create(@extended).methodCall("m", 2**40)
    assert_equal(["m", [2**40]], parser(nil).parseMethodCall(xml))

    # global flags are honored as before
    begin
      XMLRPC::Config.enable_nil_create = true
      assert_include(XMLRPC::Create.new.methodCall("m", nil), "<nil/>")
    ensure
      XMLRPC::Config.enable_nil_create = false
    end
  end

  # --- client/server instances ---------------------------------------------

  def make_server(profile)
    server = XMLRPC::BasicServer.new(type_profile: profile)
    server.add_handler("echo") { |value| value }
    server
  end

  def make_client(server, profile)
    client = LoopbackClient.new("localhost", "/RPC2", 80, type_profile: profile)
    client.backend = server
    client
  end

  def test_client_and_server_share_one_profile
    server = make_server(@extended)
    client = make_client(server, @extended)

    assert_same(@extended, client.type_profile)
    assert_same(@extended, server.type_profile)

    assert_equal([nil, 2**40, BigDecimal("0.25")],
                 client.call("echo", [nil, 2**40, BigDecimal("0.25")]))
  end

  def test_profile_assignment_propagates_to_encoder_and_parser
    client = LoopbackClient.new("localhost", "/RPC2", 80)
    assert_nil(client.type_profile)

    client.type_profile = @extended
    assert_same(@extended, client.type_profile)
    assert_same(@extended, client.send(:create).type_profile)
    assert_same(@extended, client.send(:parser).type_profile)

    server = XMLRPC::BasicServer.new
    server.type_profile = @standard
    assert_same(@standard, server.send(:create).type_profile)
    assert_same(@standard, server.send(:parser).type_profile)
  end

  def test_client_new3_accepts_type_profile
    client = XMLRPC::Client.new3("host" => "localhost", "path" => "/RPC2",
                                 "type_profile" => @extended)
    assert_same(@extended, client.type_profile)
  end

  def test_profiles_do_not_leak_between_instances
    standard_server = make_server(@standard)
    extended_server = make_server(@extended)
    standard_client = make_client(standard_server, @standard)
    extended_client = make_client(extended_server, @extended)

    assert_raise(RuntimeError) { standard_client.call("echo", nil) }
    assert_nil(extended_client.call("echo", nil))

    # the standard pair is unaffected by the extended pair
    assert_raise(RuntimeError) { standard_client.call("echo", 2**40) }
    assert_equal(2**40, extended_client.call("echo", 2**40))

    # an extended client cannot push extensions into a standard server
    cross = make_client(standard_server, @extended)
    assert_raise(RuntimeError) { cross.call("echo", nil) }
  end

  def test_concurrent_calls_with_alternating_profiles
    standard_server = make_server(@standard)
    extended_server = make_server(@extended)
    standard_client = make_client(standard_server, @standard)
    extended_client = make_client(extended_server, @extended)

    errors = []
    threads = []

    4.times do |n|
      threads << Thread.new do
        25.times do |i|
          if (n + i).even?
            result = extended_client.call("echo", [nil, 2**40 + i, BigDecimal("1.5")])
            unless result == [nil, 2**40 + i, BigDecimal("1.5")]
              errors << "extended roundtrip broken: #{result.inspect}"
            end
          else
            result = standard_client.call("echo", {"n" => [i, "x"]})
            errors << "standard roundtrip broken: #{result.inspect}" unless result == {"n" => [i, "x"]}
            begin
              standard_client.call("echo", nil)
              errors << "standard client accepted nil"
            rescue RuntimeError
              # expected
            end
          end
        end
      end
    end
    threads.each(&:join)

    assert_empty(errors)

    # settings did not wander from one instance to the other
    assert_same(@standard, standard_client.type_profile)
    assert_same(@extended, extended_client.type_profile)
    assert_same(@standard, standard_server.type_profile)
    assert_same(@extended, extended_server.type_profile)

    # global defaults untouched
    assert_false(XMLRPC::Config.enable_nil_create?)
    assert_false(XMLRPC::Config.enable_nil_parser?)
    assert_false(XMLRPC::Config.enable_bigint?)
  end

end
