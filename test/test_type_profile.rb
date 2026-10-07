# frozen_string_literal: false
require 'test/unit'
require 'xmlrpc/client'
require 'xmlrpc/server'
require 'xmlrpc/config'

class TestTypeProfile < Test::Unit::TestCase

  STANDARD = XMLRPC::TypeProfile::STANDARD
  EXTENDED = XMLRPC::TypeProfile::EXTENDED

  UNKNOWN_DOC = <<~XML
    <?xml version="1.0" ?>
    <methodResponse><params><param>
    <value><exotic>some text</exotic></value>
    </param></params></methodResponse>
  XML

  def setup
    # profiles must not depend on, nor mutate, these globals
    XMLRPC::Config.enable_bigint = false
    XMLRPC::Config.enable_nil_create = false
    XMLRPC::Config.enable_nil_parser = false
  end

  def teardown
    XMLRPC::Config.enable_bigint = false
    XMLRPC::Config.enable_nil_create = false
    XMLRPC::Config.enable_nil_parser = false
  end

  def create(profile)
    XMLRPC::Create.new(nil, type_profile: profile)
  end

  def parser(profile)
    p = XMLRPC::XMLParser::REXMLStreamParser.new
    p.type_profile = profile
    p
  end

  def response_doc(profile, value)
    create(profile).methodResponse(true, value)
  end

  # --- integer tag selection ---------------------------------------------

  def test_integer_tag_selection_by_range_and_capability
    assert_equal "i4", STANDARD.integer_tag(0)
    assert_equal "i4", STANDARD.integer_tag(2**31 - 1)
    assert_equal "i4", STANDARD.integer_tag(-(2**31))
    assert_nil STANDARD.integer_tag(2**31)

    assert_equal "i4", EXTENDED.integer_tag(2**31 - 1)
    assert_equal "i8", EXTENDED.integer_tag(2**31)
    assert_equal "i8", EXTENDED.integer_tag(-(2**63))
    assert_equal "i8", EXTENDED.integer_tag(2**63 - 1)
    assert_nil EXTENDED.integer_tag(2**63)
  end

  def test_big_integer_uses_i8_never_overflowing_i4
    xml = create(EXTENDED).methodCall("t", 2**40)
    assert_include xml, "<i8>#{2**40}</i8>"
    assert_not_include xml, "<i4>#{2**40}</i4>"
  end

  def test_big_integer_rejected_without_i8_capability
    assert_raise(RuntimeError) { create(STANDARD).methodCall("t", 2**31) }
    assert_raise(RuntimeError) { create(EXTENDED).methodCall("t", 2**63) }
  end

  def test_i8_roundtrip
    ok, val = parser(EXTENDED).parseMethodResponse(response_doc(EXTENDED, 2**40))
    assert_equal true, ok
    assert_equal 2**40, val
  end

  def test_i8_rejected_by_standard_profile
    doc = response_doc(EXTENDED, 2**40)
    e = assert_raise(RuntimeError) { parser(STANDARD).parseMethodResponse(doc) }
    assert_include e.message, "i8"
  end

  # --- exact decimals ------------------------------------------------------

  def test_decimal_encoded_exactly_without_float
    dec = XMLRPC::Decimal.new("0.300000000000000000000000000003")
    xml = create(EXTENDED).methodCall("t", dec)
    assert_include xml, "<decimal>0.300000000000000000000000000003</decimal>"
  end

  def test_decimal_roundtrip_keeps_precision
    dec = XMLRPC::Decimal.new("1.2300")
    ok, val = parser(EXTENDED).parseMethodResponse(response_doc(EXTENDED, dec))
    assert_equal true, ok
    assert_instance_of XMLRPC::Decimal, val
    assert_equal "1.2300", val.to_s
    assert_equal dec, val
  end

  def test_decimal_rejected_by_standard_profile
    assert_raise(RuntimeError) do
      create(STANDARD).methodCall("t", XMLRPC::Decimal.new("1.5"))
    end
    doc = response_doc(EXTENDED, XMLRPC::Decimal.new("1.5"))
    assert_raise(RuntimeError) { parser(STANDARD).parseMethodResponse(doc) }
  end

  def test_decimal_validates_format
    assert_raise(ArgumentError) { XMLRPC::Decimal.new("1.5x") }
    assert_raise(ArgumentError) { XMLRPC::Decimal.new("abc") }
    assert_nothing_raised { XMLRPC::Decimal.new("-12.5e3") }
  end

  # --- nil -----------------------------------------------------------------

  def test_nil_roundtrip_with_extended_profile
    ok, val = parser(EXTENDED).parseMethodResponse(response_doc(EXTENDED, nil))
    assert_equal true, ok
    assert_nil val
  end

  def test_nil_rejected_by_standard_profile
    assert_raise(RuntimeError) { create(STANDARD).methodCall("t", nil) }
    doc = response_doc(EXTENDED, nil)
    assert_raise(RuntimeError) { parser(STANDARD).parseMethodResponse(doc) }
  end

  # --- unknown extensions ----------------------------------------------------

  def test_unknown_extension_kept_as_controlled_value
    ok, val = parser(EXTENDED).parseMethodResponse(UNKNOWN_DOC)
    assert_equal true, ok
    assert_instance_of XMLRPC::UnknownValue, val
    assert_equal "exotic", val.tag
    assert_equal "some text", val.content
  end

  def test_unknown_extension_rejected_by_standard_profile
    e = assert_raise(RuntimeError) { parser(STANDARD).parseMethodResponse(UNKNOWN_DOC) }
    assert_include e.message, "exotic"
  end

  def test_unknown_extension_never_instantiates_ruby_classes
    # a tag named like an existing Ruby class must not be turned into
    # an instance of that class
    doc = <<~XML
      <?xml version="1.0" ?>
      <methodResponse><params><param>
      <value><hash>1</hash></value>
      </param></params></methodResponse>
    XML
    ok, val = parser(EXTENDED).parseMethodResponse(doc)
    assert_equal true, ok
    assert_instance_of XMLRPC::UnknownValue, val
    assert_not_instance_of Hash, val
  end

  def test_unknown_extension_inside_nested_struct
    doc = <<~XML
      <?xml version="1.0" ?>
      <methodResponse><params><param>
      <value><struct>
        <member><name>list</name><value><array><data>
          <value><i4>1</i4></value>
          <value><exotic>x</exotic></value>
        </data></array></value></member>
      </struct></value>
      </param></params></methodResponse>
    XML
    ok, val = parser(EXTENDED).parseMethodResponse(doc)
    assert_equal true, ok
    assert_equal 1, val["list"][0]
    assert_equal XMLRPC::UnknownValue.new("exotic", "x"), val["list"][1]
  end

  # --- value paths in errors -----------------------------------------------

  def test_parse_error_reports_nested_path
    doc = <<~XML
      <?xml version="1.0" ?>
      <methodResponse><params><param>
      <value><struct>
        <member><name>a</name><value><array><data>
          <value><i4>1</i4></value>
          <value><boolean>2</boolean></value>
        </data></array></value></member>
      </struct></value>
      </param></params></methodResponse>
    XML
    e = assert_raise(RuntimeError) { parser(EXTENDED).parseMethodResponse(doc) }
    assert_include e.message, '$["a"][1]'
  end

  def test_parse_error_path_for_unknown_tag
    doc = <<~XML
      <?xml version="1.0" ?>
      <methodResponse><params><param>
      <value><array><data>
        <value><i4>1</i4></value>
        <value><exotic>x</exotic></value>
      </data></array></value>
      </param></params></methodResponse>
    XML
    e = assert_raise(RuntimeError) { parser(STANDARD).parseMethodResponse(doc) }
    assert_include e.message, "$[1]"
  end

  def test_encode_error_reports_nested_path
    e = assert_raise(RuntimeError) do
      create(STANDARD).methodCall("t", {"x" => [1, nil]})
    end
    assert_include e.message, '$["x"][1]'
  end

  def test_encode_error_path_for_big_integer
    e = assert_raise(RuntimeError) do
      create(STANDARD).methodCall("t", [{"k" => 2**40}])
    end
    assert_include e.message, '$[0]["k"]'
  end

  # --- custom profiles -------------------------------------------------------

  def test_custom_profile
    profile = XMLRPC::TypeProfile.new(i8: true)
    assert_true profile.allow_i8?
    assert_false profile.allow_nil?
    assert_false profile.allow_decimal?
    assert_false profile.keep_unknown_extension?

    xml = create(profile).methodCall("t", 2**40)
    assert_include xml, "<i8>"
    assert_raise(RuntimeError) { create(profile).methodCall("t", nil) }
    assert_raise(RuntimeError) { parser(profile).parseMethodResponse(UNKNOWN_DOC) }
  end

  def test_profile_validation
    assert_raise(ArgumentError) do
      XMLRPC::TypeProfile.new(unknown_extension: :bogus)
    end
  end

  def test_predefined_profiles_are_frozen
    assert_true STANDARD.frozen?
    assert_true EXTENDED.frozen?
  end

  # --- instance wiring -------------------------------------------------------

  def test_client_shares_one_profile_between_encoder_and_parser
    client = XMLRPC::Client.new("localhost")
    profile = XMLRPC::TypeProfile.new(i8: true, nil_value: true)
    client.set_type_profile(profile)

    assert_same profile, client.type_profile
    assert_same profile, client.send(:create).type_profile
    assert_same profile, client.send(:parser).type_profile
  end

  def test_server_shares_one_profile_between_encoder_and_parser
    server = XMLRPC::BasicServer.new
    server.set_type_profile(EXTENDED)

    assert_same EXTENDED, server.send(:create).type_profile
    assert_same EXTENDED, server.send(:parser).type_profile
  end

  def test_set_type_profile_validation
    client = XMLRPC::Client.new("localhost")
    assert_raise(ArgumentError) { client.set_type_profile(:standard) }
  end

  def test_profiles_do_not_leak_between_instances
    ext_client = XMLRPC::Client.new("localhost")
    ext_client.set_type_profile(EXTENDED)
    std_client = XMLRPC::Client.new("localhost")
    std_client.set_type_profile(STANDARD)

    assert_nothing_raised { ext_client.send(:create).methodCall("t", nil, 2**40) }
    assert_raise(RuntimeError) { std_client.send(:create).methodCall("t", nil) }
    assert_raise(RuntimeError) { std_client.send(:create).methodCall("t", 2**40) }

    # and a profile-less instance still follows the global config
    plain = XMLRPC::Client.new("localhost")
    assert_nil plain.type_profile
    assert_raise(RuntimeError) { plain.send(:create).methodCall("t", 2**40) }
  end

  # --- concurrent alternating profiles ---------------------------------------

  def test_concurrent_alternating_profiles
    ext_server = XMLRPC::BasicServer.new
    ext_server.set_type_profile(EXTENDED)
    ext_server.add_handler("echo") {|v| v }

    std_server = XMLRPC::BasicServer.new
    std_server.set_type_profile(STANDARD)
    std_server.add_handler("echo") {|v| v }

    ext_client = XMLRPC::Client.new("localhost")
    ext_client.set_type_profile(EXTENDED)
    std_client = XMLRPC::Client.new("localhost")
    std_client.set_type_profile(STANDARD)

    big = 2**40 + 5
    ext_value = {"n" => [big, nil, XMLRPC::Decimal.new("3.141592653589793238462643383279")], "s" => "x"}
    std_value = {"n" => [1, 2, 3], "s" => "y"}

    errors = []
    threads = 8.times.map do
      Thread.new do
        Thread.current.report_on_exception = false
        begin
          25.times do
            # extended round trip through the extended server
            req = ext_client.send(:create).methodCall("echo", ext_value)
            ok, val = ext_client.send(:parser).parseMethodResponse(ext_server.process(req))
            raise "extended call failed" unless ok
            raise "extended mismatch: #{val.inspect}" unless val == ext_value

            # standard round trip through the standard server
            req = std_client.send(:create).methodCall("echo", std_value)
            ok, val = std_client.send(:parser).parseMethodResponse(std_server.process(req))
            raise "standard call failed" unless ok
            raise "standard mismatch: #{val.inspect}" unless val == std_value

            # the standard instance must still reject extended values
            begin
              std_client.send(:create).methodCall("echo", big)
              raise "standard profile leaked i8 capability"
            rescue RuntimeError
            end

            # the extended value must not pass through the standard server
            req = ext_client.send(:create).methodCall("echo", ext_value)
            begin
              std_server.process(req)
              raise "standard server accepted extended value"
            rescue RuntimeError
            end
          end
        rescue => e
          errors << e
        end
      end
    end
    threads.each(&:join)

    assert_empty errors

    # profiles stayed attached to their instances
    assert_same EXTENDED, ext_client.type_profile
    assert_same STANDARD, std_client.type_profile

    # the global configuration was never touched
    assert_equal false, XMLRPC::Config.enable_bigint?
    assert_equal false, XMLRPC::Config.enable_nil_create?
    assert_equal false, XMLRPC::Config.enable_nil_parser?
  end

  # --- default (legacy) mode is preserved ------------------------------------

  def test_default_mode_unchanged
    c = XMLRPC::Create.new
    p = XMLRPC::XMLParser::REXMLStreamParser.new

    # big integers rejected by default
    assert_raise(RuntimeError) { c.methodCall("t", 2**40) }
    # nil rejected by default
    assert_raise(RuntimeError) { c.methodCall("t", nil) }

    # i8 still parsed as integer in legacy mode
    doc = response_doc(EXTENDED, 2**40)
    ok, val = p.parseMethodResponse(doc)
    assert_equal true, ok
    assert_equal 2**40, val

    # unknown tags are still ignored in legacy mode
    ok, val = p.parseMethodResponse(UNKNOWN_DOC)
    assert_equal true, ok
    assert_equal "", val

    # global flags still work without a profile
    XMLRPC::Config.enable_nil_create = true
    XMLRPC::Config.enable_nil_parser = true
    assert_nothing_raised { c.methodCall("t", nil) }
    ok, val = p.parseMethodResponse(c.methodResponse(true, nil))
    assert_equal true, ok
    assert_nil val
  end

end
