# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "net_imap_test_helpers"

class ResponseParserTest < Net::IMAP::TestCase
  TEST_FIXTURE_PATH = File.join(__dir__, "fixtures/response_parser")

  include NetIMAPTestHelpers
  extend  NetIMAPTestHelpers::TestFixtureGenerators

  ############################################################################
  # Tests that do no more than parse an example response and assert the result
  # data has the correct values have been moved to yml test fixtures.
  #
  # The simplest way to add or update new test cases is to add only the test
  # name and response string to the yaml file, and then re-run the tests.  The
  # test will be marked pending, and the parsed result will be serialized and
  # printed on stdout.  This can then be copied into the yaml file.
  ############################################################################
  # Core IMAP, by RFC9051 section (w/obsolete in relative RFC3501 section):
  generate_tests_from fixture_file: "rfc3501_examples.yml"

  # §4.3: Strings (also §5.1, §9, and RFC6855):
  generate_tests_from fixture_file: "utf8_responses.yml"

  # §7.1: Generic Status Responses (OK, NO, BAD, PREAUTH, BYE, codes, text)
  generate_tests_from fixture_file: "resp_code_examples.yml"
  generate_tests_from fixture_file: "resp_cond_examples.yml"
  generate_tests_from fixture_file: "resp_text_responses.yml"

  # §7.2.1: ENABLED response
  generate_tests_from fixture_file: "enabled_responses.yml"

  # §7.2.2: CAPABILITY response
  generate_tests_from fixture_file: "capability_responses.yml"

  # §7.3.1: LIST response (including obsolete LSUB and XLIST responses)
  generate_tests_from fixture_file: "list_responses.yml"

  # §7.3.2: NAMESPACE response (also RFC2342)
  generate_tests_from fixture_file: "namespace_responses.yml"

  # §7.3.3: STATUS response
  generate_tests_from fixture_file: "status_responses.yml"

  # §7.3.4: ESEARCH response
  generate_tests_from fixture_file: "esearch_responses.yml"

  # RFC3501 §7.2.5: SEARCH response (obsolete in IMAP4rev2):
  generate_tests_from fixture_file: "search_responses.yml"

  # §7.3.5: FLAGS response
  generate_tests_from fixture_file: "flags_responses.yml"

  # §7.4: Mailbox size, EXISTS and RECENT
  generate_tests_from fixture_file: "mailbox_size_responses.yml"

  # §7.5.1: EXPUNGE response
  generate_tests_from fixture_file: "expunge_responses.yml"

  # §7.5.2: FETCH response, misc msg-att
  generate_tests_from fixture_file: "fetch_responses.yml"

  # §7.5.2: FETCH response, BODYSTRUCTURE msg-att
  generate_tests_from fixture_file: "body_structure_responses.yml"

  # §7.6: Command Continuation Request
  generate_tests_from fixture_file: "continuation_requests.yml"

  ############################################################################
  # IMAP extensions, by RFC:

  # RFC 2971: ID response
  generate_tests_from fixture_file: "id_responses.yml"

  # RFC 4314: ACL response (TODO: LISTRIGHTS and MYRIGHTS responses)
  generate_tests_from fixture_file: "acl_responses.yml"

  # RFC 4315: UIDPLUS extension, APPENDUID and COPYUID response codes
  generate_tests_from fixture_file: "uidplus_extension.yml"

  # RFC 5256: THREAD response
  generate_tests_from fixture_file: "thread_responses.yml"

  # RFC 7162: CONDSTORE and QRESYNC responses
  generate_tests_from fixture_file: "rfc7162_condstore_qresync_responses.yml"

  # RFC 8474: OBJECTID responses
  generate_tests_from fixture_file: "rfc8474_objectid_responses.yml"

  # RFC 9208: QUOTA extension
  generate_tests_from fixture_file: "rfc9208_quota_responses.yml"

  # RFC 9394: PARTIAL extension
  generate_tests_from fixture_file: "rfc9394_partial.yml"

  # RFC 9586: UIDONLY extension
  generate_tests_from fixture_file: "rfc9586_uidonly_responses.yml"

  ############################################################################
  # Workarounds or unspecified extensions:
  generate_tests_from fixture_file: "quirky_behaviors.yml"

  ############################################################################
  # More interesting tests about the behavior, either of the test or of the
  # response data, should still use normal tests, below
  ############################################################################

  test "default config inherits from Config.global" do
    parser = Net::IMAP::ResponseParser.new
    refute parser.config.frozen?
    refute_equal Net::IMAP::Config.global, parser.config
    assert_same  Net::IMAP::Config.global, parser.config.parent
  end

  test "config can be passed in to #initialize" do
    config = Net::IMAP::Config.global.new
    parser = Net::IMAP::ResponseParser.new config: config
    assert_same config, parser.config
  end

  test "passing in global config inherits from Config.global" do
    parser = Net::IMAP::ResponseParser.new config: Net::IMAP::Config.global
    refute parser.config.frozen?
    refute_equal Net::IMAP::Config.global, parser.config
    assert_same  Net::IMAP::Config.global, parser.config.parent
  end

  test "config will inherits from passed in frozen config" do
    parser = Net::IMAP::ResponseParser.new config: {debug: true}
    refute_equal Net::IMAP::Config.global, parser.config.parent
    refute parser.config.frozen?

    assert parser.config.parent.frozen?
    assert parser.config.debug?
    assert parser.config.inherited?(:debug)

    config = Net::IMAP::Config[debug: true]
    parser = Net::IMAP::ResponseParser.new(config:)
    refute_equal Net::IMAP::Config.global, parser.config.parent
    assert_same  config, parser.config.parent
  end

  # Strangly, there are no example responses for BINARY[section] in either
  # RFC3516 or RFC9051!  The closest I found was RFC5259, and those examples
  # aren't FETCH responses.
  def test_fetch_binary_and_binary_size
    debug, Net::IMAP.debug = Net::IMAP.debug, true
    png      = File.binread(File.join(TEST_FIXTURE_PATH, "ruby.png"))
    size     = png.bytesize
    parser   = Net::IMAP::ResponseParser.new
    # with literal8
    response = "* 1 FETCH (UID 5 BINARY[3.2] ~{%d}\r\n%s)\r\n".b % [size, png]
    parsed   = parser.parse response
    assert_equal png,              parsed.data.attr["BINARY[3.2]"]
    assert_equal png,              parsed.data.binary(3, 2)
    assert_equal png.bytesize,     parsed.data.attr["BINARY[3.2]"].bytesize
    assert_equal Encoding::BINARY, parsed.data.attr["BINARY[3.2]"].encoding
    # binary.size and partial
    partial  = png[0, 32]
    response = "* 1 FETCH (BINARY.SIZE[5] %d BINARY[5]<0> ~{32}\r\n%s)\r\n".b %
      [png.bytesize, partial]
    parsed   = parser.parse response
    assert_equal png.bytesize, parsed.data.attr["BINARY.SIZE[5]"]
    assert_equal png.bytesize, parsed.data.binary_size(5)
    assert_equal 32,           parsed.data.attr["BINARY[5]<0>"].bytesize
    assert_equal partial,      parsed.data.attr["BINARY[5]<0>"]
    assert_equal partial,      parsed.data.binary(5, offset: 0)
    # test every type of value
    literal8 = "\x00 to \xff\r\n".b * 8
    literal  = "\x01 to \xff\r\n".b * 8
    quoted   = "\x01 to \x7f\b\t".b * 8
    response = "* 1 FETCH (" \
               "BINARY[1] ~{%d}\r\n%s " \
               "BINARY[2] {%d}\r\n%s " \
               "BINARY[3] \"%s\" " \
               "BINARY[4] NIL)\r\n".b % [
                 literal8.bytesize, literal8, literal.bytesize, literal, quoted
               ]
    parsed   = parser.parse response
    assert_equal literal8, parsed.data.attr["BINARY[1]"]
    assert_equal literal8, parsed.data.binary(1)
    assert_equal literal,  parsed.data.attr["BINARY[2]"]
    assert_equal literal,  parsed.data.binary(2)
    assert_equal quoted,   parsed.data.attr["BINARY[3]"]
    assert_equal quoted,   parsed.data.binary(3)
    assert_nil             parsed.data.attr["BINARY[4]"]
    assert_nil             parsed.data.binary(4)
  ensure
    Net::IMAP.debug = debug
  end

  test "APPENDUID with '*'" do
    parser = Net::IMAP::ResponseParser.new
    assert_raise_with_message Net::IMAP::ResponseParseError, /uid-set cannot contain '\*'/ do
      parser.parse(
        "A004 OK [appendUID 1 1:*] Done\r\n"
      )
    end
  end

  def assert_deprecated_appenduid_data_warning
    assert_warn(/#{__FILE__}.*warning.*parser_use_deprecated_uidplus_data is ignored/) do
      result = yield
      assert_instance_of Net::IMAP::AppendUIDData, result.data.code.data
      result
    end
  end

  test "APPENDUID with parser_use_deprecated_uidplus_data = true" do
    parser = Net::IMAP::ResponseParser.new(config: {
      parser_use_deprecated_uidplus_data:      true,
      parser_max_deprecated_uidplus_data_size: 10_000,
    })
    assert_deprecated_appenduid_data_warning do
      parser.parse(
        "A004 OK [APPENDUID 1 10000:20000,1] Done\r\n"
      )
    end
    response = assert_deprecated_appenduid_data_warning do
      parser.parse("A004 OK [APPENDUID 1 100:200] Done\r\n")
    end
    uidplus  = response.data.code.data
    assert_equal 101, uidplus.assigned_uids.size
    parser.config.parser_max_deprecated_uidplus_data_size = 100
    assert_deprecated_appenduid_data_warning do
      parser.parse(
        "A004 OK [APPENDUID 1 100:200] Done\r\n"
      )
    end
    response = assert_deprecated_appenduid_data_warning do
      parser.parse("A004 OK [APPENDUID 1 101:200] Done\r\n")
    end
    uidplus  = response.data.code.data
    assert_instance_of Net::IMAP::AppendUIDData, uidplus
    assert_equal 100, uidplus.assigned_uids.size
  end

  test "APPENDUID with parser_use_deprecated_uidplus_data = :up_to_max_size" do
    parser = Net::IMAP::ResponseParser.new(config: {
      parser_use_deprecated_uidplus_data:      :up_to_max_size,
      parser_max_deprecated_uidplus_data_size: 100
    })
    response = assert_deprecated_appenduid_data_warning do
      parser.parse("A004 OK [APPENDUID 1 101:200] Done\r\n")
    end
    assert_instance_of Net::IMAP::AppendUIDData, response.data.code.data
    response = assert_deprecated_appenduid_data_warning do
      parser.parse("A004 OK [APPENDUID 1 100:200] Done\r\n")
    end
    assert_instance_of Net::IMAP::AppendUIDData, response.data.code.data
  end

  test "APPENDUID with parser_use_deprecated_uidplus_data = false" do
    parser = Net::IMAP::ResponseParser.new(config: {
      parser_use_deprecated_uidplus_data:      false,
      parser_max_deprecated_uidplus_data_size: 10_000_000,
    })
    assert_warn("") do
      response = parser.parse("A004 OK [APPENDUID 1 10] Done\r\n")
      assert_instance_of Net::IMAP::AppendUIDData, response.data.code.data
    end
  end

  test "COPYUID with backwards ranges" do
    parser = Net::IMAP::ResponseParser.new
    response = parser.parse(
      "A004 OK [copyUID 9999 20:19,500:495 92:97,101:100] Done\r\n"
    )
    code = response.data.code
    assert_equal(
      {
         19 =>  92,
         20 =>  93,
        495 =>  94,
        496 =>  95,
        497 =>  96,
        498 =>  97,
        499 => 100,
        500 => 101,
      },
      code.data.uid_mapping
    )
  end

  test "COPYUID with '*'" do
    parser = Net::IMAP::ResponseParser.new
    assert_raise_with_message Net::IMAP::ResponseParseError, /uid-set cannot contain '\*'/ do
      parser.parse(
        "A004 OK [copyUID 1 1:* 1:*] Done\r\n"
      )
    end
  end

  def assert_deprecated_copyuid_data_warning(check: true)
    assert_warn(/#{__FILE__}.*warning.*parser_use_deprecated_uidplus_data is ignored/) do
      result = yield
      assert_instance_of Net::IMAP::CopyUIDData, result.data.code.data if check
      result
    end
  end

  test "COPYUID with parser_use_deprecated_uidplus_data = true" do
    parser = Net::IMAP::ResponseParser.new(config: {
      parser_use_deprecated_uidplus_data:      true,
      parser_max_deprecated_uidplus_data_size: 10_000,
    })
    assert_deprecated_copyuid_data_warning(check: false) do
      assert_raise_with_message Net::IMAP::DataFormatError, /mismatched uid-set sizes/ do
        parser.parse(
          "A004 OK [copyUID 1 10000:20000,1 1:10001] Done\r\n"
        )
      end
    end
    response = assert_deprecated_copyuid_data_warning do
      parser.parse("A004 OK [copyUID 1 100:200 1:101] Done\r\n")
    end
    uidplus  = response.data.code.data
    assert_equal 101, uidplus.assigned_uids.size
    assert_equal 101, uidplus.source_uids.size
    parser.config.parser_max_deprecated_uidplus_data_size = 100
    assert_deprecated_copyuid_data_warning do
      parser.parse(
        "A004 OK [copyUID 1 100:200 1:101] Done\r\n"
      )
    end
    response = assert_deprecated_copyuid_data_warning do
      parser.parse("A004 OK [copyUID 1 101:200 1:100] Done\r\n")
    end
    uidplus  = response.data.code.data
    assert_equal 100, uidplus.assigned_uids.size
    assert_equal 100, uidplus.source_uids.size
  end

  test "COPYUID with parser_use_deprecated_uidplus_data = :up_to_max_size" do
    parser = Net::IMAP::ResponseParser.new(config: {
      parser_use_deprecated_uidplus_data:      :up_to_max_size,
      parser_max_deprecated_uidplus_data_size: 100
    })
    assert_deprecated_copyuid_data_warning do
      parser.parse("A004 OK [COPYUID 1 101:200 1:100] Done\r\n")
    end
    assert_deprecated_copyuid_data_warning do
      parser.parse("A004 OK [COPYUID 1 100:200 1:101] Done\r\n")
    end
  end

  test "COPYUID with parser_use_deprecated_uidplus_data = false" do
    parser = Net::IMAP::ResponseParser.new(config: {
      parser_use_deprecated_uidplus_data:      false,
      parser_max_deprecated_uidplus_data_size: 10_000_000,
    })
    response = parser.parse("A004 OK [COPYUID 1 101 1] Done\r\n")
    assert_instance_of Net::IMAP::CopyUIDData, response.data.code.data
  end

  def deeply_nested_bodystructure(depth)
    leaf = '("TEXT" "PLAIN" NIL NIL NIL "7BIT" 1 1)'
    depth.times.reduce(leaf) { |part, _| "(#{part} \"MIXED\")" }
  end

  def deeply_nested_thread(depth)
    depth.times.reduce("(1)") { |thread, _| "(#{thread}(1))" }
  end

  def deeply_nested_extension_value(depth)
    depth.times.reduce("1") { |value, _| "(#{value})" }
  end

  def patch_recursion_entrypoint(parser, method_name)
    return if ENV["TEST_RESPONSE_PARSER_STACK_LEVEL"] == "original"

    parser.define_singleton_method(method_name) do |*args, **kwargs, &block|
      raise SystemStackError, "stack level too deep"
    end
  end

  test "deeply nested BODYSTRUCTURE raises ResponseParseError instead of SystemStackError" do
    parser = Net::IMAP::ResponseParser.new
    patch_recursion_entrypoint(parser, :body)
    response = "* 1 FETCH (BODYSTRUCTURE #{deeply_nested_bodystructure(6000)})\r\n"

    error = assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse(response)
    end

    assert_equal "response recursion too deep", error.message
    assert_instance_of SystemStackError, error.cause
  end

  test "deeply nested THREAD raises ResponseParseError instead of SystemStackError" do
    parser = Net::IMAP::ResponseParser.new
    patch_recursion_entrypoint(parser, :thread_data)
    response = "* THREAD #{deeply_nested_thread(6000)}\r\n"

    error = assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse(response)
    end

    assert_equal "response recursion too deep", error.message
    assert_instance_of SystemStackError, error.cause
  end

  test "deeply nested STATUS extension raises ResponseParseError instead of SystemStackError" do
    parser = Net::IMAP::ResponseParser.new
    patch_recursion_entrypoint(parser, :tagged_ext_val)
    response = "* STATUS INBOX (X #{deeply_nested_extension_value(11_000)})\r\n"

    error = assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse(response)
    end

    assert_equal "response recursion too deep", error.message
    assert_instance_of SystemStackError, error.cause
  end

  test "QUOTA preserves every resource name and value for a quota root" do
    parser = Net::IMAP::ResponseParser.new
    response = parser.parse(
      "* QUOTA \"#user/alice\" (STORAGE 54 111 MESSAGE 42 1000)\r\n")
    quota = response.data
    assert_equal "#user/alice", quota.quota_root
    assert_equal "54", quota.usage
    assert_equal "111", quota.quota
    assert_equal [
      Net::IMAP::QuotaResource.new("STORAGE", "54",  "111"),
      Net::IMAP::QuotaResource.new("MESSAGE", "42", "1000"),
    ], quota.resources
    assert_equal quota.resources.first, quota.storage_resource
    assert_equal "54", quota.storage_usage
    assert_equal "111", quota.storage_limit
  end

  test "QUOTA without STORAGE leaves legacy accessors nil but keeps resources" do
    parser = Net::IMAP::ResponseParser.new
    response = parser.parse("* QUOTA root (MESSAGE 42 1000)\r\n")
    quota = response.data
    assert_nil quota.usage
    assert_nil quota.quota
    assert_nil quota.storage_resource
    assert_equal [Net::IMAP::QuotaResource.new("MESSAGE", "42", "1000")],
                   quota.resources
  end

  test "QUOTA legacy STORAGE accessors are case insensitive" do
    parser = Net::IMAP::ResponseParser.new
    quota = parser.parse("* QUOTA root (storage 7 8)\r\n").data
    assert_equal "7", quota.usage
    assert_equal "8", quota.quota
    assert_equal quota.resources.first, quota.storage_resource
  end

  test "QUOTA with an empty resource list returns an empty resources array" do
    parser = Net::IMAP::ResponseParser.new
    quota = parser.parse("* QUOTA root ()\r\n").data
    assert_equal "root", quota.quota_root
    assert_nil quota.usage
    assert_nil quota.quota
    assert_equal [], quota.resources
  end

  test "QUOTA preserves duplicate and unknown resources in order" do
    parser = Net::IMAP::ResponseParser.new
    response = parser.parse(
      "* QUOTA root (X-UNKNOWN 5 6 STORAGE 1 2 STORAGE 3 4)\r\n")
    quota = response.data
    assert_equal "1", quota.usage
    assert_equal "2", quota.quota
    assert_equal [
      Net::IMAP::QuotaResource.new("X-UNKNOWN", "5", "6"),
      Net::IMAP::QuotaResource.new("STORAGE",   "1", "2"),
      Net::IMAP::QuotaResource.new("STORAGE",   "3", "4"),
    ], quota.resources
  end

  test "QUOTA with a malformed resource triple raises ResponseParseError" do
    parser = Net::IMAP::ResponseParser.new
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA root (STORAGE 1)\r\n")
    end
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA root (STORAGE 1 2 3)\r\n")
    end
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA root (123 1 2)\r\n")
    end
  end

  test "QUOTAROOT followed by multiple QUOTA responses preserves quota roots" do
    parser = Net::IMAP::ResponseParser.new
    quotaroot = parser.parse(
      "* QUOTAROOT INBOX \"#user/alice\" \"!partition/sda4\"\r\n").data
    assert_equal "INBOX", quotaroot.mailbox
    assert_equal ["#user/alice", "!partition/sda4"], quotaroot.quotaroots

    user = parser.parse(
      "* QUOTA \"#user/alice\" (STORAGE 54 111 MESSAGE 42 1000)\r\n").data
    partition = parser.parse(
      "* QUOTA \"!partition/sda4\" (STORAGE 104 10923847)\r\n").data
    assert_equal("#user/alice", user.mailbox)
    assert_equal(2, user.resources.length)
    assert_equal("!partition/sda4", partition.mailbox)
    assert_equal([Net::IMAP::QuotaResource.new("STORAGE", "104", "10923847")],
                   partition.resources)
  end

end
