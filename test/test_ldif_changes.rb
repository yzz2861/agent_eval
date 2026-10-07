# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'
require 'base64'
require 'stringio'

class TestLdifChanges < Test::Unit::TestCase
  # An IO wrapper that only ever returns +block_size+ bytes per #read, used
  # to prove parsing works with arbitrarily small reads (a single byte at a
  # time in some tests).
  class TinyIO
    def initialize(string, block_size)
      @string = string.b
      @block_size = block_size
      @position = 0
    end

    def read(length)
      chunk = @string.byteslice(@position, [length, @block_size].min)
      return nil if chunk.nil? || chunk.empty?

      @position += chunk.bytesize
      chunk
    end
  end

  class FakeLDAP
    attr_reader :calls

    def initialize
      @calls = []
    end

    def add(args)
      @calls << [:add, args]
      true
    end

    def delete(args)
      @calls << [:delete, args]
      true
    end

    def modify(args)
      @calls << [:modify, args]
      true
    end

    def rename(args)
      @calls << [:rename, args]
      true
    end
  end

  # A complete mixed LDIF exercising every feature: base64, binary, an empty
  # value, folded lines, comments, a URL value, a control and interleaved
  # modify/moddn records.
  MIXED_LDIF = <<~'LDIF'.freeze
    version: 1

    # leading comment
    dn: cn=Add User,ou=People,dc=example,dc=com
    control: 1.2.3.4.5 true:: Q09OTkVDVA==
    changetype: add
    objectClass: inetOrgPerson
    cn: Add User
    cn:: QW5vdGhlciBDTg==
    jpegPhoto:: /9j/4EFBQUFBQUFBQUFBQUFBQUFBQQ==
    empty:
    description: folded text with
      two retained spaces here
    labeledURI:< http://example.com/badge

    dn: cn=Modify User,ou=People,dc=example,dc=com
    changetype: modify
    add: mail
    mail: one@example.com
    mail: two@example.com
    -
    replace: title
    title:
    -
    delete: sn
    -
    delete: givenName
    givenName: Old

    dn: cn=Old RDN,ou=People,dc=example,dc=com
    changetype: modrdn
    newrdn: cn=New RDN
    deleteoldrdn: 1
    newsuperior: ou=Managers,dc=example,dc=com

    dn: cn=Delete Me,ou=People,dc=example,dc=com
    changetype: delete
  LDIF

  SAFE_RESOLVER = proc { |url| "resolved-#{url}" }

  def parse(ldif, resolver: SAFE_RESOLVER, **options)
    block_size = options.delete(:block_size) || 1
    options[:url_resolver] = resolver unless resolver.nil?
    Net::LDAP::LDIF::Reader.new(TinyIO.new(ldif, block_size), **options).to_a
  end

  def serialize(records, **options)
    io = StringIO.new
    writer = Net::LDAP::LDIF::Writer.new(io, **options)
    records.each { |record| writer << record }
    io.string
  end

  def test_parses_all_four_change_types
    records = parse(MIXED_LDIF,
                    :url_resolver => proc { |url| "resolved-#{url}" })

    assert_equal %i[add modify moddn delete], records.map { |r| r[:action] }
  end

  def test_add_record_attributes_and_control
    records = parse(MIXED_LDIF,
                    :url_resolver => proc { |url| "resolved-#{url}" })
    add = records.first

    assert_equal "cn=Add User,ou=People,dc=example,dc=com", add[:dn]
    assert_equal ["inetOrgPerson"], add[:attributes]["objectClass"]
    assert_equal ["Add User", "Another CN"], add[:attributes]["cn"]
    assert_equal "", add[:attributes]["empty"].first
    assert_equal "folded text with two retained spaces here",
                 add[:attributes]["description"].first
    assert_equal "resolved-http://example.com/badge",
                 add[:attributes]["labeledURI"].first
    assert_equal "\xFF\xD8\xFF\xE0".b,
                 add[:attributes]["jpegPhoto"].first.byteslice(0, 4)

    control = add[:controls].first
    assert_equal "1.2.3.4.5", control[:oid]
    assert_equal true, control[:criticality]
    assert_equal "CONNECT", control[:value]
  end

  def test_modify_groups_are_ordered
    records = parse(MIXED_LDIF)
    modify = records[1]

    assert_equal [
      [:add, "mail", ["one@example.com", "two@example.com"]],
      [:replace, "title", [""]],
      [:delete, "sn", []],
      [:delete, "givenName", ["Old"]],
    ], modify[:operations]
  end

  def test_moddn_record
    records = parse(MIXED_LDIF)
    moddn = records[2]

    assert_equal :moddn, moddn[:action]
    assert_equal "cn=Old RDN,ou=People,dc=example,dc=com", moddn[:dn]
    assert_equal "cn=New RDN", moddn[:newrdn]
    assert_equal true, moddn[:delete_old_rdn]
    assert_equal "ou=Managers,dc=example,dc=com", moddn[:new_superior]
  end

  def test_moddn_keyword_alias
    ldif = "dn: cn=a\nchangetype: moddn\nnewrdn: cn=b\ndeleteoldrdn: 0\n\n"
    record = parse(ldif).first
    assert_equal :moddn, record[:action]
    assert_equal false, record[:delete_old_rdn]
  end

  def test_delete_record
    records = parse(MIXED_LDIF)
    assert_equal :delete, records.last[:action]
    assert_equal "cn=Delete Me,ou=People,dc=example,dc=com", records.last[:dn]
  end

  def test_url_requires_explicit_resolver
    ldif = "dn: cn=a\nchangetype: add\nlabeledURI:< http://example.com/x\n\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) do
      parse(ldif, :resolver => nil)
    end
    assert_match(/url_resolver/, error.message)
    assert_equal 1, error.record
    assert_equal 3, error.line
  end

  def test_url_is_not_resolved_before_record_completes
    resolved = []
    resolver = proc { |url| resolved << url; "v" }
    ldif = "dn: cn=a\nchangetype: add\nx:< http://example.com/x\nBOGUS"

    assert_raise(Net::LDAP::LDIF::ParseError) do
      parse(ldif, :resolver => resolver)
    end
    assert_empty resolved
  end

  def test_parse_error_reports_record_and_line
    ldif = "dn: cn=a\nchangetype: bogus\n\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
    assert_equal 1, error.record
    assert_equal 2, error.line
    assert_match(/unsupported changetype/, error.message)
  end

  def test_dash_outside_modify_is_an_error
    ldif = "dn: cn=a\nchangetype: add\n-\n\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
    assert_equal 1, error.record
    assert_equal 3, error.line
  end

  def test_malformed_base64_is_an_error
    ldif = "dn: cn=a\nchangetype: add\nx:: !!!not base64!!!\n\n"
    assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
  end

  def test_roundtrip_from_tiny_io_chunks
    records = parse(MIXED_LDIF,
                    :url_resolver => proc { |url| "resolved-#{url}" })
    serialized = serialize(records)

    reparsed = parse(serialized,
                     :url_resolver => proc { |url| "resolved-#{url}" })
    assert_equal records, reparsed
  end

  def test_writer_base64_encodes_dangerous_values
    records = [{
      :action => :add,
      :dn => " cn=leadingspace,dc=example,dc=com",
      :attributes => {
        "binary" => "\x00\x01\xFE".b,
        "leadingColon" => ":value",
        "leadingSpace" => " value",
        "trailingSpace" => "value ",
        "unicode" => "caf\u00E9",
      },
      :controls => [],
    }]
    output = serialize(records)

    unfolded = output.gsub(/\n[ ]+/, "")
    assert_include unfolded, "binary:: AAH+"
    assert_match(/leadingColon:: OnZhbHVl/, output)
    assert_match(/leadingSpace:: IHZhbHVl/, output)
    assert_match(/trailingSpace:: dmFsdWUg/, output)
    assert_match(/unicode: caf\u00E9/, output)
    assert_match(/dn:: IGNuPWxlYWRpbmdzcGFjZSxkYz1leGFtcGxlLGRjPWNvbQ==/, output)
  end

  def test_writer_folds_long_lines_at_78_bytes
    records = [{
      :action => :add,
      :dn => "cn=x",
      :attributes => { "k" => "a" * 200 },
    }]
    output = serialize(records)

    output.lines.each do |line|
      assert_operator line.chomp.bytesize, :<=, 78
    end
    assert_equal "k: " + ("a" * 75),
                 output.lines.find { |line| line.start_with?("k: ") }.chomp
    assert_equal "a" * 200, parse(output).first[:attributes]["k"].first
  end

  def test_writer_never_splits_a_multibyte_character
    snowman = "\u2603" # 3 bytes in UTF-8
    records = [{
      :action => :add,
      :dn => "cn=x",
      :attributes => { "k" => snowman * 40 },
    }]
    output = serialize(records)
    reparsed = parse(output).first[:attributes]["k"].first
    assert_equal snowman * 40, reparsed
    output.lines.each do |line|
      assert_operator line.chomp.bytesize, :<=, 78
      assert_predicate line.chomp, :valid_encoding?
    end
  end

  def test_apply_dispatches_all_operations
    ldap = FakeLDAP.new
    records = parse(MIXED_LDIF,
                    :url_resolver => proc { |url| "resolved-#{url}" })
    records.each { |record| Net::LDAP::LDIF.apply_record(record, ldap) }

    actions = ldap.calls.map(&:first)
    assert_equal %i[add modify rename delete], actions

    modify_args = ldap.calls[1][1]
    assert_equal [
      [:add, "mail", ["one@example.com", "two@example.com"]],
      [:replace, "title", nil],
      [:delete, "sn", nil],
      [:delete, "givenName", ["Old"]],
    ], modify_args[:operations]

    rename_args = ldap.calls[2][1]
    assert_equal "cn=New RDN", rename_args[:newrdn]
    assert_equal true, rename_args[:delete_attributes]
    assert_equal "ou=Managers,dc=example,dc=com", rename_args[:new_superior]
  end

  def test_streaming_apply_does_not_load_whole_file
    ldap = FakeLDAP.new
    io = TinyIO.new(MIXED_LDIF, 3)
    results = Net::LDAP::LDIF.apply(
      io, ldap, :url_resolver => proc { |url| "resolved-#{url}" }
    )
    assert_equal 4, results.size
    assert_equal 4, ldap.calls.size
  end

  def test_connection_rename_accepts_ber_controls
    result = make_modifyrdn_response
    mock = flexmock("socket")
    mock.should_receive(:read_ber).and_return(result)
    mock.should_receive(:write)
    conn = Net::LDAP::Connection.new(:socket => mock)
    record = {
      :action => :moddn,
      :dn => "cn=old",
      :newrdn => "cn=new",
      :delete_old_rdn => true,
      :controls => [{ :oid => "1.2.3", :criticality => true }],
    }
    assert Net::LDAP::LDIF.apply_record(record, conn)
  end

  def make_modifyrdn_response
    ber = Net::BER::BerIdentifiedArray.new([Net::LDAP::ResultCodeSuccess, "", ""])
    ber.ber_identifier = Net::LDAP::PDU::ModifyRDNResponse
    [1, ber]
  end

  def test_empty_value_roundtrips_in_add_and_modify
    records = [{
      :action => :add,
      :dn => "cn=empty",
      :attributes => { "a" => "" },
    }, {
      :action => :modify,
      :dn => "cn=empty",
      :operations => [[:replace, "a", [""]], [:delete, "b", []]],
    }]
    output = serialize(records)
    assert_match(/^a:$/, output)

    reparsed = parse(output)
    assert_equal "", reparsed[0][:attributes]["a"].first
    assert_equal [[:replace, "a", [""]], [:delete, "b", []]],
                 reparsed[1][:operations]
  end

  def test_content_record_without_changetype_is_add
    ldif = "dn: cn=a\ncn: a\n\n"
    record = parse(ldif).first
    assert_equal :add, record[:action]
    assert_equal ["a"], record[:attributes]["cn"]
  end

  def test_crlf_and_cr_line_endings
    ldif = "dn: cn=a\r\nchangetype: delete\r\n\r\n"
    assert_equal :delete, parse(ldif).first[:action]

    ldif = "dn: cn=a\rchangetype: delete\r\r"
    assert_equal :delete, parse(ldif).first[:action]
  end

  def test_crlf_split_across_one_byte_reads
    # The \r and \n of every separator arrive in separate reads.
    ldif = "dn: cn=a\r\nchangetype: delete\r\n\r\n"
    reader = Net::LDAP::LDIF::Reader.new(TinyIO.new(ldif, 1))
    record = reader.to_a.first
    assert_equal :delete, record[:action]
    assert_equal "cn=a", record[:dn]
  end

  def test_comments_and_blank_lines_between_records
    ldif = "# one\n\ndn: cn=a\n# inside header\nchangetype: delete\n\n# two\n"
    assert_equal 1, parse(ldif).size
  end
  def test_complete_records_are_processed_when_a_later_record_is_bad
    good = "dn: cn=good\nchangetype: delete\n\n"
    bad = "dn: cn=bad\nchangetype: nope\n\n"
    seen = []
    reader = Net::LDAP::LDIF::Reader.new(StringIO.new(good + bad))
    assert_raise(Net::LDAP::LDIF::ParseError) do
      reader.each { |record| seen << record[:dn] }
    end
    assert_equal ["cn=good"], seen
  end

  def test_version_after_first_record_is_an_error
    ldif = "dn: cn=a\nchangetype: delete\n\nversion: 1\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
    assert_equal 0, error.record
    assert_equal 4, error.line
  end

  def test_reader_enumerator_is_lazy
    ldif = "dn: cn=a\nchangetype: delete\n\ndn: cn=b\nchangetype: delete\n\n"
    enum = Net::LDAP::LDIF::Reader.new(StringIO.new(ldif)).each
    assert_kind_of Enumerator, enum
    assert_equal "cn=a", enum.next[:dn]
    assert_equal "cn=b", enum.next[:dn]
    assert_raise(StopIteration) { enum.next }
  end

  def test_apply_record_encodes_control_for_add
    ldap = FakeLDAP.new
    control_value = [0x04, 0x01, 0x02].pack("C3")
    record = {
      :action => :add,
      :dn => "cn=a",
      :attributes => { "cn" => "a" },
      :controls => [{ :oid => "1.2.3", :criticality => true, :value => control_value }],
    }
    Net::LDAP::LDIF.apply_record(record, ldap)
    args = ldap.calls.first[1]
    assert_kind_of Array, args[:controls]
    assert_kind_of String, args[:controls].first
    assert_include args[:controls].first, "1.2.3"
  end

  def test_writer_emits_moddn_alias_keyword
    record = { :action => :moddn, :dn => "cn=a", :newrdn => "cn=b",
               :delete_old_rdn => false }
    io = StringIO.new
    Net::LDAP::LDIF::Writer.new(io, :moddn_keyword => "moddn") << record
    assert_match(/changetype: moddn/, io.string)
  end

  def test_control_after_changetype_is_accepted
    ldif = "dn: cn=a\nchangetype: delete\ncontrol: 1.2.3 false\n\n"
    record = parse(ldif).first
    assert_equal "1.2.3", record[:controls].first[:oid]
    assert_equal false, record[:controls].first[:criticality]
  end

  def test_control_after_attributes_is_an_error
    ldif = "dn: cn=a\nchangetype: add\ncn: a\ncontrol: 1.2.3\n\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
    assert_match(/control/, error.message)
  end

  def test_moddn_missing_newrdn_is_an_error
    ldif = "dn: cn=a\nchangetype: modrdn\ndeleteoldrdn: 1\n\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
    assert_match(/newrdn/, error.message)
  end

  def test_modify_with_no_modifications_is_an_error
    ldif = "dn: cn=a\nchangetype: modify\n\n"
    error = assert_raise(Net::LDAP::LDIF::ParseError) { parse(ldif) }
    assert_match(/no modifications/, error.message)
  end

  def test_binary_and_empty_and_controls_roundtrip_with_one_byte_io
    records = [{
      :action => :add,
      :dn => "cn=binary",
      :attributes => {
        "photo" => (0..255).map(&:chr).join.b,
        "note" => "",
        "utf8" => "\u2603 snowman",
      },
      :controls => [],
    }]
    io = StringIO.new
    serialize_to = Net::LDAP::LDIF::Writer.new(io)
    records.each { |record| serialize_to << record }
    serialized = io.string

    reparsed = Net::LDAP::LDIF::Reader.new(TinyIO.new(serialized, 1)).to_a
    assert_equal (0..255).map(&:chr).join.b, reparsed[0][:attributes]["photo"].first
    assert_equal "", reparsed[0][:attributes]["note"].first
    assert_equal "\u2603 snowman", reparsed[0][:attributes]["utf8"].first
  end
end
