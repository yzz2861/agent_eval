# -*- ruby encoding: utf-8 -*-
require_relative "test_helper"
require "stringio"

class TestLdifChanges < Test::Unit::TestCase
  def parse(ldif, resolver: nil, block_size: 1)
    Net::LDAP::LDIF.read(StringIO.new(ldif.b),
                        resolver: resolver,
                        block_size: block_size)
  end

  def serialize(changes, **options)
    Net::LDAP::LDIF.generate(changes, **options)
  end

  def normalize(changes)
    changes.map do |change|
      base = { :type => change.changetype, :dn => change.dn.b }
      case change
      when Net::LDAP::LDIF::AddChange
        base[:attributes] = change.attributes.transform_values do |values|
          values.map(&:b)
        end
      when Net::LDAP::LDIF::ModifyChange
        base[:operations] = change.operations.map do |action, attr, values|
          [action, attr.to_s, values.nil? ? nil : values.map(&:b)]
        end
      when Net::LDAP::LDIF::ModifyDNChange
        base[:newrdn] = change.newrdn.b
        base[:deleteoldrdn] = change.delete_old_rdn?
        base[:newsuperior] = change.new_superior && change.new_superior.b
      end
      unless change.controls.empty?
        base[:controls] = change.controls.map do |control|
          [control.oid, control.criticality, control.value && control.value.b]
        end
      end
      base
    end
  end

  def test_parses_add_with_binary_and_empty_values
    binary = "\x00\x01\xff\xfe".b
    ldif = <<~LDIF
      dn: cn=binary,dc=example,dc=com
      changetype: add
      cn: bob
      jpegPhoto:: #{Base64.strict_encode64(binary)}
      empty::
      trailing: ends with space
    LDIF
    ldif = ldif.sub("trailing: ends with space\n",
                    "trailing: ends with space \n")

    record = parse(ldif).first
    assert_instance_of Net::LDAP::LDIF::AddChange, record
    assert_equal binary, record.attributes[:jpegphoto].first
    assert_equal "", record.attributes[:empty].first
    assert_equal "ends with space ".b, record.attributes[:trailing].first
  end

  def test_parses_delete
    record = parse("dn: cn=gone,dc=example,dc=com\nchangetype: delete\n\n").first
    assert_instance_of Net::LDAP::LDIF::DeleteChange, record
    assert_equal "cn=gone,dc=example,dc=com", record.dn
  end

  def test_parses_modify_with_ordered_dash_separated_groups
    ldif = <<~LDIF
      dn: cn=mod,dc=example,dc=com
      changetype: modify
      add: mail
      mail: a@example.com
      mail: b@example.com
      -
      delete: sn
      -
      replace: cn
      cn: mod
      -
      delete: title
      title: old title
    LDIF

    operations = parse(ldif).first.operations
    expected = [
      [:add, :mail, ["a@example.com", "b@example.com"]],
      [:delete, :sn, nil],
      [:replace, :cn, ["mod"]],
      [:delete, :title, ["old title"]],
    ]
    assert_equal expected, operations
  end

  def test_parses_moddn
    ldif = <<~LDIF
      dn: cn=old,ou=people,dc=example,dc=com
      changetype: moddn
      newrdn: cn=new
      deleteoldrdn: 0
      newsuperior: ou=others,dc=example,dc=com
    LDIF

    record = parse(ldif).first
    assert_instance_of Net::LDAP::LDIF::ModifyDNChange, record
    assert_equal "cn=new", record.newrdn
    assert_equal false, record.delete_old_rdn?
    assert_equal "ou=others,dc=example,dc=com", record.new_superior
    assert_equal({
      :olddn => "cn=old,ou=people,dc=example,dc=com",
      :newrdn => "cn=new",
      :delete_attributes => false,
      :new_superior => "ou=others,dc=example,dc=com",
    }, record.to_args)
  end

  def test_modrdn_is_accepted_as_changetype
    ldif = "dn: cn=a\nchangetype: modrdn\nnewrdn: cn=b\ndeleteoldrdn: 1\n\n"
    record = parse(ldif).first
    assert_instance_of Net::LDAP::LDIF::ModifyDNChange, record
    assert_equal true, record.delete_old_rdn?
  end

  def test_changetype_is_case_insensitive
    { "add" => Net::LDAP::LDIF::AddChange,
      "delete" => Net::LDAP::LDIF::DeleteChange,
      "moddn" => Net::LDAP::LDIF::ModifyDNChange,
      "MODRDN" => Net::LDAP::LDIF::ModifyDNChange }.each do |type, klass|
      body = case klass.name.split("::").last
             when "DeleteChange" then ""
             when "ModifyDNChange" then "newrdn: cn=b\ndeleteoldrdn: 0\n"
             else "cn: a\n"
             end
      ldif = "dn: cn=a\nchangetype: #{type}\n#{body}"
      assert_instance_of klass, parse(ldif).first
    end
  end

  def test_modify_and_moddn_mix_roundtrip
    binary = (0..255).map(&:chr).join.b
    changes = [
      Net::LDAP::LDIF::AddChange.new("cn=mix,dc=example,dc=com", {
        :objectclass => ["top"],
        :photo => [binary],
        :blank => [""],
      }),
      Net::LDAP::LDIF::ModifyChange.new("cn=mix,dc=example,dc=com", [
        [:replace, :mail, ["mix@example.com", ""]],
        [:delete, :seealso, nil],
        [:add, :cn, ["mix", "mix2"]],
      ]),
      Net::LDAP::LDIF::ModifyDNChange.new(
        "cn=mix,dc=example,dc=com", "cn=moved", true,
        "ou=people,dc=example,dc=com"
      ),
      Net::LDAP::LDIF::DeleteChange.new("cn=old,dc=example,dc=com"),
    ]

    ldif = serialize(changes)
    reparsed = parse(ldif, block_size: 1)
    assert_equal normalize(changes), normalize(reparsed)
  end

  def test_folding_keeps_physical_lines_within_column_width
    value = ("abcdefgh" * 40).b
    change = Net::LDAP::LDIF::AddChange.new("cn=long", { :data => [value] })
    ldif = serialize([change], fold_column: 76)

    assert(ldif.lines.all? { |line| line.chomp.bytesize <= 76 })
    assert(ldif.lines.any? { |line| line.start_with?(" ") })
    assert_equal value, parse(ldif, block_size: 3).first.attributes[:data].first
  end

  def test_continuation_and_base64_split_across_lines
    full = Base64.strict_encode64("cn=continues,dc=example,dc=com")
    split = full.length / 2
    ldif = "dn:: #{full[0, split]}\r\n #{full[split..-1]}\r\n" \
           "changetype: add\r\n" \
           "description: folded \r\n value\r\n\r\n"
    record = parse(ldif, block_size: 2).first
    assert_equal "cn=continues,dc=example,dc=com", record.dn
    assert_equal "folded value".b, record.attributes[:description].first
  end

  def test_comments_and_version_are_ignored
    ldif = <<~LDIF
      version: 1

      # leading comment
      dn: cn=c,dc=example,dc=com
      # inside comment
      changetype: delete

      # trailing comment
    LDIF
    records = parse(ldif)
    assert_equal 1, records.length
    assert_instance_of Net::LDAP::LDIF::DeleteChange, records.first
  end

  def test_record_level_controls
    binary = "\x00v".b
    ldif = <<~LDIF
      dn: cn=ctrl,dc=example,dc=com
      control: 1.2.840.113556.1.4.805 true
      control: 9.9.9 false:: #{Base64.strict_encode64(binary)}
      changetype: delete
    LDIF
    record = parse(ldif).first
    assert_equal ["1.2.840.113556.1.4.805", true, nil],
                 record.controls.first.to_a
    assert_equal ["9.9.9", false, binary], record.controls.last.to_a

    reparsed = parse(serialize([record])).first
    assert_equal record.controls.map(&:to_a), reparsed.controls.map(&:to_a)
  end

  def test_url_uses_explicit_resolver_and_none_by_default
    seen = []
    resolver = ->(url) { seen << url; "from-resolver" }
    ldif = "dn: cn=u\nchangetype: add\nphoto:<file:///tmp/pic.jpg\n\n"

    record = parse(ldif, resolver: resolver).first
    assert_equal ["file:///tmp/pic.jpg"], seen
    assert_equal "from-resolver", record.attributes[:photo].first

    error = assert_raise(Net::LDAP::LDIF::LdifError) { parse(ldif) }
    assert_equal 1, error.record_number
    assert_equal 3, error.line_number
    assert_match(/resolver/, error.message)
  end

  def test_parse_errors_report_record_and_line
    ldif = "dn: cn=a\nchangetype: add\n\n" \
           "dn: cn=b\nchangetype: modify\nbogus: x\n\n"
    error = assert_raise(Net::LDAP::LDIF::LdifError) { parse(ldif) }
    assert_equal 2, error.record_number
    assert_equal 6, error.line_number
  end

  def test_missing_modify_separator_is_an_error
    ldif = <<~LDIF
      dn: cn=b,dc=example,dc=com
      changetype: modify
      add: mail
      mail: a@example.com
      replace: cn
      cn: b
    LDIF
    error = assert_raise(Net::LDAP::LDIF::LdifError) { parse(ldif) }
    assert_match(/separator/, error.message)
  end

  def test_record_is_not_yielded_before_terminator_read
    events = []
    source = "dn: cn=s,dc=example,dc=com\nchangetype: delete\n\n"
    io = RecordingIO.new(source, events)
    Net::LDAP::LDIF::Reader.new(io, block_size: source.bytesize).each do |record|
      events << [:yielded, record.dn]
    end
    # The whole record (blank terminator included) is read before yield.
    terminator_index = events.index { |event, _chunk| event == :read }
    yielded_index = events.index { |event| event[0] == :yielded }
    assert !terminator_index.nil?
    assert !yielded_index.nil?
    assert terminator_index < yielded_index
  end

  def test_writer_does_not_emit_url_or_plain_for_dangerous_values
    change = Net::LDAP::LDIF::AddChange.new("cn=d", {
      :colon => [":weird"],
      :angle => ["<url-ish"],
      :space => [" lead"],
      :ascii => ["normal 123"],
    })
    ldif = serialize([change])
    assert_match(/^colon:: /, ldif)
    assert_match(/^angle:: /, ldif)
    assert_match(/^space:: /, ldif)
    assert_match(/^ascii: normal 123$/, ldif)
  end

  def test_content_record_without_changetype_parses_as_add
    record = parse("dn: cn=e,dc=example,dc=com\nobjectClass: top\ncn: e\n").first
    assert_instance_of Net::LDAP::LDIF::AddChange, record
    assert_equal ["top"], record.attributes[:objectclass]
  end

  def test_handles_io_that_returns_one_record_per_read
    chunks = [
      "dn: cn=lazy,dc=example,dc=com\nchangetype: delete\n\n",
      "dn: cn=later,dc=example,dc=com\nchangetype: delete\n\n",
    ]
    io = Object.new
    index = 0
    io.define_singleton_method(:read) do |_size|
      chunk = chunks[index]
      index += 1
      chunk
    end

    enumerator = Net::LDAP::LDIF::Reader.new(io, block_size: 4096).each
    first = enumerator.next
    assert_equal "cn=lazy,dc=example,dc=com", first.dn
    second = enumerator.next
    assert_equal "cn=later,dc=example,dc=com", second.dn
  end

  def test_records_are_yielded_incrementally_from_tiny_blocks
    ldif = "dn: cn=one\nchangetype: delete\n\n" \
           "dn: cn=two\nchangetype: delete\n\n"
    dns = []
    Net::LDAP::LDIF.foreach(StringIO.new(ldif.b), block_size: 1) do |change|
      dns << change.dn
    end
    assert_equal ["cn=one", "cn=two"], dns
  end

  # IO that records every read so tests can observe streaming order.
  class RecordingIO
    def initialize(content, events)
      @content = content.b
      @events = events
      @offset = 0
    end

    def read(size)
      chunk = @content.byteslice(@offset, size)
      return nil if chunk.nil? || chunk.empty?

      @offset += chunk.bytesize
      @events << [:read, chunk]
      chunk
    end
  end
end
