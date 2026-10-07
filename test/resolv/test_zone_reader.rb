# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'stringio'

class TestResolvDNSZoneReader < Test::Unit::TestCase
  def test_directives_owner_continuation_and_relative_names
    zone = <<~ZONE
      ; leading comment
      $ORIGIN example.org.
      $TTL 1h
      @ IN SOA ns.example. hostmaster (2026010100 1h 15m 1w 300) ; comment
      www 60 IN A 192.0.2.1
        IN AAAA 2001:db8::1
      mail IN MX 10 mail
      host IN (
        IN TXT "one"
      )
    ZONE

    records = Resolv::DNS::ZoneReader.new(zone).to_a

    assert_equal('example.org', records[0][0].to_s)
    assert_equal(3600, records[0][1])
    assert_kind_of(Resolv::DNS::Resource::SOA, records[0][2])
    assert_equal('ns.example', records[0][2].mname.to_s)
    assert_equal('hostmaster.example.org', records[0][2].rname.to_s)
    assert_equal(2026010100, records[0][2].serial)
    assert_equal(['www.example.org', 60, Resolv::IPv4],
                 [records[1][0].to_s, records[1][1], records[1][2].address.class])
    assert_equal(60, records[1][2].ttl)
    assert_equal('www.example.org', records[2][0].to_s)
    assert_kind_of(Resolv::DNS::Resource::IN::AAAA, records[2][2])
    assert_equal('mail.example.org', records[3][2].exchange.to_s)
    assert_equal(10, records[3][2].preference)
    assert_equal('host.example.org', records[4][0].to_s)
    assert_equal(['one'], records[4][2].strings)
  end

  def test_txt_escapes
    zone = <<~ZONE
      $ORIGIN example.org.
      $TTL 30
      txt IN TXT "a\\\"b\\;c" "d\\066e" plain\\;text
    ZONE

    _name, _ttl, resource = Resolv::DNS::ZoneReader.new(zone).first

    assert_equal(['a"b;c', 'dBe', 'plain;text'], resource.strings)
  end

  def test_rfc_3597_unknown_record
    zone = <<~ZONE
      $TTL 60
      unknown.example. TYPE40000 CLASS60000 \\# 3 010203
    ZONE

    _name, _ttl, resource = Resolv::DNS::ZoneReader.new(zone).first

    assert_equal(40000, resource.class::TypeValue)
    assert_equal(60000, resource.class::ClassValue)
    assert_equal([1, 2, 3].pack('C3'), resource.data)
  end

  def test_include_scope_is_isolated
    parent = <<~ZONE
      $ORIGIN example.org.
      $TTL 10
      parent IN A 192.0.2.1
      $INCLUDE child.zone sub.example.org.
        IN A 192.0.2.3
    ZONE
    included = []
    resolver = lambda do |name, origin, ttl|
      included << [name, origin, ttl]
      child = <<~CHILD
        child IN A 192.0.2.2
        $ORIGIN leaked.example.
        $TTL 99
      CHILD
      [child, 'child.zone']
    end

    records = Resolv::DNS::ZoneReader.new(parent, file: 'parent.zone', resolver: resolver).to_a

    assert_equal(['child.zone', Resolv::DNS::Name, 10],
                 [included[0][0], included[0][1].class, included[0][2]])
    assert_equal('sub.example.org', included[0][1].to_s)
    assert_equal('child.sub.example.org', records[1][0].to_s)
    assert_equal('parent.example.org', records[2][0].to_s)
    assert_equal(10, records[2][1])
  end

  def test_include_cycle
    resolver = lambda do |name|
      child = name == 'a.zone' ? '$INCLUDE b.zone' : '$INCLUDE a.zone'
      [child, name]
    end

    error = assert_raise(Resolv::DNS::ZoneReader::ParseError) do
      Resolv::DNS::ZoneReader.new("$TTL 1\n$INCLUDE a.zone\n", resolver: resolver).to_a
    end

    assert_match(/cycle/, error.message)
    assert_equal('b.zone', error.file)
    assert_equal(1, error.line)
    assert_equal('$INCLUDE a.zone', error.record)
  end

  def test_include_requires_injected_resolver_and_reports_position
    zone = "$ORIGIN example.org.\n$INCLUDE secret.zone\n"

    error = assert_raise(Resolv::DNS::ZoneReader::ParseError) do
      Resolv::DNS::ZoneReader.new(zone, file: 'zone.db').to_a
    end

    assert_equal('zone.db', error.file)
    assert_equal(2, error.line)
    assert_equal(10, error.column)
    assert_equal('$INCLUDE secret.zone', error.record)
    assert_match(/resolver/, error.message)
  end

  def test_parse_error_identifies_record
    zone = "$ORIGIN example.org.\n$TTL 1\nbad IN A not-an-address\n"

    error = assert_raise(Resolv::DNS::ZoneReader::ParseError) do
      Resolv::DNS::ZoneReader.new(zone, file: 'zone.db').to_a
    end

    assert_equal('zone.db', error.file)
    assert_equal(3, error.line)
    assert_equal(8, error.column)
    assert_equal('bad IN A not-an-address', error.record)
  end

  def test_io_source
    source = StringIO.new("$ORIGIN example.\n$TTL 2\nwww IN A 192.0.2.4\n")
    name, ttl, resource = Resolv::DNS::ZoneReader.new(source).first

    assert_equal('www.example', name.to_s)
    assert_equal(2, ttl)
    assert_equal('192.0.2.4', resource.address.to_s)
  end
end
