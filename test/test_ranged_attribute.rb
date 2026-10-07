# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestRangedAttributeName < Test::Unit::TestCase
  def test_parse_separates_name_options_and_range
    parsed = Net::LDAP::RangedAttributeName.parse("member;binary;range=10-19")
    assert_equal "member", parsed.name
    assert_equal ["binary"], parsed.options
    assert parsed.ranged?
    refute parsed.final?
    assert_equal 10, parsed.range_start
    assert_equal 19, parsed.range_end
  end

  def test_parse_end_marker
    parsed = Net::LDAP::RangedAttributeName.parse("member;range=20-*")
    assert parsed.ranged?
    assert parsed.final?
    assert_equal 20, parsed.range_start
    assert_nil parsed.range_end
  end

  def test_parse_case_insensitive_range_option
    parsed = Net::LDAP::RangedAttributeName.parse("Member;Range=0-4")
    assert_equal "Member", parsed.name
    assert parsed.ranged?
    assert_equal 0, parsed.range_start
    assert_equal 4, parsed.range_end
  end

  def test_parse_plain_attribute
    parsed = Net::LDAP::RangedAttributeName.parse("member")
    assert_equal "member", parsed.name
    assert_equal [], parsed.options
    refute parsed.ranged?
    refute parsed.final?
  end
end

class TestReadRangedAttribute < Test::Unit::TestCase
  DN = "cn=big-group,ou=groups,dc=example,dc=com"

  def setup
    @ldap = Net::LDAP.new
    @requests = []
  end

  # Stubs Net::LDAP#search with a script of entries (or nil for a failed
  # search), one per call. The block, if given, receives the search args
  # and the call index and may return an override.
  def stub_search(script)
    requests = @requests
    ldap = @ldap
    index = 0
    ldap.define_singleton_method(:search) do |args = {}|
      requests << args
      response = script[index]
      index += 1
      response
    end
  end

  def entry(attributes)
    entry = Net::LDAP::Entry.new(DN)
    attributes.each { |name, values| entry[name] = values }
    entry
  end

  def requested_ranges
    @requests.map do |args|
      args[:attributes].grep(/;range=/).first
    end
  end

  def test_reads_segments_until_end_marker_without_assuming_segment_size
    stub_search([
      [entry("member;range=0-2"   => %w(a b c))],
      [entry("member;range=3-4"   => %w(d e))],
      [entry("member;range=5-6*"  => %w(f g))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    assert result.success?, result.error
    assert_equal %w(a b c d e f g), result.values
    assert_equal ["member;range=0-*", "member;range=3-*", "member;range=5-*"],
                 requested_ranges
  end

  def test_final_segment_may_be_short
    stub_search([
      [entry("member;range=0-1"  => %w(a b))],
      [entry("member;range=2-2*" => %w(c))],
    ])

    result = @ldap.read_ranged_attribute(DN, "member")

    assert result.success?, result.error
    assert_equal %w(a b c), result.values
  end

  def test_empty_attribute_returns_empty_values
    stub_search([[entry("cn" => %w(big-group))]])

    result = @ldap.read_ranged_attribute(DN, :member)

    assert result.success?, result.error
    assert_equal [], result.values
    assert_equal 1, @requests.size
  end

  def test_suffix_case_does_not_matter
    stub_search([
      [entry("Member;Range=0-1"  => %w(a b))],
      [entry("MEMBER;RANGE=2-2*" => %w(c))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    assert result.success?, result.error
    assert_equal %w(a b c), result.values
  end

  def test_attribute_options_are_tolerated_and_binary_content_preserved
    binary_one = "\x00\xffobject\x00sid".b
    binary_two = "\x01\x02".b
    stub_search([
      [entry("member;binary;range=0-0"  => [binary_one])],
      [entry("member;binary;range=1-1*" => [binary_two])],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    assert result.success?, result.error
    assert_equal [binary_one, binary_two], result.values
    assert_equal binary_one.encoding, result.values.first.encoding
  end

  def test_plain_attribute_without_range_is_complete
    stub_search([[entry("member" => %w(a b))]])

    result = @ldap.read_ranged_attribute(DN, :member)

    assert result.success?, result.error
    assert_equal %w(a b), result.values
    assert_equal 1, @requests.size
  end

  def test_range_regression_stops_the_read
    stub_search([
      [entry("member;range=0-2" => %w(a b c))],
      [entry("member;range=1-3" => %w(b c d))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/regression, gap, or duplicate/, result.error)
    assert_equal [], result.values
    assert_equal 2, @requests.size
  end

  def test_range_gap_stops_the_read
    stub_search([
      [entry("member;range=0-2" => %w(a b c))],
      [entry("member;range=5-6" => %w(f g))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/regression, gap, or duplicate/, result.error)
    assert_equal 2, @requests.size
  end

  def test_duplicate_range_stops_the_read
    stub_search([
      [entry("member;range=0-2" => %w(a b c))],
      [entry("member;range=0-2" => %w(a b c))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/regression, gap, or duplicate/, result.error)
    assert_equal 2, @requests.size
  end

  def test_malformed_range_stops_the_read
    stub_search([
      [entry("member;range=0-0" => %w(a))],
      [entry("member;range=1-0" => %w())],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/malformed range/, result.error)
    assert_equal 2, @requests.size
  end

  def test_attribute_disappearing_mid_read_stops_the_read
    stub_search([
      [entry("member;range=0-2" => %w(a b c))],
      [entry("cn" => %w(big-group))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/stopped returning/, result.error)
    assert_equal 2, @requests.size
  end

  def test_failed_search_reports_error
    stub_search([nil])
    @ldap.define_singleton_method(:get_operation_result) do
      OpenStruct.new(:message => "operations error")
    end

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/operations error/, result.error)
  end

  def test_missing_entry_reports_error
    stub_search([[]])

    result = @ldap.read_ranged_attribute(DN, :member)

    refute result.success?
    assert_match(/no entry/, result.error)
  end

  def test_version_change_discards_partial_results
    stub_search([
      [entry("member;range=0-1" => %w(a b), "usnchanged" => %w(100))],
      [entry("member;range=2-3" => %w(c d), "usnchanged" => %w(101))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member,
                                         :version_attribute => :usnchanged)

    refute result.success?
    assert_match(/usnchanged changed/, result.error)
    assert_equal [], result.values
    refute result.consistent?
    assert_equal 2, @requests.size
  end

  def test_stable_version_marks_result_consistent
    stub_search([
      [entry("member;range=0-1"  => %w(a b), "usnchanged" => %w(100))],
      [entry("member;range=2-2*" => %w(c),   "usnchanged" => %w(100))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member,
                                         :version_attribute => :usnchanged)

    assert result.success?, result.error
    assert result.consistent?
    assert_equal [], result.warnings
    assert_equal %w(a b c), result.values
    assert @requests.all? { |args| args[:attributes].include?("usnchanged") }
  end

  def test_unavailable_version_warns_that_consistency_cannot_be_guaranteed
    stub_search([
      [entry("member;range=0-1"  => %w(a b))],
      [entry("member;range=2-2*" => %w(c))],
    ])

    result = @ldap.read_ranged_attribute(DN, :member,
                                         :version_attribute => :usnchanged)

    assert result.success?, result.error
    refute result.consistent?
    assert_equal 1, result.warnings.size
    assert_match(/snapshot consistency cannot be guaranteed/,
                 result.warnings.first)
  end

  def test_no_version_attribute_means_not_consistent
    stub_search([[entry("member;range=0-0*" => %w(a))]])

    result = @ldap.read_ranged_attribute(DN, :member)

    assert result.success?, result.error
    refute result.consistent?
    assert_equal [], result.warnings
  end
end
