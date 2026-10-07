# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestRangedAttribute < Test::Unit::TestCase
  DN = 'cn=Large Group,ou=Groups,dc=example,dc=org'.freeze

  class SearchResult < Struct.new(:result_code, :message)
    def success?
      result_code == Net::LDAP::ResultCodeSuccess
    end
  end

  class FakeConnection
    attr_reader :searches

    def initialize(pages)
      @pages = pages
      @searches = []
    end

    def search(args)
      @searches << args
      entry = @pages.call(args)
      yield entry if entry
      SearchResult.new(Net::LDAP::ResultCodeSuccess, '')
    end
  end

  def setup
    @ldap = Net::LDAP.new(:force_no_page => true)
  end

  def test_reads_ranges_until_wildcard_without_assuming_page_size
    binary_value = "\x00\xffcn=Binary Member,dc=example,dc=org".b
    pages = {
      'MEMber;BINary;range=0-*' => entry(
        'member;binary;range=0-1' => ['cn=first,dc=example,dc=org', binary_value],
        'usnchanged' => ['7']
      ),
      'MEMber;BINary;range=2-*' => entry(
        'member;binary;range=2-*' => ['cn=last,dc=example,dc=org'],
        'usnchanged' => ['7']
      )
    }
    use_fake_connection(pages)

    values = @ldap.read_ranged_attribute(DN, 'MEMber;BINary', :version_attribute => 'usnChanged')

    assert_equal [
      'cn=first,dc=example,dc=org',
      binary_value,
      'cn=last,dc=example,dc=org'
    ], values
    assert_equal Encoding::ASCII_8BIT, values[1].encoding
    assert_equal [
      'MEMber;BINary;range=0-*',
      'usnChanged'
    ], searches[0][:attributes]
    assert_equal [
      'MEMber;BINary;range=2-*',
      'usnChanged'
    ], searches[1][:attributes]
    assert_equal [DN, DN], searches.map { |args| args[:base] }
    assert_equal [Net::LDAP::SearchScope_BaseObject] * 2, searches.map { |args| args[:scope] }
  end

  def test_empty_attribute_returns_an_empty_array
    pages = {
      'member;range=0-*' => entry('usnChanged' => ['9'])
    }
    use_fake_connection(pages)

    assert_equal [], @ldap.read_ranged_attribute(
      DN,
      'member',
      :version_attribute => 'usnChanged',
    )
  end

  def test_accepts_different_case_in_returned_suffix
    pages = {
      'member;range=0-*' => entry('MEMBER;RANGE=0-0' => ['cn=first,dc=example,dc=org']),
      'member;range=1-*' => entry('member;Range=1-*' => ['cn=second,dc=example,dc=org'])
    }
    use_fake_connection(pages)

    assert_equal [
      'cn=first,dc=example,dc=org',
      'cn=second,dc=example,dc=org'
    ], @ldap.read_ranged_attribute(DN, 'member')
  end

  def test_missing_caller_selected_version_attribute_rejects_results
    pages = {
      'member;range=0-*' => entry('member;range=0-*' => ['cn=first,dc=example,dc=org'])
    }
    use_fake_connection(pages)

    error = assert_raise Net::LDAP::RangedAttributeVersionUnavailableError do
      @ldap.read_ranged_attribute(DN, 'member', :version_attribute => 'usnChanged')
    end

    assert_match(/usnChanged/, error.message)
    assert_match(/snapshot consistency cannot be guaranteed/, error.message)
  end

  def test_member_change_during_read_discards_accumulated_results
    pages = lambda do |args|
      case args[:attributes].first
      when 'member;range=0-*'
        entry(
          'member;range=0-1' => ['cn=first,dc=example,dc=org', 'cn=second,dc=example,dc=org'],
          'usnChanged' => ['10']
        )
      when 'member;range=2-*'
        entry(
          'member;range=2-*' => ['cn=new,dc=example,dc=org'],
          'usnChanged' => ['11']
        )
      end
    end
    use_fake_connection(pages)

    error = assert_raise Net::LDAP::RangedAttributeVersionChangedError do
      @ldap.read_ranged_attribute(DN, 'member', :version_attribute => 'usnChanged')
    end

    assert_match(/changed/, error.message)
    assert_match(/discarding accumulated results/, error.message)
    assert_equal 2, fake_connection.searches.length
  end

  def test_duplicate_range_stops_without_another_request
    pages = lambda do |args|
      case args[:attributes].first
      when 'member;range=0-*'
        entry('member;range=0-1' => [
          'cn=first,dc=example,dc=org',
          'cn=second,dc=example,dc=org'
        ])
      when 'member;range=2-*'
        entry('member;range=0-1' => [
          'cn=duplicate,dc=example,dc=org',
          'cn=duplicate-too,dc=example,dc=org'
        ])
      end
    end
    use_fake_connection(pages)

    assert_raise Net::LDAP::InvalidRangedAttributeError do
      @ldap.read_ranged_attribute(DN, 'member')
    end

    assert_equal 2, fake_connection.searches.length
  end

  def test_gap_stops
    pages = lambda do |args|
      case args[:attributes].first
      when 'member;range=0-*'
        entry('member;range=0-1' => [
          'cn=first,dc=example,dc=org',
          'cn=second,dc=example,dc=org'
        ])
      when 'member;range=2-*'
        entry('member;range=3-*' => ['cn=skipped,dc=example,dc=org'])
      end
    end
    use_fake_connection(pages)

    error = assert_raise Net::LDAP::InvalidRangedAttributeError do
      @ldap.read_ranged_attribute(DN, 'member')
    end

    assert_match(/start at 2/, error.message)
  end

  def test_declared_non_final_range_with_no_values_stops
    pages = {
      'member;range=0-*' => entry('member;range=0-1' => [])
    }
    use_fake_connection(pages)

    error = assert_raise Net::LDAP::InvalidRangedAttributeError do
      @ldap.read_ranged_attribute(DN, 'member')
    end

    assert_match(/0 values for 0-1/, error.message)
    assert_equal 1, fake_connection.searches.length
  end

  def test_backwards_range_stops
    pages = lambda do |args|
      case args[:attributes].first
      when 'member;range=0-*'
        entry('member;range=0-1' => [
          'cn=first,dc=example,dc=org',
          'cn=second,dc=example,dc=org'
        ])
      when 'member;range=2-*'
        entry('member;range=1-0' => ['cn=backwards,dc=example,dc=org'])
      end
    end
    use_fake_connection(pages)

    assert_raise Net::LDAP::InvalidRangedAttributeError do
      @ldap.read_ranged_attribute(DN, 'member')
    end
  end

  private

  def entry(attributes)
    Net::LDAP::Entry.new(DN).tap do |entry|
      attributes.each do |name, values|
        entry[name] = values
      end
    end
  end

  def use_fake_connection(pages)
    @fake_connection = FakeConnection.new(page_lookup(pages))
    @ldap.connection = @fake_connection
  end

  def page_lookup(pages)
    if pages.respond_to?(:call)
      pages
    else
      lambda do |args|
        pages.fetch(args[:attributes].first)
      end
    end
  end

  def fake_connection
    @fake_connection
  end

  def searches
    fake_connection.searches
  end
end
