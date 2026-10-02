# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/preferences'
end

describe Rack::Preferences do
  def parse(header)
    Rack::Preferences.parse(header)
  end

  it "is empty for a nil or empty header" do
    parse(nil).to_a.must_be_empty
    parse('').to_a.must_be_empty
  end

  it "parses a simple preference with a value" do
    preferences = parse('return=minimal')
    preferences['return'].must_equal 'minimal'
    preferences.key?('return').must_equal true
  end

  it "parses a preference without a value as true" do
    parse('respond-async')['respond-async'].must_equal true
  end

  it "returns nil for preferences that were not requested" do
    parse('return=minimal')['wait'].must_be_nil
    parse('return=minimal').key?('wait').must_equal false
  end

  it "parses multiple preferences in order" do
    preferences = parse('return=minimal, wait=10, respond-async')
    preferences.to_a.must_equal [['return', 'minimal'], ['wait', '10'], ['respond-async', true]]
  end

  it "downcases preference names" do
    preferences = parse('RETURN=Minimal')
    preferences['return'].must_equal 'Minimal'
    preferences.key?('RETURN').must_equal true
  end

  it "uses the first occurrence of a duplicated preference" do
    parse('return=minimal, return=representation')['return'].must_equal 'minimal'
    parse('wait=10, wait=20')['wait'].must_equal '10'
  end

  it "resolves conflicting return values in favor of the first" do
    parse('return=representation, return=minimal')['return'].must_equal 'representation'
  end

  it "unquotes quoted values" do
    parse('wait="10"')['wait'].must_equal '10'
  end

  it "keeps commas inside quoted values" do
    parse('foo="a,b", wait=10').to_a.must_equal [['foo', 'a,b'], ['wait', '10']]
  end

  it "unescapes quoted-pairs in quoted values" do
    parse('foo="a\"b"')['foo'].must_equal 'a"b'
  end

  it "parses extension parameters" do
    preferences = parse('respond-async; wait=10; trace')
    preferences['respond-async'].must_equal true
    preferences.params('respond-async').must_equal 'wait' => '10', 'trace' => true
  end

  it "unquotes quoted extension parameter values" do
    parse('foo;bar="baz qux"').params('foo').must_equal 'bar' => 'baz qux'
  end

  it "keeps semicolons inside quoted parameter values" do
    parse('foo;bar="a;b", wait=10').params('foo').must_equal 'bar' => 'a;b'
  end

  it "uses the first occurrence of a duplicated parameter" do
    parse('foo;bar=1;bar=2').params('foo').must_equal 'bar' => '1'
  end

  it "returns an empty hash of parameters for unknown preferences" do
    parse('return=minimal').params('unknown').must_equal({})
  end

  it "ignores malformed entries" do
    preferences = parse('=oops, foo bar=baz, , wait=10')
    preferences.to_a.must_equal [['wait', '10']]
  end

  it "ignores whitespace around names, values and separators" do
    parse('  return = minimal ,  wait= 10  ')['return'].must_equal 'minimal'
  end

  it "only applies preferences that were requested" do
    preferences = parse('return=minimal')
    preferences.apply('return').must_equal true
    preferences.apply('respond-async').must_equal false
    preferences.applied.must_equal ['return']
  end

  it "applies a preference with a matching value" do
    preferences = parse('return=minimal')
    preferences.apply('return', 'minimal').must_equal true
    preferences.apply('return', 'representation').must_equal false
    preferences.applied.must_equal ['return']
  end

  it "matches applied values case-insensitively" do
    parse('return=MINIMAL').apply('return', 'minimal').must_equal true
  end

  it "does not apply a preference twice" do
    preferences = parse('return=minimal')
    preferences.apply('return')
    preferences.apply('return')
    preferences.applied.must_equal ['return']
  end

  it "tracks applied state" do
    preferences = parse('return=minimal, wait=10')
    preferences.applied?('return').must_equal false
    preferences.apply('return')
    preferences.applied?('return').must_equal true
    preferences.applied?('wait').must_equal false
  end

  it "serializes applied preferences with normalized requested values" do
    preferences = parse('return=minimal, respond-async, wait="10"')
    preferences.apply('return')
    preferences.apply('respond-async')
    preferences.apply('wait')
    preferences.applied_header.must_equal 'return=minimal, respond-async, wait=10'
  end

  it "quotes applied values that are not valid tokens" do
    preferences = parse('foo="a,b"')
    preferences.apply('foo')
    preferences.applied_header.must_equal 'foo="a,b"'
  end
end
