# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/query_parser'
end

describe Rack::QueryParser do
  it "can normalize values with missing values" do
    query_parser = Rack::QueryParser.make_default(8)
    query_parser.parse_nested_query("a=a").must_equal({"a" => "a"})
    query_parser.parse_nested_query("a=").must_equal({"a" => ""})
    query_parser.parse_nested_query("a").must_equal({"a" => nil})
    query_parser.parse_query_pairs("a=a").must_equal([["a", "a"]])
    query_parser.parse_query_pairs("a=").must_equal([["a", ""]])
    query_parser.parse_query_pairs("a").must_equal([["a", nil]])
  end

  it "accepts bytesize_limit to specify maximum size of query string to parse" do
    query_parser = Rack::QueryParser.make_default(32, bytesize_limit: 3)
    query_parser.parse_query("a=a").must_equal({"a" => "a"})
    query_parser.parse_nested_query("a=a").must_equal({"a" => "a"})
    query_parser.parse_nested_query("a=a", '&').must_equal({"a" => "a"})
    query_parser.parse_query_pairs("a=a").must_equal([["a", "a"]])
    proc { query_parser.parse_query("a=aa") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_nested_query("a=aa") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_nested_query("a=aa", '&') }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_query_pairs("a=aa") }.must_raise Rack::QueryParser::QueryLimitError
  end

  it "does not enforce a bytesize limit when bytesize_limit is nil" do
    query_parser = Rack::QueryParser.make_default(32, bytesize_limit: nil)
    query_parser.parse_query("a=aa").must_equal({"a" => "aa"})
    query_parser.parse_nested_query("a=aa").must_equal({"a" => "aa"})
    query_parser.parse_nested_query("a=aa", '&').must_equal({"a" => "aa"})
    query_parser.parse_query_pairs("a=aa").must_equal([["a", "aa"]])
  end

  it "accepts params_limit to specify maximum number of query parameters to parse" do
    query_parser = Rack::QueryParser.make_default(32, params_limit: 2)
    query_parser.parse_query("a=a&b=b").must_equal({"a" => "a", "b" => "b"})
    query_parser.parse_nested_query("a=a&b=b").must_equal({"a" => "a", "b" => "b"})
    query_parser.parse_nested_query("a=a&b=b", '&').must_equal({"a" => "a", "b" => "b"})
    query_parser.parse_query_pairs("a=a&b=b").must_equal([["a", "a"], ["b", "b"]])
    query_parser.parse_query_pairs("a=1&a=2").must_equal([["a", "1"], ["a", "2"]])
    proc { query_parser.parse_query("a=a&b=b&c=c") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_nested_query("a=a&b=b&c=c", '&') }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_query("b[]=a&b[]=b&b[]=c") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_query_pairs("a=a&b=b&c=c") }.must_raise Rack::QueryParser::QueryLimitError
  end

  it "does not enforce a params limit when params_limit is nil" do
    query_parser = Rack::QueryParser.make_default(32, params_limit: nil)
    query_parser.parse_query("a=a&b=b&c=c").must_equal({"a" => "a", "b" => "b", "c" => "c"})
    query_parser.parse_nested_query("a=a&b=b&c=c").must_equal({"a" => "a", "b" => "b", "c" => "c"})
  end

  it "raises when normalizing params with incompatible encoding such as UTF-16LE" do
    query_parser = Rack::QueryParser.make_default(8)
    name = "utf-16le".dup.force_encoding("UTF-16LE")
    value = "Alice?".dup.force_encoding("UTF-16LE")
    lambda {
      query_parser.normalize_params({}, name, value)
    }.must_raise(::Rack::QueryParser::IncompatibleEncodingError)
  end

  it "supports duplicate scalar handling strategies for nested parameters" do
    query = "order[id]=7&order[%69d]=9&items[][id]=1&items[][id]=2"

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :first)
    parser.duplicate_scalar_handling.must_equal :first
    parser.parse_nested_query(query).must_equal(
      "order" => {"id" => "7"},
      "items" => [{"id" => "1"}, {"id" => "2"}]
    )

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :last)
    parser.duplicate_scalar_handling.must_equal :last
    parser.parse_nested_query(query).must_equal(
      "order" => {"id" => "9"},
      "items" => [{"id" => "1"}, {"id" => "2"}]
    )

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :reject)
    error = proc { parser.parse_nested_query(query) }.must_raise(Rack::QueryParser::DuplicateParameterError)
    error.parameter_name.must_equal "order[id]"
    error.first_position.must_equal 1
    error.second_position.must_equal 2
    error.message.must_equal "duplicate scalar parameter `order[id]' assigned at positions 1 and 2"
    parser.parse_nested_query("items[][id]=1&items[][id]=2").must_equal(
      "items" => [{"id" => "1"}, {"id" => "2"}]
    )
  end

  it "accepts a duplicate scalar handling strategy for a single parse call" do
    parser = Rack::QueryParser.make_default(8)
    parser.parse_nested_query("a=1&a=2", nil, duplicate_scalar_handling: :first).
      must_equal("a" => "1")
    parser.duplicate_scalar_handling.must_be_nil
  end

  it "uses decoded full paths and reports non-empty pair positions for duplicate scalars" do
    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: "reject")
    query = "safe=0&outer[inner]=first&&outer[%69nner]=second"
    error = proc { parser.parse_nested_query(query) }.must_raise(Rack::QueryParser::DuplicateParameterError)
    error.parameter_name.must_equal "outer[inner]"
    error.first_position.must_equal 2
    error.second_position.must_equal 3
  end

  it "applies duplicate scalar handling to missing and empty values" do
    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :first)
    parser.parse_nested_query("a&a=").must_equal("a" => nil)
    parser.parse_nested_query("a=&a").must_equal("a" => "")

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :last)
    parser.parse_nested_query("a&a=").must_equal("a" => "")
    parser.parse_nested_query("a=&a").must_equal("a" => nil)

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :reject)
    proc { parser.parse_nested_query("a&a=") }.must_raise(Rack::QueryParser::DuplicateParameterError)
  end

  it "rejects or selects conflicting scalar and container assignments" do
    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :reject)
    error = proc { parser.parse_nested_query("a=1&a[b]=2") }.
      must_raise(Rack::QueryParser::ConflictingParameterError)
    error.parameter_name.must_equal "a"
    error.first_position.must_equal 1
    error.second_position.must_equal 2
    proc { parser.parse_nested_query("a[b]=1&a=2") }.
      must_raise(Rack::QueryParser::ParameterTypeError)

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :first)
    parser.parse_nested_query("a=1&a[b]=2").must_equal("a" => "1")
    parser.parse_nested_query("a[b]=1&a=2").must_equal("a" => {"b" => "1"})

    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :last)
    parser.parse_nested_query("a=1&a[b]=2").must_equal("a" => {"b" => "2"})
    parser.parse_nested_query("a[b]=1&a=2").must_equal("a" => "2")
  end

  it "checks invalid encoding and depth limits together with duplicate scalar handling" do
    parser = Rack::QueryParser.make_default(8, duplicate_scalar_handling: :reject)
    error = proc { parser.parse_nested_query("a%=3&order[id]=1&order[id]=2") }.
      must_raise(Rack::QueryParser::InvalidParameterError)
    error.class.must_equal Rack::QueryParser::InvalidParameterError
    error.message.must_equal "invalid %-encoding (a%)"
    proc { parser.parse_nested_query("order[id]=1&order[id]=2&a%=3") }.
      must_raise(Rack::QueryParser::InvalidParameterError)

    [:first, :last, :reject].each do |handling|
      parser = Rack::QueryParser.make_default(1, duplicate_scalar_handling: handling)
      proc { parser.parse_nested_query("order[id]=1&order[id]=2") }.
        must_raise(Rack::QueryParser::ParamsTooDeepError)
    end
  end

  it "preserves historical query parser behavior without an explicit strategy" do
    parser = Rack::QueryParser.make_default(8)
    parser.duplicate_scalar_handling.must_be_nil
    parser.parse_nested_query("a=1&a=2").must_equal("a" => "2")
    parser.parse_nested_query("a[b]=1&a=2").must_equal("a" => "2")
    proc { parser.parse_nested_query("a=1&a[b]=2") }.
      must_raise(Rack::QueryParser::ParameterTypeError)
  end
end
