# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Specialization do
  class SpecializationSchema < GraphQL::Schema
    CALLS = Hash.new(0)
    CALL_ORDER = []

    class ColorEnum < GraphQL::Schema::Enum
      graphql_name "Color"
      value "RED", value: :red
      value "BLUE", value: :blue
    end

    class FilterInput < GraphQL::Schema::InputObject
      graphql_name "Filter"
      argument :term, String, required: true
      argument :limit, Integer, required: false
      argument :color, ColorEnum, required: false
    end

    class Query < GraphQL::Schema::Object
      field :greeting, String do
        argument :name, String, required: true
      end

      def greeting(name:)
        SpecializationSchema::CALLS[:greeting] += 1
        "Hello, #{name}!"
      end

      field :secret, String

      def secret
        SpecializationSchema::CALLS[:secret] += 1
        "shh"
      end

      field :boom, String

      def boom
        SpecializationSchema::CALLS[:boom] += 1
        raise GraphQL::ExecutionError, "kapow"
      end

      field :search, [String] do
        argument :filter, FilterInput, required: true
      end

      def search(filter:)
        SpecializationSchema::CALLS[:search] += 1
        ["#{filter[:term]}|#{filter[:limit]}|#{filter[:color]}"]
      end

      field :color_name, String do
        argument :color, ColorEnum, required: true
      end

      def color_name(color:)
        SpecializationSchema::CALLS[:color_name] += 1
        color.to_s
      end

      field :echo_ids, [String] do
        argument :ids, [GraphQL::Types::ID], required: true
      end

      def echo_ids(ids:)
        SpecializationSchema::CALLS[:echo_ids] += 1
        ids
      end
    end

    class Mutation < GraphQL::Schema::Object
      field :first_action, String
      field :second_action, String
      field :third_action, String

      def first_action
        SpecializationSchema::CALLS[:first_action] += 1
        SpecializationSchema::CALL_ORDER << :first_action
        "first"
      end

      def second_action
        SpecializationSchema::CALLS[:second_action] += 1
        SpecializationSchema::CALL_ORDER << :second_action
        "second"
      end

      def third_action
        SpecializationSchema::CALLS[:third_action] += 1
        SpecializationSchema::CALL_ORDER << :third_action
        "third"
      end
    end

    class CachedDirective < GraphQL::Schema::Directive
      graphql_name "cached"
      locations GraphQL::Schema::Directive::FIELD
      argument :ttl, Integer, required: false
    end

    query Query
    mutation Mutation
    directive CachedDirective
  end

  before do
    SpecializationSchema::CALLS.clear
    SpecializationSchema::CALL_ORDER.clear
  end

  def assert_equivalent(original, original_variables, specialized, specialized_variables)
    SpecializationSchema::CALLS.clear
    SpecializationSchema::CALL_ORDER.clear
    original_result = SpecializationSchema.execute(original, variables: original_variables)
    original_calls = SpecializationSchema::CALLS.dup
    original_order = SpecializationSchema::CALL_ORDER.dup

    SpecializationSchema::CALLS.clear
    SpecializationSchema::CALL_ORDER.clear
    specialized_result = SpecializationSchema.execute(specialized, variables: specialized_variables)

    assert_equal original_result.to_h, specialized_result.to_h
    assert_equal original_calls, SpecializationSchema::CALLS
    assert_equal original_order, SpecializationSchema::CALL_ORDER
  end

  it "binds constants, prunes decided branches, and removes unused variables and fragments" do
    query = <<~GRAPHQL
      query GetGreeting($flag: Boolean!, $name: String!) {
        greeting(name: $name)
        secret @include(if: $flag)
        ...Extras @skip(if: $flag)
      }

      fragment Extras on Query {
        echoIds(ids: ["x"])
      }
    GRAPHQL

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "flag" => true })

    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    assert_includes result.query_string, "$name: String!"
    refute_includes result.query_string, "$flag"
    refute_includes result.query_string, "@include"
    refute_includes result.query_string, "@skip"
    refute_includes result.query_string, "Extras"
    refute_includes result.query_string, "echoIds"

    assert_equivalent(query, { "flag" => true, "name" => "Ruby" }, result.query_string, { "name" => "Ruby" })
  end

  it "keeps unbound variables as runtime parameters" do
    query = <<~GRAPHQL
      query GetGreeting($flag: Boolean!, $name: String!) {
        greeting(name: $name)
        secret @include(if: $flag)
      }
    GRAPHQL

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { flag: false })

    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    assert_includes result.query_string, "greeting(name: $name)"
    refute_includes result.query_string, "secret"

    assert_equivalent(query, { "flag" => false, "name" => "A" }, result.query_string, { "name" => "A" })
    assert_equivalent(query, { "flag" => false, "name" => "B" }, result.query_string, { "name" => "B" })
  end

  it "rejects bindings that don't match the variable's type" do
    query = "query($flag: Boolean!, $limit: Int) { secret @include(if: $flag) @cached(ttl: $limit) }"

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "flag" => "yes" })
    refute result.ok?
    assert_nil result.query_string
    assert_match(/\$flag/, result.errors.join)

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "flag" => nil })
    refute result.ok?
    assert_match(/non-null/, result.errors.join)

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "limit" => 1.5 })
    refute result.ok?
    assert_match(/\$limit/, result.errors.join)
  end

  it "rejects bindings for variables the operation doesn't define" do
    query = "query($flag: Boolean!) { secret @include(if: $flag) }"

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "nope" => 1 })

    refute result.ok?
    assert_match(/\$nope/, result.errors.join)
  end

  it "returns a clear result when the original query is invalid" do
    result = GraphQL::Specialization.specialize(SpecializationSchema, "query { nope }")

    refute result.ok?
    assert_match(/invalid/, result.errors.join)
  end

  it "returns a clear result when pruning empties the operation" do
    query = "query($flag: Boolean!) { secret @include(if: $flag) }"

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "flag" => false })

    refute result.ok?
    assert_nil result.query_string
    assert_match(/removed every selection/, result.errors.join)
  end

  it "never reorders mutation top-level fields when pruning" do
    query = <<~GRAPHQL
      mutation DoThings($skipSecond: Boolean!) {
        firstAction
        secondAction @skip(if: $skipSecond)
        thirdAction
      }
    GRAPHQL

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "skipSecond" => true })

    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    first_idx = result.query_string.index("firstAction")
    third_idx = result.query_string.index("thirdAction")
    assert first_idx < third_idx, "Expected firstAction to stay before thirdAction"
    refute_includes result.query_string, "secondAction"

    assert_equivalent(query, { "skipSecond" => true }, result.query_string, {})
    assert_equal [:first_action, :third_action], SpecializationSchema::CALL_ORDER
  end

  it "leaves custom directives untouched instead of executing them" do
    query = "query($ttl: Int!) { secret @cached(ttl: $ttl) }"

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "ttl" => 60 })

    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    assert_includes result.query_string, "@cached(ttl: 60)"
    refute_includes result.query_string, "$ttl"

    assert_equivalent(query, { "ttl" => 60 }, result.query_string, {})
  end

  it "inlines enum, input object, and list bindings as literals" do
    query = <<~GRAPHQL
      query Search($filter: Filter!, $color: Color!, $ids: [ID!]!) {
        search(filter: $filter)
        colorName(color: $color)
        echoIds(ids: $ids)
      }
    GRAPHQL

    bindings = {
      "filter" => { "term" => "ruby", "limit" => 3, "color" => "RED" },
      "color" => :blue,
      "ids" => ["1", "2"],
    }
    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: bindings)

    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    assert_includes result.query_string, 'term: "ruby"'
    assert_includes result.query_string, "color: RED"
    assert_includes result.query_string, "color: BLUE"
    assert_includes result.query_string, 'ids: ["1", "2"]'
    refute_includes result.query_string, "$filter"

    original_variables = bindings.merge("color" => "BLUE")
    assert_equivalent(query, original_variables, result.query_string, {})
  end

  it "compares errors as well as data" do
    query = <<~GRAPHQL
      query WithError($flag: Boolean!) {
        boom
        secret @skip(if: $flag)
      }
    GRAPHQL

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "flag" => true })

    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    assert_equivalent(query, { "flag" => true }, result.query_string, {})
    assert_equal 1, SpecializationSchema::CALLS[:boom]
    assert_equal 0, SpecializationSchema::CALLS[:secret]
  end

  it "requires an operation name when the document has several operations" do
    query = <<~GRAPHQL
      query A($flag: Boolean!) { secret @include(if: $flag) }
      query B { greeting(name: "x") }
    GRAPHQL

    result = GraphQL::Specialization.specialize(SpecializationSchema, query, variables: { "flag" => true })
    refute result.ok?
    assert_match(/operation_name/, result.errors.join)

    result = GraphQL::Specialization.specialize(
      SpecializationSchema, query, variables: { "flag" => true }, operation_name: "A"
    )
    assert result.ok?, "Expected specialization to succeed, got: #{result.errors.inspect}"
    assert_includes result.query_string, "query A"
    assert_includes result.query_string, "query B"
    refute_includes result.query_string, "$flag"
  end
end
