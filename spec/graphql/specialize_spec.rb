# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Specialize do
  class SpecializeTestSchema < GraphQL::Schema
    CALLS = []

    class EpisodeEnum < GraphQL::Schema::Enum
      value "EMPIRE"
      value "JEDI"
    end

    class FilterInput < GraphQL::Schema::InputObject
      argument :query, String, required: false
      argument :limit, Integer, required: false
      argument :episode, EpisodeEnum, required: false
    end

    class CustomDirective < GraphQL::Schema::Directive
      graphql_name "custom"
      locations GraphQL::Schema::Directive::FIELD
      argument :tag, String, required: false
    end

    class OperationDirective < GraphQL::Schema::Directive
      graphql_name "operation_flag"
      locations GraphQL::Schema::Directive::QUERY
      argument :tag, String, required: false
    end

    class Query < GraphQL::Schema::Object
      field :greeting, String do
        argument :name, String, required: false
      end
      def greeting(name: nil)
        CALLS << [:greeting, name]
        "Hello, #{name || "world"}"
      end

      field :secret, String
      def secret
        CALLS << [:secret]
        "shh"
      end

      field :search, [String] do
        argument :filter, FilterInput, required: false
      end
      def search(filter: nil)
        CALLS << [:search, filter.to_h]
        ["result-#{filter ? filter[:query] : "none"}"]
      end

      field :episode_name, String do
        argument :episode, EpisodeEnum, required: false
      end
      def episode_name(episode: nil)
        CALLS << [:episode_name, episode]
        episode.to_s
      end

      field :broken, String do
        argument :flag, Boolean, required: false
      end
      def broken(flag: false)
        CALLS << [:broken, flag]
        raise GraphQL::ExecutionError, "boom" if flag
        "fine"
      end
    end

    class Mutation < GraphQL::Schema::Object
      field :first_step, String do
        argument :note, String, required: false
      end
      def first_step(note: nil)
        CALLS << [:first_step, note]
        "one"
      end

      field :second_step, String
      def second_step
        CALLS << [:second_step]
        "two"
      end

      field :third_step, String
      def third_step
        CALLS << [:third_step]
        "three"
      end
    end

    directive(CustomDirective)
    directive(OperationDirective)
    query(Query)
    mutation(Mutation)
  end

  def reset_calls
    SpecializeTestSchema::CALLS.clear
  end

  def run_both(original_query, all_variables, bound_variables, operation_name: nil)
    specialize_kwargs = { variables: bound_variables }
    specialize_kwargs[:operation_name] = operation_name if operation_name
    result = GraphQL::Specialize.call(SpecializeTestSchema, original_query, **specialize_kwargs)
    assert result.success?, "expected specialization to succeed, got: #{result.errors.inspect}"

    reset_calls
    original_response = SpecializeTestSchema.execute(original_query, variables: all_variables, operation_name: operation_name)
    original_calls = SpecializeTestSchema::CALLS.dup

    reset_calls
    remaining_variables = all_variables.reject { |key, _| bound_variables.key?(key.to_s) || bound_variables.key?(key.to_sym) }
    specialized_response = SpecializeTestSchema.execute(result.query_string, variables: remaining_variables, operation_name: operation_name)
    specialized_calls = SpecializeTestSchema::CALLS.dup

    [result, original_response, specialized_response, original_calls, specialized_calls]
  end

  def assert_same_execution(original_response, specialized_response, original_calls, specialized_calls)
    assert_equal original_response.to_h["data"], specialized_response.to_h["data"], "expected the same data"
    original_errors = original_response.to_h["errors"]
    if original_errors.nil?
      assert_nil specialized_response.to_h["errors"], "expected no errors"
    else
      assert_equal original_errors, specialized_response.to_h["errors"], "expected the same errors"
    end
    assert_equal original_calls, specialized_calls, "expected the same resolver calls"
  end

  before { reset_calls }

  describe "binding constants" do
    it "replaces bound variables with literals and keeps unbound ones as runtime parameters" do
      query = <<~GRAPHQL
        query GetStuff($name: String, $limit: Int) {
          greeting(name: $name)
          search(filter: { query: "x", limit: $limit })
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "limit" => 3 })
      assert result.success?
      assert_equal ["name"], result.variables
      specialized = result.query_string
      assert_includes specialized, "limit: 3"
      assert_includes specialized, "$name: String"
      refute_includes specialized, "$limit"
    end

    it "renders enum, input object, list, and null literals from bound values" do
      query = <<~GRAPHQL
        query GetStuff($ep: EpisodeEnum, $filter: FilterInput, $name: String) {
          episodeName(episode: $ep)
          search(filter: $filter)
          greeting(name: $name)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: {
        "ep" => "JEDI",
        "filter" => { "query" => "x", "limit" => 2, "episode" => "EMPIRE" },
        "name" => nil,
      })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      assert_includes specialized, "episode: JEDI"
      assert_includes specialized, 'filter: {query: "x", limit: 2, episode: EMPIRE}'
      assert_includes specialized, "name: null"
      assert_equal [], result.variables
    end

    it "validates bound values against variable types before specializing" do
      query = <<~GRAPHQL
        query GetStuff($limit: Int!, $ep: EpisodeEnum) {
          search(filter: { limit: $limit })
          episodeName(episode: $ep)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "limit" => "not-an-int" })
      refute result.success?
      assert_equal 1, result.errors.size
      assert_includes result.errors.first, "$limit"
      assert_nil result.document
      assert_nil result.query_string

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "ep" => "NOT_AN_EPISODE" })
      refute result.success?
      assert_includes result.errors.first, "$ep"

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "limit" => nil })
      refute result.success?
      assert_includes result.errors.first, "$limit"
    end
  end

  describe "@skip and @include pruning" do
    it "removes branches decided by bound booleans and drops the directives" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!, $name: String) {
          greeting(name: $name)
          secret @include(if: $verbose)
          episodeName @skip(if: $verbose)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => false })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      refute_includes specialized, "secret"
      assert_includes specialized, "episodeName"
      refute_includes specialized, "@include"
      refute_includes specialized, "@skip"
      refute_includes specialized, "$verbose"
      assert_equal ["name"], result.variables
    end

    it "leaves undecided directives alone" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!) {
          greeting
          secret @include(if: $verbose)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: {})
      assert result.success?
      assert_includes result.query_string, "@include(if: $verbose)"
      assert_equal ["verbose"], result.variables
    end

    it "never executes custom directives to decide branches" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!, $tag: String) {
          greeting @custom(tag: $tag)
          secret @include(if: $verbose)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => false, "tag" => "kept" })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      assert_includes specialized, '@custom(tag: "kept")'
      refute_includes specialized, "secret"
    end
  end

  describe "unused definitions" do
    it "removes variables and fragments that are no longer used" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!, $unused: String) {
          greeting
          ...Extras @include(if: $verbose)
        }

        fragment Extras on Query {
          secret
        }

        fragment Orphan on Query {
          episodeName
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => false })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      refute_includes specialized, "Extras"
      refute_includes specialized, "Orphan"
      refute_includes specialized, "$unused"
      refute_includes specialized, "fragment"
    end

    it "keeps fragments that are still spread" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!) {
          greeting
          ...Extras @include(if: $verbose)
        }

        fragment Extras on Query {
          secret
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => true })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      assert_includes specialized, "...Extras"
      assert_includes specialized, "fragment Extras on Query"
      refute_includes specialized, "@include"
    end
  end

  describe "edge cases" do
    it "removes variables that are only used in pruned branches" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!, $name: String) {
          greeting(name: $name) @include(if: $verbose)
          secret
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => false })
      assert result.success?, result.errors.inspect
      assert_equal [], result.variables
      refute_includes result.query_string, "$name"
      refute_includes result.query_string, "greeting"
    end

    it "binds variables used inside fragment definitions" do
      query = <<~GRAPHQL
        query GetStuff($name: String) {
          ...Extras
        }

        fragment Extras on Query {
          greeting(name: $name)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "name" => "Frag" })
      assert result.success?, result.errors.inspect
      assert_equal [], result.variables
      assert_includes result.query_string, 'greeting(name: "Frag")'

      reset_calls
      response = SpecializeTestSchema.execute(result.query_string)
      assert_equal({ "greeting" => "Hello, Frag" }, response.to_h["data"])
    end

    it "drops inline fragments emptied by pruning" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!) {
          greeting
          ... on Query {
            secret @include(if: $verbose)
          }
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => false })
      assert result.success?, result.errors.inspect
      refute_includes result.query_string, "..."
      refute_includes result.query_string, "secret"
    end

    it "binds variables used in operation directives" do
      query = <<~GRAPHQL
        query GetStuff($tag: String) @operation_flag(tag: $tag) {
          greeting
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "tag" => "op" })
      assert result.success?, result.errors.inspect
      assert_includes result.query_string, '@operation_flag(tag: "op")'
      assert_equal [], result.variables
    end
  end

  describe "mutations" do
    it "never reorders top-level mutation fields" do
      query = <<~GRAPHQL
        mutation DoSteps($skipSecond: Boolean!) {
          firstStep
          secondStep @skip(if: $skipSecond)
          thirdStep
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "skipSecond" => false })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      first_idx = specialized.index("firstStep")
      second_idx = specialized.index("secondStep")
      third_idx = specialized.index("thirdStep")
      assert first_idx < second_idx, "firstStep should come before secondStep"
      assert second_idx < third_idx, "secondStep should come before thirdStep"

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "skipSecond" => true })
      assert result.success?, result.errors.inspect
      specialized = result.query_string
      refute_includes specialized, "secondStep"
      assert specialized.index("firstStep") < specialized.index("thirdStep")
    end
  end

  describe "invalid results" do
    it "returns a clear result when pruning would leave an empty selection set" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!) {
          search {
            __typename @include(if: $verbose)
          }
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => false })
      refute result.success?
      assert_equal 1, result.errors.size
      assert_includes result.errors.first, "empty selection set"
      assert_nil result.document
    end

    it "returns a clear result when the whole operation is pruned away" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!) {
          greeting @skip(if: $verbose)
        }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { "verbose" => true })
      refute result.success?
      assert_includes result.errors.first, "no selections"
    end

    it "returns a clear result when the operation can't be found" do
      query = <<~GRAPHQL
        query One { greeting }
        query Two { secret }
      GRAPHQL

      result = GraphQL::Specialize.call(SpecializeTestSchema, query)
      refute result.success?
      assert_includes result.errors.first, "operation name"

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, operation_name: "Three")
      refute result.success?
      assert_includes result.errors.first, "Three"

      result = GraphQL::Specialize.call(SpecializeTestSchema, query, operation_name: "Two")
      assert result.success?
      assert_includes result.query_string, "secret"
      refute_includes result.query_string, "greeting"
    end
  end

  describe "execution equivalence" do
    it "produces the same data, errors, and resolver calls as the original query" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!, $name: String, $ep: EpisodeEnum, $flag: Boolean!) {
          greeting(name: $name)
          secret @include(if: $verbose)
          episodeName(episode: $ep)
          broken(flag: $flag)
          ...Extras @skip(if: $verbose)
        }

        fragment Extras on Query {
          search(filter: { query: "from-fragment" })
        }
      GRAPHQL

      all_variables = { "verbose" => true, "name" => "Ruby", "ep" => "EMPIRE", "flag" => false }
      bound = { "verbose" => true, "ep" => "EMPIRE" }
      result, original_response, specialized_response, original_calls, specialized_calls =
        run_both(query, all_variables, bound)

      assert_same_execution(original_response, specialized_response, original_calls, specialized_calls)
      assert_equal ["name", "flag"], result.variables
      assert_equal({ "greeting" => "Hello, Ruby", "secret" => "shh", "episodeName" => "EMPIRE", "broken" => "fine" }, specialized_response.to_h["data"])
    end

    it "matches when errors are raised in both runs" do
      query = <<~GRAPHQL
        query GetStuff($verbose: Boolean!, $flag: Boolean!) {
          greeting
          broken(flag: $flag)
          secret @include(if: $verbose)
        }
      GRAPHQL

      all_variables = { "verbose" => false, "flag" => true }
      bound = { "verbose" => false }
      _result, original_response, specialized_response, original_calls, specialized_calls =
        run_both(query, all_variables, bound)

      assert_same_execution(original_response, specialized_response, original_calls, specialized_calls)
      assert_equal "boom", specialized_response.to_h["errors"].first["message"]
    end

    it "matches for mutations with pruned top-level fields" do
      query = <<~GRAPHQL
        mutation DoSteps($skipSecond: Boolean!, $note: String) {
          firstStep(note: $note)
          secondStep @skip(if: $skipSecond)
          thirdStep
        }
      GRAPHQL

      all_variables = { "skipSecond" => true, "note" => "hi" }
      bound = { "skipSecond" => true }
      _result, original_response, specialized_response, original_calls, specialized_calls =
        run_both(query, all_variables, bound)

      assert_same_execution(original_response, specialized_response, original_calls, specialized_calls)
      assert_equal [[:first_step, "hi"], [:third_step]], specialized_calls
    end
  end

  describe "inputs" do
    it "accepts a GraphQL::Query" do
      query = GraphQL::Query.new(SpecializeTestSchema, "query GetStuff($verbose: Boolean!) { secret @include(if: $verbose) greeting }")
      result = GraphQL::Specialize.call(SpecializeTestSchema, query, variables: { verbose: true })
      assert result.success?, result.errors.inspect
      assert_includes result.query_string, "secret"
      refute_includes result.query_string, "@include"
    end

    it "accepts a parsed document" do
      document = GraphQL.parse("query GetStuff($verbose: Boolean!) { secret @include(if: $verbose) greeting }")
      result = GraphQL::Specialize.call(SpecializeTestSchema, document, variables: { "verbose" => false })
      assert result.success?, result.errors.inspect
      refute_includes result.query_string, "secret"
    end

    it "returns a clear result for unparseable input" do
      result = GraphQL::Specialize.call(SpecializeTestSchema, "query {", variables: {})
      refute result.success?
      assert result.errors.any?
    end
  end
end
