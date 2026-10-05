# frozen_string_literal: true
require "spec_helper"
require "json"

describe GraphQL::Testing::QueryGenerator do
  class QueryGeneratorSchema < GraphQL::Schema
    class Flavor < GraphQL::Schema::Enum
      graphql_name "Flavor"
      value "VANILLA"
      value "CHOCOLATE"
    end

    class DateScalar < GraphQL::Schema::Scalar
      graphql_name "Date"
      def self.coerce_input(value, ctx)
        value
      end

      def self.coerce_result(value, ctx)
        value
      end
    end

    class ToppingInput < GraphQL::Schema::InputObject
      argument :name, String, required: true
      argument :sprinkles, Integer, required: false, default_value: 3
    end

    # `LoopInputA` and `LoopInputB` require each other non-null,
    # so no finite value can ever be constructed for them.
    class LoopInputA < GraphQL::Schema::InputObject
      argument :b, "QueryGeneratorSchema::LoopInputB", required: true
      argument :label, String, required: false
    end

    class LoopInputB < GraphQL::Schema::InputObject
      argument :a, LoopInputA, required: true
    end

    class RecipeInput < GraphQL::Schema::InputObject
      argument :title, String, required: true
      argument :flavor, Flavor, required: false, default_value: "VANILLA"
      argument :toppings, [ToppingInput], required: false
      argument :impossible, LoopInputA, required: false
    end

    class Cone < GraphQL::Schema::Object
      field :scoop_count, Integer
    end

    class Cup < GraphQL::Schema::Object
      field :material, String
    end

    class Container < GraphQL::Schema::Union
      possible_types Cone, Cup

      def self.resolve_type(object, ctx)
        object.key?(:material) ? Cup : Cone
      end
    end

    module Named
      include GraphQL::Schema::Interface
      field :name, String
    end

    class Recipe < GraphQL::Schema::Object
      implements Named
      field :flavor, Flavor
      field :topping_names, [String]
      field :container, Container
    end

    class Chef < GraphQL::Schema::Object
      implements Named
      field :years, Integer
    end

    class Query < GraphQL::Schema::Object
      field :recipe, Recipe do
        argument :input, RecipeInput, required: true
        argument :servings, Integer, required: false, default_value: 2
      end
      field :container, Container
      field :named, Named
      field :on_date, String do
        argument :date, DateScalar, required: true
      end
      field :broken, String do
        argument :loop, LoopInputA, required: true
      end
      field :echo, String do
        argument :flavor, Flavor, required: false, default_value: "CHOCOLATE"
        argument :tags, [String], required: false
      end

      def recipe(input:, servings: 2)
        {
          name: "#{input[:title]} for #{servings}",
          flavor: input[:flavor] || "VANILLA",
          topping_names: (input[:toppings] || []).map { |t| t[:name] },
          container: { material: "waffle" },
        }
      end

      def container
        { scoop_count: 3 }
      end

      def named
        { name: "Chef Pascal", years: 12 }
      end

      def on_date(date:)
        date
      end

      def broken(loop:)
        raise "This field requires an unconstructible input and must never be selected"
      end

      def echo(flavor: "CHOCOLATE", tags: nil)
        JSON.generate({ flavor: flavor, tags: tags })
      end
    end

    class Mutation < GraphQL::Schema::Object
      field :set_flavor, Flavor do
        argument :flavor, Flavor, required: true
      end

      def set_flavor(flavor:)
        flavor
      end
    end

    module Named
      def self.resolve_type(object, ctx)
        object.key?(:years) ? Chef : Recipe
      end
    end

    query Query
    mutation Mutation
    orphan_types Chef
  end

  SCALAR_SAMPLES = { "Date" => "2026-10-05" }

  def generate_result(seed:, **options)
    GraphQL::Testing::QueryGenerator.new(
      QueryGeneratorSchema,
      seed: seed,
      scalar_samples: SCALAR_SAMPLES,
      **options
    ).generate
  end

  def selection_depth(node)
    return 0 if node.selections.empty?
    1 + node.selections.map { |child| selection_depth(child) }.max
  end

  def each_leaf(value, &block)
    case value
    when Hash
      value.each_value { |v| each_leaf(v, &block) }
    when Array
      value.each { |v| each_leaf(v, &block) }
    else
      yield value
    end
  end

  def collect_arrays(value, arrays = [])
    case value
    when Hash
      value.each_value { |v| collect_arrays(v, arrays) }
    when Array
      arrays << value
      value.each { |v| collect_arrays(v, arrays) }
    end
    arrays
  end

  it "generates operations that pass static validation and execute without errors" do
    25.times do |seed|
      result = generate_result(seed: seed)
      errors = QueryGeneratorSchema.validate(result.query)
      assert_equal [], errors.map(&:message), "seed #{seed}: #{result.query}"

      exec_result = QueryGeneratorSchema.execute(result.query, variables: result.variables).to_h
      assert_nil exec_result["errors"], "seed #{seed}: #{result.query} with #{result.variables.inspect}"
      refute_nil exec_result["data"]
    end
  end

  it "is deterministic for a fixed seed" do
    first = generate_result(seed: 123)
    second = generate_result(seed: 123)
    assert_equal first.query, second.query
    assert_equal first.variables, second.variables

    other = generate_result(seed: 124)
    refute_equal first.query, other.query
  end

  it "never selects fields or arguments that require unconstructible non-null recursive inputs" do
    25.times do |seed|
      result = generate_result(seed: seed)
      refute_includes result.query, "broken"
      refute_includes result.query, "loop"
      refute_includes result.query, "impossible"
      each_leaf(result.variables) do |leaf|
        refute_nil leaf, "seed #{seed}: nil value generated in #{result.variables.inspect}"
      end
    end
  end

  it "skips fields whose required custom scalar arguments have no caller-provided sample" do
    10.times do |seed|
      result = GraphQL::Testing::QueryGenerator.new(QueryGeneratorSchema, seed: seed).generate
      refute_includes result.query, "onDate"

      errors = QueryGeneratorSchema.validate(result.query)
      assert_equal [], errors.map(&:message), "seed #{seed}: #{result.query}"
    end
  end

  it "uses caller-provided samples for custom scalars" do
    saw_on_date = false
    25.times do |seed|
      result = generate_result(seed: seed)
      next unless result.query.include?("onDate")
      saw_on_date = true
      exec_result = QueryGeneratorSchema.execute(result.query, variables: result.variables).to_h
      assert_equal "2026-10-05", exec_result.dig("data", "onDate")
    end
    assert saw_on_date, "expected at least one generated query to select onDate"
  end

  it "selects union and interface fields with inline fragments on possible types" do
    saw_union = false
    saw_interface = false
    25.times do |seed|
      result = generate_result(seed: seed)
      if result.query.match?(/container\s*[({]/)
        saw_union = true
        assert_match(/\.\.\. on (Cone|Cup)/, result.query)
      end
      if result.query.match?(/named\s*[({]/)
        saw_interface = true
        assert_match(/\.\.\. on (Recipe|Chef)/, result.query)
      end
    end
    assert saw_union, "expected at least one generated query to select container"
    assert saw_interface, "expected at least one generated query to select named"
  end

  it "only generates enum values defined by the schema" do
    25.times do |seed|
      result = generate_result(seed: seed)
      result.query.scan(/\$(v\d+): Flavor/).each do |(variable_name)|
        assert_includes ["VANILLA", "CHOCOLATE"], result.variables.fetch(variable_name)
      end
    end
  end

  it "lets schema defaults apply for omitted optional arguments" do
    saw_default = false
    25.times do |seed|
      result = generate_result(seed: seed)
      # `echo` selected without its optional `flavor` argument:
      next unless result.query.match?(/echo(\s*{|\s*$|\s+[a-zA-Z])/)
      saw_default = true
      exec_result = QueryGeneratorSchema.execute(result.query, variables: result.variables).to_h
      echoed = JSON.parse(exec_result.dig("data", "echo"))
      assert_equal "CHOCOLATE", echoed["flavor"]
    end
    assert saw_default, "expected at least one generated query to select echo without arguments"
  end

  it "respects the max_depth budget" do
    10.times do |seed|
      shallow = generate_result(seed: seed, max_depth: 0)
      document = GraphQL.parse(shallow.query)
      assert_equal 1, selection_depth(document.definitions.first), "seed #{seed}: #{shallow.query}"

      deep = generate_result(seed: seed, max_depth: 2)
      document = GraphQL.parse(deep.query)
      assert_operator selection_depth(document.definitions.first), :<=, 3, "seed #{seed}: #{deep.query}"
    end
  end

  it "respects the max_list_length budget" do
    25.times do |seed|
      result = generate_result(seed: seed, max_list_length: 0)
      collect_arrays(result.variables).each do |array|
        assert_empty array, "seed #{seed}: #{result.variables.inspect}"
      end

      result = generate_result(seed: seed, max_list_length: 1)
      collect_arrays(result.variables).each do |array|
        assert_operator array.size, :<=, 1, "seed #{seed}: #{result.variables.inspect}"
      end
    end
  end

  it "generates mutations" do
    5.times do |seed|
      result = GraphQL::Testing::QueryGenerator.new(QueryGeneratorSchema, seed: seed).generate(operation_type: :mutation)
      assert_match(/\Amutation /, result.query)
      errors = QueryGeneratorSchema.validate(result.query)
      assert_equal [], errors.map(&:message), "seed #{seed}: #{result.query}"
      exec_result = QueryGeneratorSchema.execute(result.query, variables: result.variables).to_h
      assert_nil exec_result["errors"]
      assert_includes ["VANILLA", "CHOCOLATE"], exec_result.dig("data", "setFlavor")
    end
  end

  it "raises for operation types the schema doesn't support" do
    error = assert_raises(ArgumentError) do
      GraphQL::Testing::QueryGenerator.new(QueryGeneratorSchema, seed: 1).generate(operation_type: :subscription)
    end
    assert_match(/no subscription root type/, error.message)
  end
end
