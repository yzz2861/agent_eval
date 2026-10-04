# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Execution::NullPropagation do
  class NullPropagationItem < GraphQL::Schema::Object
    field :title, String, null: false, hash_key: :title
  end

  module NullPropagationNode
    include GraphQL::Schema::Interface
    field :title, String, null: false, hash_key: :title
  end

  class NullPropagationThing < GraphQL::Schema::Object
    implements NullPropagationNode
  end

  class NullPropagationQuery < GraphQL::Schema::Object
    field :missing_title, NullPropagationItem, null: true
    field :items, [NullPropagationItem, null: true], null: true
    field :required_items, [NullPropagationItem], null: false
    field :required_item_objects, [NullPropagationItem], null: false
    field :thing, NullPropagationNode, null: true
    field :execution_error, String, null: false, hash_key: :execution_error
  end

  class NullPropagationSchema < GraphQL::Schema
    query(NullPropagationQuery)
    orphan_types(NullPropagationThing)

    def self.resolve_type(_type, _object, _context)
      NullPropagationThing
    end
  end

  class NullPropagationNextSchema < NullPropagationSchema
    use GraphQL::Execution::Next
  end

  ROOT_VALUE = OpenStruct.new(
    missing_title: {},
    items: [{ title: "first" }, nil, { title: "third" }, {}],
    required_items: nil,
    required_item_objects: [nil],
    thing: {},
    execution_error: GraphQL::ExecutionError.new("ordinary failure"),
  )

  def execute(schema, query, context = {}, root_value = ROOT_VALUE)
    if schema.respond_to?(:execute_next)
      schema.execute_next(query, context: context, root_value: root_value)
    else
      schema.execute(query, context: context, root_value: root_value)
    end
  end

  it "is disabled unless explicitly enabled" do
    result = execute(NullPropagationNextSchema, "{ missingTitle { title } }")

    refute result.key?("extensions")
  end

  it "ignores ordinary execution errors" do
    result = execute(
      NullPropagationSchema,
      "{ executionError }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true }
    )

    assert_equal ["ordinary failure"], result["errors"].map { |error| error["message"] }
    refute result.key?("extensions")
  end

  it "records the origin, non-null wrappers, and stopping response path" do
    result = execute(
      NullPropagationNextSchema,
      "{ aliased: missingTitle { aliasedTitle: title } }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true }
    )

    assert_equal({
      "data" => { "aliased" => nil },
      "errors" => [{
        "message" => "Cannot return null for non-nullable field NullPropagationItem.title",
        "path" => ["aliased", "aliasedTitle"],
        "locations" => [{ "line" => 1, "column" => 27 }],
      }],
      "extensions" => {
        "nullPropagation" => {
          "traces" => [{
            "origin" => {
              "path" => ["aliased", "aliasedTitle"],
              "parentType" => "NullPropagationItem",
              "fieldName" => "title",
              "kind" => "FIELD",
              "type" => "String!",
            },
            "wrappers" => [{
              "path" => ["aliased", "aliasedTitle"],
              "kind" => "FIELD",
              "type" => "String!",
            }],
            "stopPath" => ["aliased"],
          }],
        },
      },
    }, result.to_h)
  end

  it "distinguishes non-null list elements from non-null lists" do
    list_result = execute(
      NullPropagationNextSchema,
      "{ items { title } }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true }
    )
    list_element_result = execute(
      NullPropagationNextSchema,
      "{ requiredItemObjects { title } }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true }
    )
    required_list_result = execute(
      NullPropagationNextSchema,
      "{ requiredItems { title } }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true },
      ROOT_VALUE.dup.tap { |root_value| root_value.required_items = nil }
    )

    list_trace = list_result["extensions"]["nullPropagation"]["traces"].first
    list_element_trace = list_element_result["extensions"]["nullPropagation"]["traces"].first
    required_list_trace = required_list_result["extensions"]["nullPropagation"]["traces"].first

    assert_equal([
      { "path" => ["items", 3, "title"], "kind" => "FIELD", "type" => "String!" },
    ], list_trace["wrappers"])
    assert_equal(["items", 3], list_trace["stopPath"])
    assert_nil(list_result["data"]["items"][3])

    assert_equal([
      { "path" => ["requiredItemObjects"], "kind" => "LIST", "type" => "[NullPropagationItem!]!" },
      { "path" => ["requiredItemObjects", 0], "kind" => "LIST_ELEMENT", "type" => "NullPropagationItem!" },
    ], list_element_trace["wrappers"])
    assert_equal([], list_element_trace["stopPath"])
    assert_nil(list_element_result["data"])

    assert_equal([{
      "path" => ["requiredItems"],
      "kind" => "LIST",
      "type" => "[NullPropagationItem!]!",
    }], required_list_trace["wrappers"])
    assert_equal([], required_list_trace["stopPath"])
    assert_nil(required_list_result["data"])
  end

  it "keeps separate causes when one ancestor receives several errors" do
    schema = Class.new(NullPropagationSchema)
    root_value = OpenStruct.new(items: [{}, {}])

    result = execute(
      schema,
      "{ items { title } }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true },
      root_value
    )

    assert_equal [["items", 0, "title"], ["items", 1, "title"]], result["errors"].map { |error| error["path"] }
    assert_equal [["items", 0, "title"], ["items", 1, "title"]], result["extensions"]["nullPropagation"]["traces"].map { |trace| trace["origin"]["path"] }
  end

  it "supports the legacy interpreter" do
    result = execute(
      NullPropagationSchema,
      "{ aliased: missingTitle { aliasedTitle: title } }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true }
    )
    trace = result["extensions"]["nullPropagation"]["traces"].first
    assert_equal(["aliased", "aliasedTitle"], trace["origin"]["path"])
    assert_equal("FIELD", trace["origin"]["kind"])
    assert_equal(["aliased", "aliasedTitle"], trace["wrappers"].first["path"])
    assert_equal(["aliased"], trace["stopPath"])
  end

  it "follows aliases through concrete fragment types" do
    result = execute(
      NullPropagationSchema,
      "{ thing { ...ThingFields } } fragment ThingFields on NullPropagationThing { aliasedTitle: title }",
      { GraphQL::Execution::NullPropagation::CONTEXT_KEY => true }
    )

    trace = result["extensions"]["nullPropagation"]["traces"].first
    assert_equal(["thing", "aliasedTitle"], trace["origin"]["path"])
    assert_equal("title", trace["origin"]["fieldName"])
    assert_equal(["thing"], trace["stopPath"])
  end
end
