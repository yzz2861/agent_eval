# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Execution::Interpreter::NullPropagationTrace do
  class NullPropagationTestSchema < GraphQL::Schema
    class DeepObject < GraphQL::Schema::Object
      field :required_name, String, null: false
      def required_name
        nil
      end
    end

    class ItemObject < GraphQL::Schema::Object
      field :required_name, String, null: false
      def required_name
        nil
      end

      field :required_deep, DeepObject, null: false
      def required_deep
        {}
      end
    end

    class BoxObject < GraphQL::Schema::Object
      field :items, [ItemObject, null: false], null: true
      def items
        [{}, {}]
      end

      field :aliased_single, ItemObject, null: true
      def aliased_single
        {}
      end

      field :required_items, [ItemObject, null: false], null: false
      def required_items
        [{}]
      end

      field :required_list_that_is_nil, [ItemObject], null: false
      def required_list_that_is_nil
        nil
      end

      field :twins, [ItemObject, null: false], null: true
      def twins
        [{}, {}]
      end

      field :first_required, ItemObject, null: true
      def first_required
        {}
      end

      field :second_required, ItemObject, null: true
      def second_required
        {}
      end
    end

    class Query < GraphQL::Schema::Object
      class RequestIdExtension < GraphQL::Schema::FieldExtension
        def after_resolve(value:, context:, **_rest)
          context.response_extensions["requestId"] = "req-123"
          value
        end
      end

      field :request_id, String, null: true, extensions: [RequestIdExtension]
      def request_id
        "ignored"
      end

      field :nullable_box, BoxObject, null: true
      def nullable_box
        {}
      end

      field :required_box, BoxObject, null: false
      def required_box
        {}
      end
    end

    query Query
  end

  def execute(query_str, **context)
    NullPropagationTestSchema.execute(query_str, context: context)
  end

  it "is not collected unless explicitly enabled" do
    result = execute("{ nullableBox { items { requiredName } } }")
    refute result.to_h.key?("extensions")
  end

  it "records the origin field, crossed non-null wrappers and the nullable stop" do
    result = execute("{ nullableBox { items { requiredName } } }", null_propagation_diagnostics: true)

    assert_nil result["data"]["nullableBox"]["items"]
    assert_equal [
      {
        "origin" => {
          "path" => ["nullableBox", "items", 0, "requiredName"],
          "field" => "ItemObject.requiredName",
          "kind" => "FIELD",
          "type" => "String!",
        },
        "wrappers" => [
          { "path" => ["nullableBox", "items", 0], "kind" => "LIST_ELEMENT", "type" => "ItemObject!" },
        ],
        "stop" => { "at" => "NULLABLE", "path" => ["nullableBox", "items"] },
      },
    ], result["extensions"]["nullPropagation"]
  end

  it "uses the client-visible alias in every path" do
    result = execute("{ nullableBox { chosen: aliasedSingle { requiredDeep { requiredName } } } }", null_propagation_diagnostics: true)

    trace = result["extensions"]["nullPropagation"].first
    assert_equal ["nullableBox", "chosen", "requiredDeep", "requiredName"], trace["origin"]["path"]
    assert_equal [["nullableBox", "chosen", "requiredDeep"]], trace["wrappers"].map { |w| w["path"] }
    assert_equal ["nullableBox", "chosen"], trace["stop"]["path"]
  end

  it "distinguishes a non-null list element from a non-null list itself" do
    result = execute("{ nullableBox { requiredListThatIsNil { requiredName } } }", null_propagation_diagnostics: true)

    trace = result["extensions"]["nullPropagation"].first
    assert_equal "LIST", trace["origin"]["kind"]
    assert_equal "[ItemObject!]!", trace["origin"]["type"]
    assert_equal ["nullableBox", "requiredListThatIsNil"], trace["origin"]["path"]
    assert_equal [], trace["wrappers"]
    assert_equal({ "at" => "NULLABLE", "path" => ["nullableBox"] }, trace["stop"])
  end

  it "stops a failed non-null element at the nullable list itself" do
    result = execute("{ nullableBox { twins { requiredName } } }", null_propagation_diagnostics: true)

    assert_nil result["data"]["nullableBox"]["twins"]
    trace = result["extensions"]["nullPropagation"].first
    assert_equal ["nullableBox", "twins", 0, "requiredName"], trace["origin"]["path"]
    assert_equal "FIELD", trace["origin"]["kind"]
    assert_equal [{ "path" => ["nullableBox", "twins", 0], "kind" => "LIST_ELEMENT", "type" => "ItemObject!" }], trace["wrappers"]
    assert_equal({ "at" => "NULLABLE", "path" => ["nullableBox", "twins"] }, trace["stop"])
  end

  it "keeps separate reasons when multiple sibling fields affect the same ancestor" do
    result = execute("{ nullableBox { firstRequired { requiredName } secondRequired { requiredName } } }", null_propagation_diagnostics: true)

    traces = result["extensions"]["nullPropagation"]
    assert_equal 2, traces.size
    origins = [["nullableBox", "firstRequired", "requiredName"], ["nullableBox", "secondRequired", "requiredName"]]
    assert_equal origins, traces.map { |t| t["origin"]["path"] }
    assert_equal ["nullableBox", "nullableBox"], traces.map { |t| t["stop"]["path"][0] }
  end

  it "stops at the root and nulls data when every wrapper is non-null" do
    result = execute("{ requiredBox { requiredItems { requiredDeep { requiredName } } } }", null_propagation_diagnostics: true)

    assert_nil result["data"]
    trace = result["extensions"]["nullPropagation"].first
    assert_equal ["requiredBox", "requiredItems", 0, "requiredDeep", "requiredName"], trace["origin"]["path"]
    assert_equal [
      ["requiredBox", "requiredItems", 0, "requiredDeep"],
      ["requiredBox", "requiredItems", 0],
      ["requiredBox", "requiredItems"],
      ["requiredBox"],
    ], trace["wrappers"].map { |w| w["path"] }
    assert_equal ["FIELD", "LIST_ELEMENT", "LIST", "FIELD"], trace["wrappers"].map { |w| w["kind"] }
    assert_equal ["DeepObject!", "ItemObject!", "[ItemObject!]!", "BoxObject!"], trace["wrappers"].map { |w| w["type"] }
    assert_equal({ "at" => "ROOT", "path" => [] }, trace["stop"])
  end

  it "keeps standard data and errors unchanged and coexists with other extensions" do
    query_str = "{ requestId nullableBox { items { requiredName } } }"
    enabled = execute(query_str, null_propagation_diagnostics: true)
    disabled = execute(query_str)

    assert_equal disabled["data"], enabled["data"]
    assert_equal disabled["errors"], enabled["errors"]
    assert enabled["errors"].all? { |error| error.key?("message") && error.key?("path") }
    assert_nil enabled["data"]["nullableBox"]["items"]
    assert_equal "req-123", enabled["extensions"]["requestId"]
    assert enabled["extensions"].key?("nullPropagation")
    assert_equal "req-123", disabled["extensions"]["requestId"]
    refute disabled["extensions"].key?("nullPropagation")
  end

  it "never collects resolved field values" do
    result = execute("{ nullableBox { items { requiredName } } }", null_propagation_diagnostics: true)
    serialized = JSON.generate(result["extensions"]["nullPropagation"])
    refute_match(/\{\}/, serialized)
  end
end
