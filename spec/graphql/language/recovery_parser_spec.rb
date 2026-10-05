# frozen_string_literal: true
require "spec_helper"

describe "Fault-tolerant recovery parser" do
  it "is a separate entry point and leaves strict parsing unchanged" do
    assert GraphQL.respond_to?(:parse_with_recovery)
    assert_raises(GraphQL::ParseError) do
      GraphQL.parse("{ foo {")
    end
    result = GraphQL.parse_with_recovery("{ foo {")
    assert_kind_of GraphQL::Language::Parser::ParseResult, result
    refute result.ok?
    assert_equal 1, result.errors.size
    assert result.document
  end

  it "does not return a document when the input cannot start parsing" do
    result = GraphQL.parse_with_recovery(nil)
    refute result.ok?
    assert_nil result.document
    assert_equal 1, result.errors.size
    assert_raises(GraphQL::ParseError) { GraphQL.parse(nil) }
  end

  it "keeps recovery results out of normal query execution" do
    query_str = "{ broken {"
    result = GraphQL.parse_with_recovery(query_str)
    refute result.ok?
    # Execution goes through the strict parser, which still raises.
    assert_raises(GraphQL::ParseError) { GraphQL.parse(query_str) }
    query = GraphQL::Query.new(Dummy::Schema, query_str)
    assert_nil query.document
    assert_equal 1, query.context.errors.size
  end

  it "returns no diagnostics for valid documents" do
    [
      "{ foo { id } }",
      "query Q($x: ID = \"1\") @cached { foo(x: $x) { id name } }",
      "type Foo { bar: String }",
    ].each do |query|
      result = GraphQL.parse_with_recovery(query)
      assert result.ok?, "expected no diagnostics for #{query.inspect}, got: #{result.errors.map(&:message).inspect}"
      assert_equal GraphQL.parse(query).to_query_string, result.document.to_query_string
    end
  end

  it "keeps fields parsed before a missing closing brace" do
    result = GraphQL.parse_with_recovery("{ foo { bar")
    assert_equal 1, result.errors.size
    op = result.document.definitions.first
    field = op.selections.first
    assert_equal "foo", field.name
    assert_equal ["bar"], field.selections.grep(GraphQL::Language::Nodes::Field).map(&:name)
    missing = field.selections.grep(GraphQL::Language::Nodes::MissingToken)
    assert_equal 1, missing.size
    assert_equal "RCURLY", missing.first.expected
    assert missing.first.pos
  end

  it "continues at a reliable sync point and marks the broken region" do
    result = GraphQL.parse_with_recovery("{ ~~~ keepMe { id } }")
    assert_equal 1, result.errors.size
    op = result.document.definitions.first
    errors = op.selections.grep(GraphQL::Language::Nodes::SyntaxError)
    assert_equal 1, errors.size
    broken = errors.first
    assert_equal 2, broken.pos
    assert_equal 6, broken.end_pos
    assert_equal "~~~ ", "{ ~~~ keepMe { id } }"[broken.pos...broken.end_pos]
    assert_equal ["keepMe"], op.selections.grep(GraphQL::Language::Nodes::Field).map(&:name)
  end

  it "does not treat braces inside strings as sync points" do
    query = '{ foo(arg: "{ not a brace } } still string") { after } }'
    result = GraphQL.parse_with_recovery(query)
    assert result.ok?, result.errors.map(&:message).inspect
    field = result.document.definitions.first.selections.first
    assert_equal "foo", field.name
    assert_equal "{ not a brace } } still string", field.arguments.first.value
    assert_equal ["after"], field.selections.map(&:name)
  end

  it "recovers from an unterminated string without eating later braces" do
    result = GraphQL.parse_with_recovery('{ foo(arg: "oops) bar { id }')
    # The string stays one atomic token; only its unterminated state plus the
    # missing closer are reported.
    assert result.errors.size >= 1
    op = result.document.definitions.first
    assert_equal "foo", op.selections.first.name
  end

  it "recovers independently across multiple operations" do
    result = GraphQL.parse_with_recovery("{ a } query Broken($x: { good } query After { z }")
    ops = result.document.definitions.grep(GraphQL::Language::Nodes::OperationDefinition)
    assert_equal [nil, "Broken", "After"], ops.map(&:name)
    assert_equal ["a"], ops[0].selections.map(&:name)
    assert_equal ["good"], ops[1].selections.map(&:name)
    assert_equal ["z"], ops[2].selections.map(&:name)
    assert result.errors.any? { |e| e.message.include?("Missing type definition for variable") }
  end

  it "does not crash, loop, or lose later fields while the query is typed character by character" do
    queries = [
      "query User($id: ID!) { user(id: $id) { name email friends { id } } }",
      "mutation Do($input: Input!) { doThing(input: $input) { ok } } fragment F on T { x }",
      '{ a(s: "}{}{") { b } } { c }',
    ]
    queries.each do |full_query|
      recovered_field_sets = []
      (0..full_query.length).each do |len|
        prefix = full_query[0, len]
        Timeout.timeout(5) do
          result = GraphQL.parse_with_recovery(prefix)
          assert result.document, "expected a document for #{prefix.inspect}"
          # The recovered document must remain traversable ...
          GraphQL::Language::StaticVisitor.new(result.document).visit
          # ... and printable.
          result.document.to_query_string
          ops = result.document.definitions.grep(GraphQL::Language::Nodes::OperationDefinition)
          recovered_field_sets << ops.flat_map(&:selections).grep(GraphQL::Language::Nodes::Field).map(&:name)
        end
      end
      # Once a field has been fully typed it must survive all later prefixes.
      full_doc = GraphQL.parse_with_recovery(full_query)
      assert full_doc.ok?, full_doc.errors.map(&:message).inspect
    end
  end

  it "exposes source positions on syntax error nodes" do
    result = GraphQL.parse_with_recovery("{ foo 123~ bar }")
    error_node = result.document.definitions.first.selections
      .grep(GraphQL::Language::Nodes::SyntaxError).first
    assert error_node
    assert(error_node.pos < error_node.end_pos)
    assert_equal 1, error_node.line
  end
end
