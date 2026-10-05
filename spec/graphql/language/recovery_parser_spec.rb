# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Language::RecoveryParser do
  def recover(string)
    GraphQL.parse_with_recovery(string)
  end

  def strict_parse(string)
    GraphQL.parse(string)
  end

  describe "entry points" do
    it "is available on GraphQL and on the Parser class" do
      assert_kind_of GraphQL::Language::RecoveryParser::Result, GraphQL.parse_with_recovery("{ a }")
      assert_kind_of GraphQL::Language::RecoveryParser::Result, GraphQL::Language::Parser.parse_with_recovery("{ a }")
    end

    it "returns a valid result with no diagnostics for a complete document" do
      query_string = "query GetUser($id: ID!) { user(id: $id) { name } }"
      result = recover(query_string)
      assert result.valid?
      assert_empty result.diagnostics
      assert_equal strict_parse(query_string).to_query_string, result.document.to_query_string
    end

    it "reports an empty document as a diagnostic rather than raising" do
      result = recover("")
      refute result.valid?
      assert_equal 1, result.diagnostics.size
      assert_kind_of GraphQL::ParseError, result.diagnostics.first
      assert_equal 1, result.diagnostics.first.line
    end
  end

  describe "strict parse isolation" do
    it "still raises GraphQL::ParseError on the first syntax error" do
      ["{ a", "{ a(b: ", "query Q($x ) { a }"] .each do |broken|
        assert_raises(GraphQL::ParseError) { strict_parse(broken) }
        refute recover(broken).valid?
      end
    end

    it "produces nodes that are not mixed into the strict parsing path" do
      result = recover("{ a(b: ")
      assert result.document.definitions.any?
      assert_raises(GraphQL::ParseError) { strict_parse("{ a(b: ") }
    end
  end

  describe "partial AST and diagnostics" do
    it "keeps the completed field when a closing brace is missing" do
      result = recover("{ a")
      assert_equal 1, result.diagnostics.size
      assert_includes result.diagnostics.first.message, "Expected RCURLY"

      operation = result.document.definitions.first
      assert_equal ["a"], operation.selections.map(&:name)

      missing = operation.selections.last
      refute_kind_of GraphQL::Language::Nodes::MissingNode, operation.selections.last
      nodes = flatten(result.document)
      assert nodes.any? { |n| n.is_a?(GraphQL::Language::Nodes::MissingNode) }
    end

    it "emits a missing node for an unclosed argument list" do
      result = recover("{ field(foo: 1")
      messages = result.diagnostics.map(&:message)
      assert(messages.any? { |m| m.include?("Expected RPAREN") })
      assert(messages.any? { |m| m.include?("Expected RCURLY") })

      field = result.document.definitions.first.selections.first
      assert_equal "field", field.name
      assert_equal 1, field.arguments.first.value
      assert flatten(result.document).any?(GraphQL::Language::Nodes::MissingNode)
    end

    it "uses a syntax error node with a source range for a broken span" do
      result = recover("{ ..a }")
      error_node = flatten(result.document).find { |n| n.is_a?(GraphQL::Language::Nodes::SyntaxErrorNode) }
      refute_nil error_node
      assert_equal "..", error_node.token
      assert_equal 2, error_node.pos
      assert_equal 4, error_node.end_pos
      assert_equal [1, 3], [error_node.line, error_node.col]
      assert_equal [1, 5], [error_node.end_line, error_node.end_col]
    end

    it "keeps the field prefix and later operations after recovering from a bad directive" do
      result = recover("{ a @ } { c }")
      operation = result.document.definitions.first
      assert_equal "a", operation.selections.first.name
      assert flatten(result.document).any?(GraphQL::Language::Nodes::SyntaxErrorNode)
      assert_equal ["c"], result.document.definitions.last.selections.map(&:name)
    end

    it "recovers a broken variable definition and keeps the operation" do
      result = recover("query Q($x $y: Int) { a }")
      variables = result.document.definitions.first.variables
      assert variables.any? { |v| v.is_a?(GraphQL::Language::Nodes::SyntaxErrorNode) }
      assert_equal ["y"], variables.select { |v| v.respond_to?(:name) }.map(&:name)
    end

    it "preserves ranges on every diagnostics entry" do
      result = recover("{ a(b: 1 2) }")
      assert(result.diagnostics.size >= 1)
      result.diagnostics.each do |diagnostic|
        assert diagnostic.line >= 1
        assert diagnostic.col >= 1
      end
      error_node = flatten(result.document).find { |n| n.is_a?(GraphQL::Language::Nodes::SyntaxErrorNode) }
      assert_operator error_node.end_pos, :>=, error_node.pos
    end

    it "prints a partial document without raising" do
      ["{ a(b: ", "{ ..a } query R { b }", "query Q($x ) { a }"] .each do |broken|
        printed = recover(broken).document.to_query_string
        assert_kind_of String, printed
      end
    end

    it "can be traversed with visitors" do
      result = recover("{ a(b: 1 2) } { d }")

      static_seen = 0
      static_visitor = Class.new(GraphQL::Language::StaticVisitor) do
        define_method(:on_syntax_error_node) do |node, parent|
          static_seen += 1
          super(node, parent)
        end
      end
      static_visitor.new(result.document).visit
      assert_equal 1, static_seen

      # The error node is attached directly to the argument list.
      field = result.document.definitions.first.selections.grep(GraphQL::Language::Nodes::Field).first
      assert field.arguments.any? { |a| a.is_a?(GraphQL::Language::Nodes::SyntaxErrorNode) }

      visitor = Class.new(GraphQL::Language::Visitor) do
        define_method(:on_syntax_error_node) do |node, parent|
          super(node, parent)
        end
      end
      visitor.new(result.document).visit
    end
  end

  describe "synchronization points" do
    it "does not treat a brace inside a completed string as a synchronization point" do
      query_string = '{ a(b: "x}") { c }'
      result = recover(query_string)
      refute result.valid? # missing closing brace of the operation
      assert_equal 1, result.diagnostics.size
      field = result.document.definitions.first.selections.first
      assert_equal "x}", field.arguments.first.value
      assert_equal ["c"], field.selections.map(&:name)
    end

    it "consumes an unterminated string as one error token and resumes at the next operation" do
      query_string = "query A { a(x: \"open } } query B { b }"
      result = recover(query_string)
      assert(result.diagnostics.size >= 1)

      error_node = flatten(result.document).find { |n| n.is_a?(GraphQL::Language::Nodes::SyntaxErrorNode) && n.token.include?("open") }
      refute_nil error_node
      # The braces inside the string belong to the error token's span
      assert_includes error_node.token, "}"
    end

    it "skips a stray closing brace and continues" do
      result = recover("} { a }")
      assert result.diagnostics.any?
      assert_equal ["a"], result.document.definitions.last.selections.map(&:name)
    end

    it "recovers from a stray unknown character without losing surrounding fields" do
      result = recover("{ a ^ b }")
      assert result.diagnostics.any?
      fields = result.document.definitions.first.selections.grep(GraphQL::Language::Nodes::Field)
      assert_equal ["a", "b"], fields.map(&:name)
      assert flatten(result.document).any?(GraphQL::Language::Nodes::SyntaxErrorNode)
    end
  end

  describe "character-by-character input" do
    DOCUMENTS = [
      "query GetUser($id: ID!) { user(id: $id) { name ...UserFields friends { count } } } fragment UserFields on User { email }",
      'mutation { create(input: { name: "Ada", tags: [1, 2] }) { ok errors } } subscription Watch { tick }',
      '{ q(x: "a}b") { y } query Two { z }',
    ].freeze

    DOCUMENTS.each_with_index do |document, idx|
      it "stays stable for every prefix of document #{idx} (##{document.length + 1} prefixes)" do
        (0..document.length).each do |len|
          prefix = document[0, len]
          result = Timeout.timeout(5) { recover(prefix) }
          assert_kind_of String, result.document.to_query_string
          GraphQL::Language::StaticVisitor.new(result.document).visit
          result.diagnostics.each do |diagnostic|
            assert diagnostic.line >= 1
            assert diagnostic.col >= 1
          end
        end
      end
    end
  end

  describe "multi-operation documents" do
    it "recovers later operations after an error in an earlier one" do
      result = recover("{ a(b: } query B { ok } mutation C { done }")
      names = result.document.definitions.map { |d|
        case d
        when GraphQL::Language::Nodes::OperationDefinition then d.selections.map(&:name)
        else
          nil
        end
      }.compact.flatten
      assert_includes names, "ok"
      assert_includes names, "done"
      assert(result.diagnostics.any?)
    end

    it "keeps both operations when only the final brace is missing" do
      result = recover("query A { a } query B { b")
      operations = result.document.definitions.grep(GraphQL::Language::Nodes::OperationDefinition)
      assert_equal ["A", "B"], operations.map(&:name)
      assert_equal ["a"], operations.first.selections.map(&:name)
      assert_equal ["b"], operations.last.selections.map(&:name)
      assert result.diagnostics.one?
    end

    it "collects several diagnostics for multiple broken spans" do
      result = recover("{ ..a } { ..b }")
      assert_operator result.diagnostics.size, :>=, 2
      error_nodes = flatten(result.document).select { |n| n.is_a?(GraphQL::Language::Nodes::SyntaxErrorNode) }
      assert_operator error_nodes.size, :>=, 2
    end
  end

  def flatten(node)
    nodes = [node]
    node.children.each { |child| nodes.concat(flatten(child)) } if node.is_a?(GraphQL::Language::Nodes::AbstractNode)
    nodes
  end
end
