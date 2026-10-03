# frozen_string_literal: true

RSpec.describe Dry::Types::Recursive do
  module Types
    include Dry.Types()
  end

  let(:tree_type) do
    Types::Recursive(:node) do |node|
      Types::Hash.schema(
        value: Types::Integer,
        children: Types::Array.of(node)
      )
    end
  end

  def leaf(value = 1)
    { value: value, children: [] }
  end

  describe "definition" do
    it "does not require the full graph to be expanded while defining" do
      type = Types::Recursive(:node) do |node|
        Types::Hash.schema(
          value: Types::Integer,
          children: Types::Array.of(node)
        )
      end

      # building the root declaration is enough; nested refs are lazy
      expect(type).to be_a(Dry::Types::Recursive::Root)
      expect(type.name).to be(:node)
    end

    it "supports mutually referencing types" do
      pair_ref = nil
      node_ref = nil
      type = Types::Recursive { |t|
        pair_ref = t.declare(:pair) { |pair|
          Types::Hash.schema(
            head: node_ref,
            tail: Types::Array.of(pair).optional
          )
        }

        node_ref = t.declare(:node) {
          Types::Hash.schema(payload: Types::Integer)
        }
        pair_ref
      }

      input = {
        head: { payload: 2 },
        tail: [{ head: { payload: 3 }, tail: nil }]
      }

      expect(type.(input)).to eql(input)
    end
  end

  describe "#call / #try on finite trees" do
    it "applies a finite tree" do
      input = { value: 1, children: [leaf(2), leaf(3)] }
      expect(tree_type.(input)).to eql(input)
    end

    it "handles a deep tree without stack overflow for the cycles" do
      input = leaf
      200.times { input = { value: 1, children: [input] } }

      expect(tree_type.(input)).to eql(input)
    end

    it "accepts a shared, acyclic sub-object appearing more than once" do
      shared = leaf(9)
      input = { value: 1, children: [shared, shared, shared] }

      expect { tree_type.(input) }.not_to raise_error
      expect(tree_type.(input)).to eql(input)
    end

    it "coerces values through the recursive members" do
      coercible = Types::Recursive(:node) do |node|
        Types::Hash.schema(
          value: Types::Coercible::Integer,
          children: Types::Array.of(node)
        )
      end

      input = { value: "1", children: [{ value: "2", children: [] }] }
      expect(coercible.(input)).to eql(
        { value: 1, children: [{ value: 2, children: [] }] }
      )
    end

    it "reports type mismatches in nested nodes" do
      input = { value: 1, children: [{ value: "nope", children: [] }] }
      expect { tree_type.(input) }.to raise_error(Dry::Types::SchemaError)
    end

    it "returns a failure for #try on invalid finite input" do
      input = { value: 1, children: [{ value: "nope", children: [] }] }
      expect(tree_type.try(input)).to be_failure
    end

    it "returns a success for #try on valid input" do
      expect(tree_type.try(leaf)).to be_success
    end

    it "supports #valid?" do
      expect(tree_type).to be_valid(leaf)
      expect(tree_type).not_to be_valid("not a tree")
    end
  end

  describe "cyclic input" do
    it "raises a CircularStructureError with a path instead of overflowing" do
      cyclic = leaf
      cyclic[:children] << cyclic

      error = begin
        tree_type.(cyclic)
      rescue => e
        e
      end

      expect(error).to be_a(Dry::Types::CircularStructureError)
      expect(error.message).to include("$.children[0].node")
      expect(error.path).to eql("$.children[0].node")
    end

    it "detects a self-referencing array value" do
      type = Types::Recursive(:seq) do |seq|
        Types::Array.of(seq) | Types::Integer
      end

      cyclic = []
      cyclic << cyclic

      expect { type.(cyclic) }.to raise_error(
        Dry::Types::CircularStructureError, /cyclic structure/
      )
    end

    it "detects a nested key cycle with the matching path" do
      type = Types::Recursive(:box) do |box|
        Types::Hash.schema(inner: box.optional)
      end

      cyclic = { inner: nil }
      cyclic[:inner] = cyclic

      error = begin
        type.(cyclic)
      rescue Dry::Types::CircularStructureError => e
        e
      end

      expect(error.path).to eql("$.inner.box")
    end

    it "returns a failure (not a stack overflow) from #try" do
      cyclic = leaf
      cyclic[:children] << cyclic

      result = tree_type.try(cyclic)
      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::CircularStructureError)
    end

    it "supports a block on #try for cyclic input" do
      cyclic = leaf
      cyclic[:children] << cyclic

      yielded = nil
      tree_type.try(cyclic) { |failure| yielded = failure }
      expect(yielded).to be_failure
      expect(yielded.error).to be_a(Dry::Types::CircularStructureError)
    end

    it "does not blow the stack for a cyclic object under #call" do
      cyclic = leaf
      cyclic[:children] << cyclic

      expect { tree_type.(cyclic) }.to raise_error(
        Dry::Types::CircularStructureError
      )
    end
  end

  describe "invalid recursive type definitions (alias cycles)" do
    it "rejects a self-referencing alias that never reaches an entity type" do
      type = Types::Recursive(:a) { |a| a }

      expect { type.(1) }.to raise_error(
        Dry::Types::RecursiveAliasError, /a -> a/
      )
    end

    it "rejects a mutual alias cycle" do
      type = Types::Recursive { |t|
        t.declare(:a) { |_a, d| d[:b] }
        t.declare(:b) { |_b, d| d[:a] }
      }

      expect { type.(1) }.to raise_error(
        Dry::Types::RecursiveAliasError, /a -> b -> a/
      )
    end

    it "rejects alias cycles when compiling the AST" do
      type = Types::Recursive(:a) { |a| a }
      expect { type.to_ast }.to raise_error(Dry::Types::RecursiveAliasError)
    end

    it "accepts a recursive branch that eventually reaches an entity type" do
      type = Types::Recursive(:x) { |x| Types::Integer | x }
      expect(type.(5)).to be(5)
    end

    it "rejects an indirect alias with a grounded sibling that never lands" do
      type = Types::Recursive { |t|
        t.declare(:b) { |_b, d| Types::Integer | d[:a] }
        t.declare(:a) { |_a, d| d[:b] }
      }

      # b is grounded through Integer, so a (alias to b) is usable as integer
      expect(type.(7)).to be(7)
    end
  end

  describe "caching" do
    it "resolves each declaration once and reuses the result" do
      calls = 0
      type = Types::Recursive(:node) do |node|
        calls += 1
        Types::Hash.schema(
          value: Types::Integer,
          children: Types::Array.of(node)
        )
      end

      type.(leaf)
      type.(leaf(2))
      type.(leaf(3))
      expect(calls).to be(1)
    end
  end

  describe "AST" do
    it "emits a self-describing recursive node" do
      ast = tree_type.to_ast
      tag, body = ast

      expect(tag).to be(:recursive)
      root_name, declarations, = body
      expect(root_name).to be(:node)
      expect(declarations.map { |d| d[0] }).to eql(%i[declaration])

      # references inside a declaration body are bare refs
      ref_nodes = each_node(declarations).select { |node| node[0] == :ref }
      expect(ref_nodes).not_to be_empty
      expect(ref_nodes.map { |n| n[1][0] }).to all(eq(:node))
    end

    it "round-trips through the compiler" do
      compiled = Dry::Types::Compiler.new(Dry::Types).(tree_type.to_ast)

      expect(compiled).to be_a(Dry::Types::Recursive::Root)
      expect(compiled.(leaf)).to eql(leaf)
    end

    it "the compiled type keeps cyclic-input protection" do
      compiled = Dry::Types::Compiler.new(Dry::Types).(tree_type.to_ast)
      cyclic = leaf
      cyclic[:children] << cyclic

      expect { compiled.(cyclic) }.to raise_error(
        Dry::Types::CircularStructureError
      )
    end

    it "round-trips mutually referencing types" do
      pair_ref = nil
      node_ref = nil
      type = Types::Recursive { |t|
        node_ref = t.declare(:node) { Types::Integer }
        pair_ref = t.declare(:pair) { |pair|
          Types::Hash.schema(head: node_ref, tail: Types::Array.of(pair).optional)
        }
        pair_ref
      }

      compiled = Dry::Types::Compiler.new(Dry::Types).(type.to_ast)
      input = { head: 1, tail: [] }
      expect(compiled.(input)).to eql(input)
    end
  end

  describe "printing" do
    it "prints the recursive entry without expanding the graph" do
      expect(tree_type.to_s).to eql("#<Dry::Types[Recursive(:node)]>")
    end

    it "prints a lazy reference" do
      ref = nil
      Types::Recursive { |t|
        ref = t.declare(:node) { |node|
          Types::Hash.schema(children: Types::Array.of(node))
        }
      }

      expect(ref.to_s).to eql("#<Dry::Types[Recursive[:node]]>")
    end
  end

  def each_node(ast)
    return [] unless ast.is_a?(::Array)

    if ast[0].is_a?(::Symbol) && ast.size == 2 && ast[1].is_a?(::Array)
      [ast] + ast[1].flat_map { |child| each_node(child) }
    else
      ast.flat_map { |child| each_node(child) }
    end
  end
end
