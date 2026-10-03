# frozen_string_literal: true

RSpec.describe Dry::Types::Recursive do
  subject(:tree_type) do
    described_class.define(:tree) do |tree|
      hash.schema(
        value: integer,
        children: array.of(tree)
      )
    end
  end

  let(:hash) { Dry::Types["nominal.hash"] }
  let(:array) { Dry::Types["nominal.array"] }
  let(:integer) { Dry::Types["nominal.integer"] }

  def build_tree(depth)
    node = {value: 0, children: []}
    leaf = node

    depth.times do |index|
      leaf = {value: index + 1, children: [leaf]}
    end

    leaf
  end

  describe ".define" do
    it "does not build the type graph at definition time" do
      expect(described_class.const_defined?(:Scope)).to be(true)

      built = false
      described_class.define(:late) { |rec|
        built = true
        hash.schema(value: integer, next: rec)
      }

      expect(built).to be(false)
    end

    it "requires a block" do
      expect { described_class.define(:x) }.to raise_error(ArgumentError, /block is required/)
    end
  end

  describe "#call" do
    it "applies the type to a finite tree" do
      data = {
        value: 1,
        children: [
          {value: 2, children: []},
          {value: 3, children: [{value: 4, children: []}]}
        ]
      }

      expect(tree_type.(data)).to eql(data)
    end

    it "handles a deep tree without expanding the graph eagerly" do
      data = build_tree(300)

      expect(tree_type.(data)).to eql(data)
    end

    it "accepts shared but acyclic sub-objects" do
      shared = {value: 9, children: []}
      data = {value: 1, children: [shared, shared, {value: 2, children: [shared]}]}

      expect(tree_type.(data)).to eql(data)
    end

    it "rejects values violating the underlying type" do
      bad = {value: "nope", children: []}

      strict_tree = described_class.define(:strict_tree) do |tree|
        hash.schema(
          value: Dry::Types["strict.integer"],
          children: array.of(tree)
        )
      end

      expect { strict_tree.(bad) }.to raise_error(Dry::Types::CoercionError)
    end

    it "raises CyclicDataError with a path for a self-referencing input" do
      data = {value: 1, children: []}
      data[:children] << data

      expect {
        tree_type.(data)
      }.to raise_error(Dry::Types::CyclicDataError, /\$\.children\[0\]/)
    end

    it "does not blow the stack on a self-referencing input" do
      data = {value: 1, children: []}
      data[:children] << data

      expect {
        tree_type.(data)
      }.to raise_error(Dry::Types::CyclicDataError, /cyclic data/)
    end

    it "detects a cycle nested deeper than one level" do
      a = {value: 1, children: []}
      b = {value: 2, children: [a]}
      a[:children] << b

      expect {
        tree_type.(a)
      }.to raise_error(Dry::Types::CyclicDataError, /\$\.children\[0\]\.children\[0\]/)
    end

    it "detects a direct self-referencing array node" do
      list_type = described_class.define(:list) do |list|
        array.of(list) | integer
      end

      data = [1]
      data << data

      expect {
        list_type.(data)
      }.to raise_error(Dry::Types::CyclicDataError, /\$\[1\]/)
    end

    it "calls the block instead of raising in safe mode" do
      data = {value: 1, children: []}
      data[:children] << data

      expect(tree_type.call(data) { :fallback }).to be(:fallback)
    end
  end

  describe "#try" do
    it "returns a success for valid data" do
      expect(tree_type.try(build_tree(10)).success?).to be(true)
    end

    it "returns a failure carrying the path for cyclic data" do
      data = {value: 1, children: []}
      data[:children] << data

      result = tree_type.try(data)

      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::CyclicDataError)
      expect(result.error.path).to eql("$.children[0]")
    end

    it "yields the failure when given a block" do
      data = {value: 1, children: []}
      data[:children] << data

      yielded = nil
      tree_type.try(data) { |failure| yielded = failure }

      expect(yielded.error).to be_a(Dry::Types::CyclicDataError)
    end
  end

  describe "#valid?" do
    it "is true for valid trees and shared acyclic data" do
      shared = {value: 1, children: []}

      expect(tree_type).to be_valid(build_tree(50))
      expect(tree_type).to be_valid(value: 1, children: [shared, shared])
    end

    it "is false for cyclic data" do
      data = {value: 1, children: []}
      data[:children] << data

      expect(tree_type).not_to be_valid(data)
    end
  end

  describe "#lax" do
    it "returns the original cyclic input instead of raising" do
      data = {value: 1, children: []}
      data[:children] << data

      expect(tree_type.lax.(data)).to equal(data)
    end
  end

  describe "caching" do
    it "resolves the underlying type once and caches it" do
      scope = described_class::Scope.new
      calls = 0
      scope.register(:node) do |current_scope|
        calls += 1
        hash.schema(value: integer, children: array.of(current_scope[:node]))
      end

      type = scope[:node]
      type.(value: 1, children: [])
      type.(value: 2, children: [{value: 3, children: []}])

      expect(calls).to be(1)
      expect(scope.resolve(:node)).to equal(scope.resolve(:node))
    end
  end

  describe "mutual recursion" do
    subject(:mutual) do
      described_class::Scope.new do |scope|
        scope.register(:a) { hash.schema(b: scope[:b]) }
        scope.register(:b) { hash.schema(a: scope[:a].optional) }
      end
    end

    it "applies mutually recursive types" do
      data = {b: {a: {b: {a: nil}}}}

      expect(mutual[:a].(data)).to eql(data)
    end

    it "shares cached resolutions across names" do
      expect(mutual.resolve(:a)).to equal(mutual.resolve(:a))
      expect(mutual.resolve(:b)).to equal(mutual.resolve(:b))
    end

    it "reports the path of a cycle through both names" do
      data = {b: {}}
      data[:b][:a] = data

      expect {
        mutual[:a].(data)
      }.to raise_error(Dry::Types::CyclicDataError, /\$\.b\.a/)
    end

    it "returns a failure from #try for cyclic mutual data" do
      data = {b: {}}
      data[:b][:a] = data

      expect(mutual[:a].try(data)).to be_failure
    end
  end

  describe "alias cycles" do
    it "rejects a direct self-alias that never reaches a concrete type" do
      recursive = described_class.define(:q) { |q| q }

      expect {
        recursive.(1)
      }.to raise_error(Dry::Types::AliasCycleError, /q -> q/)
    end

    it "rejects a mutual alias cycle" do
      scope = described_class::Scope.new do |s|
        s.register(:x) { s[:y] }
        s.register(:y) { s[:x] }
      end

      expect {
        scope[:x].(1)
      }.to raise_error(Dry::Types::AliasCycleError, /x -> y -> x/)
    end

    it "keeps raising on subsequent calls after a failed resolution" do
      scope = described_class::Scope.new do |s|
        s.register(:x) { s[:y] }
        s.register(:y) { s[:x] }
      end

      2.times do
        expect { scope[:x].(1) }.to raise_error(Dry::Types::AliasCycleError)
      end
    end

    it "accepts an alias chain that ends in a concrete type" do
      scope = described_class::Scope.new do |s|
        s.register(:p) { s[:q] }
        s.register(:q) { integer }
      end

      expect(scope[:p].(42)).to be(42)
    end

    it "raises on unknown names" do
      scope = described_class::Scope.new

      expect { scope.resolve(:missing) }.to raise_error(KeyError, /missing/)
    end

    it "prints without raising" do
      scope = described_class::Scope.new do |s|
        s.register(:x) { s[:y] }
        s.register(:y) { s[:x] }
      end

      expect(scope[:x].to_s).to include("Recursive(x)")
      expect(scope[:x].to_s).to include("alias cycle")
    end
  end

  describe "#to_ast" do
    it "emits a recursive node with references on repeat" do
      ast = tree_type.to_ast

      expect(ast[0]).to be(:recursive)

      _scope_id, name, inner_ast, _meta = ast[1]
      expect(name).to be(:tree)

      ref_names = []
      walk = nil
      walk = proc do |value|
        if value.is_a?(::Array)
          ref_names << value[1][1] if value[0] == :recursive_ref && value[1].is_a?(::Array)
          value.each { |child| walk.(child) }
        elsif value.is_a?(::Hash)
          value.each_value { |child| walk.(child) }
        end
      end
      walk.(inner_ast)

      expect(ref_names).to include(:tree)
    end

    it "uses the same scope id for mutually recursive names" do
      scope = described_class::Scope.new do |s|
        s.register(:a) { hash.schema(b: s[:b]) }
        s.register(:b) { hash.schema(a: s[:a]) }
      end

      ast = scope[:a].to_ast
      ids = []
      walk = nil
      walk = proc do |value|
        if value.is_a?(::Array)
          if %i[recursive recursive_ref].include?(value[0]) && value[1].is_a?(::Array)
            ids << value[1][0]
          end
          value.each { |child| walk.(child) }
        elsif value.is_a?(::Hash)
          value.each_value { |child| walk.(child) }
        end
      end
      walk.(ast)

      expect(ids.uniq.size).to be(1)
    end
  end

  describe "AST compilation" do
    subject(:compiler) { Dry::Types::Compiler.new(Dry::Types) }

    it "round-trips a self-recursive type" do
      compiled = compiler.(tree_type.to_ast)
      data = build_tree(20)

      expect(compiled.(data)).to eql(data)
      expect(compiled.to_ast).to eql(tree_type.to_ast)
    end

    it "round-trips mutually recursive types" do
      scope = described_class::Scope.new do |s|
        s.register(:a) { hash.schema(b: s[:b]) }
        s.register(:b) { hash.schema(a: s[:a].optional) }
      end

      compiled = compiler.(scope[:a].to_ast)
      data = {b: {a: {b: {a: nil}}}}

      expect(compiled.(data)).to eql(data)
      expect(compiled.to_ast).to eql(scope[:a].to_ast)
    end

    it "rejects dangling references" do
      ast = [:recursive_ref, ["unknown-scope", :ghost, {}]]

      expect {
        compiler.(ast)
      }.to raise_error(ArgumentError, /unresolved recursive reference :ghost/)
    end

    it "preserves meta through the round-trip" do
      with_meta = tree_type.meta(tag: "tree")
      compiled = compiler.(with_meta.to_ast)

      expect(compiled.meta).to eql(tag: "tree")
      expect(compiled.to_ast).to eql(with_meta.to_ast)
    end
  end

  describe "printing" do
    it "prints the name and the expanded type once" do
      output = tree_type.to_s

      expect(output).to start_with("#<Dry::Types[Recursive(tree)<")
      expect(output).to include("recursive_ref(tree)")
    end

    it "prints mutually recursive types with repeated references" do
      scope = described_class::Scope.new do |s|
        s.register(:a) { hash.schema(b: s[:b]) }
        s.register(:b) { hash.schema(a: s[:a]) }
      end

      output = scope[:a].to_s

      expect(output).to include("Recursive(a)<")
      expect(output).to include("Recursive(b)<")
      expect(output).to include("recursive_ref(a)")
    end
  end

  describe "safe calls on cyclic mutual data" do
    it "supports blocks and lax for mutual recursion" do
      mutual = described_class::Scope.new do |scope|
        scope.register(:a) { hash.schema(b: scope[:b]) }
        scope.register(:b) { hash.schema(a: scope[:a]) }
      end

      data = {b: {}}
      data[:b][:a] = data

      expect(mutual[:a].call(data) { :safe }).to be(:safe)
      expect(mutual[:a].lax.(data)).to equal(data)
    end
  end
end
