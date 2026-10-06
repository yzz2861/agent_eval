# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestProvenance < TestCase
    def load_provenance(yaml, filename: "config.yml")
      Psych.load_with_provenance(yaml, filename: filename)
    end

    def snapshot(node)
      [
        node.class.name,
        (node.anchor if node.respond_to?(:anchor)),
        (node.value if node.respond_to?(:value)),
        (node.children.map { |child| snapshot(child) } if node.respond_to?(:children) && node.children)
      ]
    end

    def test_data_matches_normal_load
      yaml = <<~YAML
        defaults: &defaults
          timeout: 30
        production:
          <<: *defaults
          timeout: 5
      YAML
      result = load_provenance(yaml)
      assert_equal Psych.load(yaml, aliases: true), result.data
    end

    def test_object_sharing_preserved
      yaml = <<~YAML
        a: &a
          x: 1
        b: *a
      YAML
      result = load_provenance(yaml)
      assert_same result.data["a"], result.data["b"]
    end

    def test_direct_declaration
      result = load_provenance("foo: 1\n")
      trace = result.provenance.trace("foo")
      assert_equal 1, trace.size
      assert_equal :declared, trace[0].kind
      assert_equal 1, trace[0].line
    end

    def test_multi_level_merge_chain
      yaml = <<~YAML
        base: &base
          a: 1
        mid: &mid
          <<: *base
          b: 2
        leaf:
          <<: *mid
          c: 3
      YAML
      result = load_provenance(yaml)
      trace = result.provenance.trace("leaf.a")
      assert_equal [:declared, :merged, :merged], trace.map(&:kind)
      assert_equal [nil, "base", "mid"], trace.map(&:anchor)
      assert_equal [2, 4, 7], trace.map(&:line)
    end

    def test_explicit_override_after_merge
      yaml = <<~YAML
        defaults: &defaults
          timeout: 30
        production:
          <<: *defaults
          timeout: 5
      YAML
      result = load_provenance(yaml)
      trace = result.provenance.trace("production.timeout")
      assert_equal [:declared, :merged, :override], trace.map(&:kind)
      assert_equal [2, 4, 5], trace.map(&:line)
      assert_equal "defaults", trace[1].anchor
      assert_equal :override, result.provenance.source("production.timeout").kind
    end

    def test_merge_sequence_priority
      yaml = <<~YAML
        defaults: &defaults
          a: 1
          b: 2
        other: &other
          b: 20
          c: 30
        svc:
          <<: [*defaults, *other]
      YAML
      result = load_provenance(yaml)
      assert_equal 2, result.data["svc"]["b"]
      assert_equal "defaults", result.provenance.source("svc.b").anchor
      assert_equal "other", result.provenance.source("svc.c").anchor
    end

    def test_duplicate_keys
      result = load_provenance("dup:\n  k: 1\n  k: 2\n")
      trace = result.provenance.trace("dup.k")
      assert_equal [:declared, :override], trace.map(&:kind)
      assert_equal [2, 3], trace.map(&:line)
    end

    def test_alias_cycle
      yaml = <<~YAML
        a: &a
          x: 1
          self: *a
      YAML
      result = load_provenance(yaml)
      assert_same result.data["a"], result.data["a"]["self"]
      trace = result.provenance.trace("a.self")
      assert_equal [:aliased], trace.map(&:kind)
      assert_equal "a", trace[0].anchor
    end

    def test_input_nodes_are_not_modified
      yaml = <<~YAML
        defaults: &defaults
          timeout: 30
        production:
          <<: *defaults
      YAML
      ast = Psych.parse(yaml)
      before = snapshot(ast)
      Psych::Provenance.from_ast(ast)
      assert_equal before, snapshot(ast)
    end

    def test_filename_line_column
      result = load_provenance("foo: 1\n", filename: "conf.yml")
      entry = result.provenance.source("foo")
      assert_equal "conf.yml", entry.filename
      assert_equal 1, entry.line
      assert_equal 6, entry.column
      assert_equal "conf.yml:1:6", entry.location
    end

    def test_query_by_array_path_and_sequence_index
      yaml = <<~YAML
        items:
          - name: a
          - name: b
      YAML
      result = load_provenance(yaml)
      assert_equal result.provenance.trace(["items", 1, "name"]),
                     result.provenance.trace("items.1.name")
      assert_equal :declared, result.provenance.source("items.0.name").kind
    end

    def test_unknown_path
      result = load_provenance("foo: 1\n")
      assert_equal [], result.provenance.trace("nope")
      assert_nil result.provenance.source("nope")
      assert_not_include result.provenance.paths, ["nope"]
    end

    def test_inline_mapping_merge
      result = load_provenance("m:\n  <<: {a: 1}\n")
      trace = result.provenance.trace("m.a")
      assert_equal [:declared, :merged], trace.map(&:kind)
      assert_nil trace.last.anchor
    end

    def test_merge_clobbers_earlier_explicit_value
      yaml = <<~YAML
        defaults: &defaults
          b: 2
        svc:
          b: 100
          <<: *defaults
      YAML
      result = load_provenance(yaml)
      assert_equal 2, result.data["svc"]["b"]
      trace = result.provenance.trace("svc.b")
      assert_equal [:declared, :merged], trace.map(&:kind)
      assert_equal "defaults", trace.last.anchor
    end
  end
end
