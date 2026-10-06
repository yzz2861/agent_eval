# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestAliasExpansion < TestCase
    def test_aliases_expand_to_independent_values
      yaml = <<~YAML
        ---
        a: &shared
          nested: value
        b: *shared
      YAML

      result = Psych.safe_load(yaml, aliases: :expand)

      assert_equal(result.fetch("a"), result.fetch("b"))
      refute_same(result.fetch("a"), result.fetch("b"))
    end

    def test_shared_alias_mode_is_unchanged
      yaml = <<~YAML
        ---
        a: &shared
          nested: value
        b: *shared
      YAML

      result = Psych.safe_load(yaml, aliases: true)

      assert_same(result.fetch("a"), result.fetch("b"))
    end

    def test_scalar_aliases_are_independent
      yaml = "---\na: &shared mutable\nb: *shared\n"

      result = Psych.safe_load(yaml, aliases: :expand)
      result.fetch("b").upcase!

      refute_same(result.fetch("a"), result.fetch("b"))
      assert_equal("mutable", result.fetch("a"))
    end

    def test_repeated_non_cyclic_references_are_allowed
      yaml = <<~YAML
        ---
        leaf: &leaf
          value: 1
        branch:
          one: *leaf
          two: *leaf
        another: *leaf
      YAML

      result = Psych.safe_load(yaml, aliases: :expand)
      branch = result.fetch("branch")

      refute_same(branch.fetch("one"), branch.fetch("two"))
      refute_same(branch.fetch("one"), result.fetch("another"))
    end

    def test_merge_keys_expand_aliases
      yaml = <<~YAML
        ---
        defaults: &defaults
          one: 1
          two: 2
        first:
          <<: *defaults
          three: 3
        second:
          <<: *defaults
          three: 4
      YAML

      result = Psych.safe_load(yaml, aliases: :expand)

      assert_equal({"one" => 1, "two" => 2, "three" => 3}, result.fetch("first"))
      assert_equal({"one" => 1, "two" => 2, "three" => 4}, result.fetch("second"))
      refute_same(result.fetch("defaults"), result.fetch("first"))
      refute_same(result.fetch("first"), result.fetch("second"))
    end

    def test_exponentially_expanding_document_is_limited
      yaml = exponential_yaml(6)

      error = assert_raise(Psych::AliasExpansionLimit) do
        Psych.safe_load(yaml, aliases: :expand, max_expanded_nodes: 100,
                        max_expanded_bytes: nil)
      end
      assert_match("expanded nodes", error.message)
    end

    def test_exponentially_expanding_scalar_bytes_are_limited
      yaml = exponential_yaml(6, "abcdefghij")

      error = assert_raise(Psych::AliasExpansionLimit) do
        Psych.safe_load(yaml, aliases: :expand, max_expanded_nodes: nil,
                        max_expanded_bytes: 100)
      end
      assert_match("expanded bytes", error.message)
    end

    def test_exponentially_expanding_document_is_acyclic
      yaml = exponential_yaml(5)

      result = Psych.safe_load(yaml, aliases: :expand, max_expanded_nodes: nil,
                                max_expanded_bytes: nil)

      assert_kind_of(Array, result.fetch("value"))
    end

    def test_limits_apply_before_ruby_objects_are_built
      yaml = exponential_yaml(6)

      assert_raise(Psych::AliasExpansionLimit) do
        Psych.safe_load(yaml, aliases: :expand, max_expanded_nodes: 10,
                        max_expanded_bytes: nil)
      end
    end

    def test_self_alias_is_a_cycle
      yaml = "---\na: &a [*a]\n"

      assert_raise(Psych::AliasCycle) do
        Psych.safe_load(yaml, aliases: :expand)
      end
    end

    def test_alias_back_to_current_expansion_path_is_a_cycle
      yaml = <<~YAML
        ---
        outer: &outer
          inner:
            back: *outer
        copy: *outer
      YAML

      assert_raise(Psych::AliasCycle) do
        Psych.safe_load(yaml, aliases: :expand)
      end
    end

    def test_safe_load_does_not_allow_extra_classes
      yaml = "--- !ruby/object:Object {}\n"

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(yaml, aliases: :expand)
      end
    end

    def test_unsafe_load_accepts_expansion_mode
      yaml = "---\na: &shared value\nb: *shared\n"

      result = Psych.unsafe_load(yaml, aliases: :expand)

      refute_same(result.fetch("a"), result.fetch("b"))
    end

    def test_alias_mode_must_be_a_known_value
      assert_raise(ArgumentError) do
        Psych.safe_load("--- x\n", aliases: :copy)
      end
    end

    def test_expansion_options_require_expansion_mode
      assert_raise(ArgumentError) do
        Psych.safe_load("--- x\n", max_expanded_nodes: 1)
      end
    end

    private

    def exponential_yaml levels, value = "x"
      lines = ["a0: &a0 [#{value}]"]
      (1...levels).each do |level|
        lines << "a#{level}: &a#{level} [*a#{level - 1}, *a#{level - 1}]"
      end
      lines << "value: *a#{levels - 1}"
      lines.join("\n") + "\n"
    end
  end
end
