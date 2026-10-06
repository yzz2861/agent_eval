# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestAliasExpansion < TestCase
    def test_expand_returns_independent_copies
      yaml = <<~YAML
        ---
        - &shared
          name: base
          tags: [one]
        - *shared
      YAML

      result = Psych.safe_load yaml, aliases: :expand

      assert_equal result[0], result[1]
      assert_not_same result[0], result[1]
      assert_not_same result[0]["tags"], result[1]["tags"]

      result[0]["tags"] << "two"
      result[0]["name"] = "changed"
      assert_equal ["one"], result[1]["tags"]
      assert_equal "base", result[1]["name"]
    end

    def test_shared_mode_still_returns_same_object
      yaml = <<~YAML
        ---
        - &shared
          name: base
        - *shared
      YAML

      result = Psych.safe_load yaml, aliases: true
      assert_same result[0], result[1]
    end

    def test_aliases_still_disabled_by_default
      yaml = <<~YAML
        ---
        - &shared 1
        - *shared
      YAML

      assert_raise(Psych::AliasesNotEnabled) { Psych.safe_load yaml }
    end

    def test_many_references_without_cycle
      yaml = <<~YAML
        ---
        shared: &s
          list: [1, 2]
        a: *s
        b: *s
        c: *s
      YAML

      result = Psych.safe_load yaml, aliases: :expand

      assert_equal result["shared"], result["a"]
      assert_equal result["a"], result["b"]
      assert_equal result["b"], result["c"]
      assert_not_same result["a"], result["b"]
      assert_not_same result["b"], result["c"]

      result["a"]["list"] << 3
      assert_equal [1, 2], result["b"]["list"]
      assert_equal [1, 2], result["shared"]["list"]
    end

    def test_direct_cycle_raises
      assert_raise(Psych::CircularAlias) do
        Psych.safe_load "--- &a [*a]", aliases: :expand
      end
    end

    def test_indirect_cycle_raises
      yaml = <<~YAML
        ---
        &a
        x: &b
          y: *a
      YAML

      assert_raise(Psych::CircularAlias) do
        Psych.safe_load yaml, aliases: :expand
      end
    end

    def test_exponential_expansion_is_limited
      lines = ["---"]
      ("a".."z").each_cons(2) do |prev, cur|
        lines << "#{prev}: &#{prev} [\"x\"]" if prev == "a"
        lines << "#{cur}: &#{cur} [*#{prev}, *#{prev}]"
      end
      lines << "root: *z"
      yaml = lines.join("\n")

      assert yaml.bytesize < 1_000
      assert_raise(Psych::AliasExpansionLimitExceeded) do
        Psych.safe_load yaml, aliases: :expand
      end
    end

    def test_node_limit_keyword
      yaml = <<~YAML
        ---
        - &a [1, 2, 3]
        - *a
      YAML

      assert_raise(Psych::AliasExpansionLimitExceeded) do
        Psych.safe_load yaml, aliases: :expand, max_expanded_nodes: 2
      end

      result = Psych.safe_load yaml, aliases: :expand, max_expanded_nodes: 100
      assert_equal [[1, 2, 3], [1, 2, 3]], result
    end

    def test_string_bytes_limit
      long = "x" * 100
      yaml = <<~YAML
        ---
        - &a #{long}
        - *a
        - *a
      YAML

      assert_raise(Psych::AliasExpansionLimitExceeded) do
        Psych.safe_load yaml, aliases: :expand, max_expanded_string_bytes: 150
      end

      result = Psych.safe_load yaml, aliases: :expand, max_expanded_string_bytes: 1_000
      assert_equal [long, long, long], result
      assert_not_same result[0], result[1]
    end

    def test_merge_keys_are_expanded
      yaml = <<~YAML
        ---
        - &base
          a: 1
          nested: {x: 1}
        - <<: *base
          b: 2
        - <<: *base
          b: 3
      YAML

      result = Psych.safe_load yaml, aliases: :expand

      assert_equal({"a" => 1, "nested" => {"x" => 1}, "b" => 2}, result[1])
      assert_equal({"a" => 1, "nested" => {"x" => 1}, "b" => 3}, result[2])

      assert_not_same result[1]["nested"], result[2]["nested"]
      result[1]["nested"]["x"] = 99
      assert_equal 1, result[2]["nested"]["x"]
      assert_equal 1, result[0]["nested"]["x"]
    end

    def test_merge_key_sequence_of_aliases
      yaml = <<~YAML
        ---
        - &one {a: 1}
        - &two {b: 2}
        - <<: [*one, *two]
      YAML

      result = Psych.safe_load yaml, aliases: :expand
      assert_equal({"a" => 1, "b" => 2}, result[2])
    end

    def test_safe_load_expand_does_not_permit_extra_classes
      yaml = <<~YAML
        ---
        - &a !ruby/object {}
        - *a
      YAML

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yaml, aliases: :expand
      end
    end

    def test_safe_load_expand_respects_permitted_classes
      yaml = <<~YAML
        ---
        - &a 2020-01-01
        - *a
      YAML

      result = Psych.safe_load yaml, aliases: :expand, permitted_classes: [Date]
      assert_equal [Date.new(2020, 1, 1), Date.new(2020, 1, 1)], result
      assert_not_same result[0], result[1]
    end

    def test_load_expand
      yaml = <<~YAML
        ---
        - &a :sym
        - *a
      YAML

      result = Psych.load yaml, aliases: :expand
      assert_equal [:sym, :sym], result
    end

    def test_unsafe_load_expand
      yaml = <<~YAML
        ---
        - &a [1]
        - *a
      YAML

      result = Psych.unsafe_load yaml, aliases: :expand
      assert_equal [[1], [1]], result
      assert_not_same result[0], result[1]
    end

    def test_expand_without_aliases_in_document
      result = Psych.safe_load "---\nfoo: bar\n", aliases: :expand
      assert_equal({"foo" => "bar"}, result)
    end

    def test_undefined_anchor_raises
      assert_raise(Psych::AnchorNotDefined) do
        Psych.safe_load "--- *nope", aliases: :expand
      end
    end
  end
end
