# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestSourceMap < TestCase
    YAML = <<~eoyml
      base: &base
        inherited: from_base
        override: base
        skipped: base
      left: &left
        <<: *base
        override: left
      right: &right
        inherited: from_right
        override: right
      target:
        <<: [*left, *right]
        override: final
        direct: value
      loop: &loop
        - *loop
      aliased: *left
    eoyml

    def test_load_returns_normal_data_and_source_map
      value, sources = Psych.load_with_source(YAML, aliases: true)

      assert_equal({
        "inherited" => "from_base",
        "override" => "final",
        "skipped" => "base",
        "direct" => "value"
      }, value["target"])
      assert_instance_of(SourceMap, sources)
    end

    def test_direct_declaration
      _value, sources = Psych.unsafe_load_with_source(YAML)
      source = sources.source_for("target", "direct")

      assert_predicate(source, :direct?)
      refute_predicate(source, :inherited?)
      assert_equal(["target", "direct"], source.path)
      assert_equal(["target", "direct"], source.declaration_path)
      assert_equal(13, source.line)
      assert_equal(10, source.column)
      assert_nil(source.anchor)
      assert_empty(source.via)
      assert_empty(source.overrides)
    end

    def test_multilevel_merge_records_complete_chain_and_sequence_priority
      value, sources = Psych.unsafe_load_with_source(YAML, filename: "config.yml")
      source = sources.source_for("target", "inherited")

      assert_equal("from_base", value["target"]["inherited"])
      assert_predicate(source, :inherited?)
      assert_equal("base", source.anchor)
      assert_equal(1, source.line)
      assert_equal(13, source.column)
      assert_equal(["base", "inherited"], source.declaration_path)
      assert_equal([:merge, :merge], source.via.map(&:kind))
      assert_equal(["left", "base"], source.via.map(&:anchor))
      assert_equal([11, 5], source.via.map(&:line))
      assert(source.via.all? { |step| step.file == "config.yml" })
      assert_equal("config.yml", source.file)

      override = source.overrides.first
      assert_predicate(override, :overridden?)
      assert_equal("right", override.anchor)
      assert_equal(8, override.line)
      assert_equal(["right"], override.via.map(&:anchor))
    end

    def test_explicit_value_overrides_same_named_anchor_values
      _value, sources = Psych.unsafe_load_with_source(YAML)

      nested = sources.source_for("left", "override")
      assert_predicate(nested, :direct?)
      assert_equal(6, nested.line)
      assert_equal("left", nested.anchor)
      assert_equal(1, nested.overrides.length)

      nested_override = nested.overrides.first
      assert_predicate(nested_override, :inherited?)
      assert_predicate(nested_override, :overridden?)
      assert_equal("base", nested_override.anchor)
      assert_equal(2, nested_override.line)
      assert_equal(["base", "override"], nested_override.declaration_path)
      assert_equal([:merge], nested_override.via.map(&:kind))
      assert_equal(["base"], nested_override.via.map(&:anchor))
      assert_equal(5, nested_override.via.first.line)

      final = sources.source_for("target", "override")
      assert_predicate(final, :direct?)
      assert_equal(12, final.line)
      assert_equal(%w[left right], final.overrides.map(&:anchor))
      assert(final.overrides.all?(&:overridden?))
    end

    def test_alias_chain_without_merge
      value, sources = Psych.unsafe_load_with_source(YAML)
      source = sources.source_for("aliased", "skipped")

      assert_same(value["left"], value["aliased"])
      assert_predicate(source, :inherited?)
      assert_equal("base", source.anchor)
      assert_equal(3, source.line)
      assert_equal(["base", "skipped"], source.declaration_path)
      assert_equal([:alias, :merge], source.via.map(&:kind))
      assert_equal(["left", "base"], source.via.map(&:anchor))
    end

    def test_alias_cycle_is_terminated_and_marked
      value, sources = Psych.unsafe_load_with_source(YAML)
      source = sources.source_for("loop", 0, 0)

      assert_same(value["loop"], value["loop"][0][0])
      assert_predicate(source, :aliased?)
      assert_predicate(source, :cycle?)
      assert_equal("loop", source.anchor)
      assert_equal(14, source.line)
      assert_equal(2, source.via.length)
      assert_equal(["loop", "loop"], source.via.map(&:anchor))
      assert(source.via.all?(&:cycle?))
    end

    def test_symbolized_paths_and_array_lookup
      _value, sources = Psych.unsafe_load_with_source(
        YAML,
        symbolize_names: true
      )

      source = sources.source_for(:target, :direct)
      assert_predicate(source, :direct?)
      assert_equal(%i[target direct], source.path)
    end

    def test_explicit_chevron_key_is_not_merged
      yaml = <<~eoyml
        base: &base
          value: inherited
        target:
          !!str '<<': *base
      eoyml
      value, sources = Psych.unsafe_load_with_source(yaml)

      assert_equal({"value" => "inherited"}, value["target"]["<<"])
      source = sources.source_for("target", "<<", "value")
      assert_predicate(source, :aliased?)
      assert_equal("base", source.anchor)
    end

    def test_source_map_does_not_modify_ast
      document = Psych.parse(YAML)
      before = document.map { |node| node_snapshot(node) }
      document.to_ruby_with_source
      after = document.map { |node| node_snapshot(node) }

      assert_equal(before, after)
    end

    private

    def node_snapshot(node)
      [
        node.class,
        node.start_line,
        node.start_column,
        node.end_line,
        node.end_column,
        node.respond_to?(:anchor) ? node.anchor : nil
      ]
    end
  end
end
