# frozen_string_literal: true
require 'psych/helper'

module Psych
  class TestPreserveUnknownTags < TestCase
    def test_unknown_scalar_tag_is_preserved
      result = Psych.safe_load "--- !python/tuple 42\n", preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal "!python/tuple", result.tag
      assert_equal "42", result.value
    end

    def test_unknown_quoted_scalar_tag_is_preserved
      result = Psych.safe_load "--- !foreign/scalar \"hello world\"\n", preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal "!foreign/scalar", result.tag
      assert_equal "hello world", result.value
    end

    def test_unknown_sequence_tag_is_preserved
      result = Psych.safe_load "--- !python/tuple\n- 1\n- two\n", preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal "!python/tuple", result.tag
      assert_equal [1, "two"], result.value
    end

    def test_unknown_mapping_tag_is_preserved
      result = Psych.safe_load "--- !java.util.HashMap\nfoo: bar\n", preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal "!java.util.HashMap", result.tag
      assert_equal({ "foo" => "bar" }, result.value)
    end

    def test_unknown_tags_nested_in_plain_structures
      yaml = <<~YAML
        ---
        - !foreign/item
          name: one
        - plain
        - key: !foreign/scalar value
      YAML

      foreign, plain, nested = Psych.safe_load yaml, preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, foreign
      assert_equal({ "name" => "one" }, foreign.value)
      assert_equal "plain", plain
      assert_instance_of Psych::UnknownTag, nested["key"]
      assert_equal "value", nested["key"].value
    end

    def test_default_behavior_is_unchanged_without_the_option
      # foreign tags are silently dropped
      assert_equal [1, 2], Psych.safe_load("--- !python/tuple\n- 1\n- 2\n")
      assert_equal 42, Psych.safe_load("--- !python/tuple 42\n")

      # ruby class tags still raise
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load "--- !ruby/object:NotPermitted {}\n"
      end
    end

    def test_untagged_disallowed_symbol_still_raises
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load "--- :foo\n", preserve_unknown_tags: true
      end
    end

    def test_anchors_and_aliases_share_the_preserved_object
      yaml = <<~YAML
        ---
        - !python/tuple &shared
          - 1
          - 2
        - *shared
      YAML

      first, second = Psych.safe_load yaml, preserve_unknown_tags: true, aliases: true

      assert_instance_of Psych::UnknownTag, first
      assert_same first, second

      first.value << 3
      assert_equal [1, 2, 3], second.value
    end

    def test_permitted_classes_still_deserialize_normally
      assert_equal :foo, Psych.safe_load("--- !ruby/sym foo\n",
                                         permitted_classes: [Symbol],
                                         preserve_unknown_tags: true)

      date = Psych.safe_load "--- 2024-01-02\n",
                             permitted_classes: [Date],
                             preserve_unknown_tags: true
      assert_equal Date.new(2024, 1, 2), date
    end

    def test_not_permitted_ruby_tag_is_preserved_instead_of_raising
      result = Psych.safe_load "--- !ruby/sym foo\n", preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal "!ruby/sym", result.tag
      assert_equal "foo", result.value
    end

    def test_core_yaml_tags_still_use_builtin_handling
      assert_equal "3", Psych.safe_load("--- !!str 3\n", preserve_unknown_tags: true)
      assert_equal 3, Psych.safe_load("--- !!int 3\n", preserve_unknown_tags: true)
      assert_equal "hi", Psych.safe_load("--- !binary aGk=\n", preserve_unknown_tags: true)
      assert_equal [1, 2], Psych.safe_load("--- !!seq\n- 1\n- 2\n", preserve_unknown_tags: true)
      assert_equal({ "a" => "b" }, Psych.safe_load("--- !!map\na: b\n", preserve_unknown_tags: true))
    end

    def test_round_trip_preserves_tags_and_shared_anchors
      yaml = <<~YAML
        ---
        meta: !com.example/meta
          version: 1
        items: !python/tuple &shared
          - 1
          - 2
        again: *shared
        note: !foreign/scalar hello
      YAML

      doc = Psych.safe_load yaml, preserve_unknown_tags: true, aliases: true
      assert_same doc["items"], doc["again"]

      doc["items"].value << 3
      doc["note"].value = "goodbye"

      reloaded = Psych.safe_load Psych.dump(doc), preserve_unknown_tags: true, aliases: true

      assert_equal "!com.example/meta", reloaded["meta"].tag
      assert_equal({ "version" => 1 }, reloaded["meta"].value)
      assert_equal "!python/tuple", reloaded["items"].tag
      assert_same reloaded["items"], reloaded["again"]
      assert_equal [1, 2, 3], reloaded["again"].value
      assert_equal "!foreign/scalar", reloaded["note"].tag
      assert_equal "goodbye", reloaded["note"].value
    end

    def test_replaced_value_is_dumped_with_the_original_tag
      obj = Psych.safe_load "--- !python/tuple [1, 2]\n", preserve_unknown_tags: true
      obj.value = [3, 4]

      assert_equal "--- !python/tuple\n- 3\n- 4\n", Psych.dump(obj)
    end

    def test_safe_dump_allows_preserved_objects
      obj = Psych.safe_load "--- !python/tuple [1, 2]\n", preserve_unknown_tags: true

      assert_equal "--- !python/tuple\n- 1\n- 2\n", Psych.safe_dump(obj)
    end

    def test_masquerading_ruby_class_tag_does_not_constantize_or_instantiate
      hits = []
      klass = Class.new do
        define_singleton_method(:allocate) { hits << :allocate }
        define_method(:initialize) { |*| hits << :initialize }
        define_method(:init_with) { |*| hits << :init_with }
      end
      Object.const_set :MasqueradingNotPermitted, klass

      yaml = "--- !ruby/object:MasqueradingNotPermitted\nfoo: bar\n"
      result = Psych.safe_load yaml, preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal "!ruby/object:MasqueradingNotPermitted", result.tag
      assert_equal({ "foo" => "bar" }, result.value)
      assert_empty hits
    ensure
      Object.send :remove_const, :MasqueradingNotPermitted
    end

    def test_nonexistent_ruby_class_tag_is_preserved_without_name_error
      yaml = "--- !ruby/object:This::Constant::DoesNotExist\nfoo: bar\n"
      result = Psych.safe_load yaml, preserve_unknown_tags: true

      assert_instance_of Psych::UnknownTag, result
      assert_equal({ "foo" => "bar" }, result.value)
    end

    def test_no_constant_lookup_happens_for_masquerading_tags
      loader = Class.new(Psych::ClassLoader::Restricted) do
        def resolve name
          raise "constant lookup attempted for #{name.inspect}"
        end
      end.new([], [])

      scanner = Psych::ScalarScanner.new loader
      visitor = Psych::Visitors::ToRuby.new scanner, loader, preserve_unknown_tags: true

      result = visitor.accept Psych.parse("--- !ruby/object:DefinitelyNotARealClass\nfoo: bar\n")

      assert_instance_of Psych::UnknownTag, result
      assert_equal({ "foo" => "bar" }, result.value)
    end
  end
end
