# frozen_string_literal: true
require 'psych/helper'

module Psych
  class TestSafeLoad < TestCase
    def setup
      @orig_verbose, $VERBOSE = $VERBOSE, nil
    end

    def teardown
      $VERBOSE = @orig_verbose
    end

    class Foo; end

    class Exploding
      class << self
        def const_missing(name)
          raise "unexpected constant lookup: #{name}"
        end

        def allocate
          raise "unexpected allocation"
        end

        def new(*)
          raise "unexpected user constructor"
        end
      end

      def initialize(*)
        raise "unexpected user constructor"
      end
    end

    class RegisteredTagged
      attr_accessor :value

      def init_with(coder)
        @value = coder.scalar
      end
    end

    [1, 2.2, {}, [], "foo"].each do |obj|
      define_method(:"test_basic_#{obj.class}") do
        assert_safe_cycle obj
      end
    end

    def test_raises_when_alias_found_if_alias_parsing_not_enabled
      yaml_with_aliases = <<~YAML
        ---
        a: &ABC
          k1: v1
          k2: v2
        b: *ABC
      YAML

      assert_raise(Psych::AliasesNotEnabled) do
        Psych.safe_load(yaml_with_aliases)
      end
    end

    def test_aliases_are_parsed_when_alias_parsing_is_enabled
      yaml_with_aliases = <<~YAML
        ---
        a: &ABC
          k1: v1
          k2: v2
        b: *ABC
      YAML

      result = Psych.safe_load(yaml_with_aliases, aliases: true)
      assert_same result.fetch("a"), result.fetch("b")
    end

    def test_permitted_symbol
      yml = Psych.dump :foo
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yml
      end
      assert_equal(
        :foo,
        Psych.safe_load(
          yml,
          permitted_classes: [Symbol],
          permitted_symbols: [:foo]
        )
      )
    end

    def test_symbol
      assert_raise(Psych::DisallowedClass) do
        assert_safe_cycle :foo
      end
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load '--- !ruby/symbol foo', permitted_classes: []
      end

      assert_safe_cycle :foo, permitted_classes: [Symbol]
      assert_safe_cycle :foo, permitted_classes: %w{ Symbol }
      assert_equal :foo, Psych.safe_load('--- !ruby/symbol foo', permitted_classes: [Symbol])
    end

    def test_encoding
      yaml = "--- !ruby/encoding UTF-8\n"
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yaml
      end
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yaml, permitted_classes: []
      end

      assert_equal Encoding::UTF_8, Psych.safe_load(yaml, permitted_classes: [Encoding])
      assert_equal Encoding::UTF_8, Psych.safe_load(yaml, permitted_classes: %w{ Encoding })
    end

    def test_foo
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load '--- !ruby/object:Foo {}', permitted_classes: [Foo]
      end

      assert_raise(Psych::DisallowedClass) do
        assert_safe_cycle Foo.new
      end
      assert_kind_of(Foo, Psych.safe_load(Psych.dump(Foo.new), permitted_classes: [Foo]))
    end

    X = Struct.new(:x)
    def test_struct_depends_on_sym
      assert_safe_cycle(X.new, permitted_classes: [X, Symbol])
      assert_raise(Psych::DisallowedClass) do
        cycle X.new, permitted_classes: [X]
      end
    end

    def test_anon_struct
      assert Psych.safe_load(<<-eoyml, permitted_classes: [Struct, Symbol])
--- !ruby/struct
  foo: bar
                      eoyml

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Struct])
--- !ruby/struct
  foo: bar
                      eoyml
      end

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Symbol])
--- !ruby/struct
  foo: bar
                      eoyml
      end
    end

    D = Data.define(:d) unless RUBY_VERSION < "3.2"

    def test_data_depends_on_sym
      omit "Data requires ruby >= 3.2" if RUBY_VERSION < "3.2"
      assert_safe_cycle(D.new(nil), permitted_classes: [D, Symbol])
      assert_raise(Psych::DisallowedClass) do
        cycle D.new(nil), permitted_classes: [D]
      end
    end

    def test_anon_data
      omit "Data requires ruby >= 3.2" if RUBY_VERSION < "3.2"
      assert Psych.safe_load(<<-eoyml, permitted_classes: [Data, Symbol])
--- !ruby/data
  foo: bar
      eoyml

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Data])
--- !ruby/data
  foo: bar
        eoyml
      end

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Symbol])
--- !ruby/data
  foo: bar
        eoyml
      end
    end

    def test_safe_load_default_fallback
      assert_nil Psych.safe_load("")
    end

    def test_safe_load
      assert_equal %w[a b], Psych.safe_load("- a\n- b")
    end

    def test_preserve_unknown_tags_is_opt_in
      yaml = "--- !svc/tag value\n"

      assert_equal "value", Psych.safe_load(yaml)

      value = Psych.safe_load(yaml, preserve_unknown_tags: true)
      assert_instance_of Psych::UnknownTag, value
      assert_equal "!svc/tag", value.tag
      assert_equal "value", value.value
      assert_predicate value, :scalar?
    end

    def test_preserve_unknown_scalar_sequence_and_mapping_tags
      yaml = <<~YAML
        scalar: !svc/scalar 42
        sequence: !svc/sequence
          - 1
        mapping: !svc/mapping
          name: hello
      YAML

      result = Psych.safe_load(yaml, preserve_unknown_tags: true)

      scalar = result.fetch("scalar")
      sequence = result.fetch("sequence")
      mapping = result.fetch("mapping")

      assert_instance_of Psych::UnknownTag, scalar
      assert_equal 42, scalar.value
      assert_predicate scalar, :scalar?
      assert_instance_of Psych::UnknownTag, sequence
      assert_equal [1], sequence.value
      assert_predicate sequence, :sequence?
      assert_instance_of Psych::UnknownTag, mapping
      assert_equal({"name" => "hello"}, mapping.value)
      assert_predicate mapping, :map?
    end

    def test_preserved_unknown_tag_value_can_be_replaced
      value = Psych.safe_load("--- !svc/tag old\n", preserve_unknown_tags: true)
      value.value = "new"

      assert_equal "new", value.value
      assert_predicate value, :scalar?
      assert_equal "--- !svc/tag new\n", Psych.dump(value)

      value.value = ["a", "b"]
      assert_predicate value, :sequence?
      assert_equal "--- !svc/tag\n- a\n- b\n", Psych.dump(value)

      value.value = {"name" => "new"}
      assert_predicate value, :map?
      assert_equal "--- !svc/tag\nname: new\n", Psych.dump(value)
    end

    def test_preserved_unknown_tag_respects_freeze
      value = Psych.safe_load(<<~YAML, freeze: true, preserve_unknown_tags: true)
        --- !svc/mapping
        name: hello
      YAML

      assert_predicate value, :frozen?
      assert_predicate value.value, :frozen?
      assert_raise(FrozenError) { value.value = {} }
    end

    def test_preserved_unknown_tags_round_trip_and_keep_anchor_sharing
      yaml = <<~YAML
        scalar: &scalar !svc/scalar value
        sequence: &sequence !svc/sequence
          - 1
        mapping: &mapping !svc/mapping
          name: hello
        scalar_alias: *scalar
        sequence_alias: *sequence
        mapping_alias: *mapping
      YAML

      result = Psych.safe_load(yaml, aliases: true, preserve_unknown_tags: true)

      assert_same result.fetch("scalar"), result.fetch("scalar_alias")
      assert_same result.fetch("sequence"), result.fetch("sequence_alias")
      assert_same result.fetch("mapping"), result.fetch("mapping_alias")

      result.fetch("sequence_alias").value << 2
      assert_equal [1, 2], result.fetch("sequence").value
      result.fetch("mapping_alias").value["shared"] = true
      assert_equal true, result.fetch("mapping").value["shared"]

      dumped = Psych.dump(result)
      assert_include dumped, "!svc/scalar"
      assert_include dumped, "!svc/sequence"
      assert_include dumped, "!svc/mapping"

      round_trip = Psych.safe_load(dumped, aliases: true, preserve_unknown_tags: true)
      assert_same round_trip.fetch("scalar"), round_trip.fetch("scalar_alias")
      assert_same round_trip.fetch("sequence"), round_trip.fetch("sequence_alias")
      assert_same round_trip.fetch("mapping"), round_trip.fetch("mapping_alias")
    end

    def test_preserved_unknown_tag_supports_recursive_values
      sequence = Psych::UnknownTag.new("!svc/sequence", [])
      sequence.value << sequence
      mapping = Psych::UnknownTag.new("!svc/mapping", {})
      mapping.value["self"] = mapping

      assert_equal "--- &1 !svc/sequence\n- *1\n", Psych.dump(sequence)
      assert_equal "--- &1 !svc/mapping\nself: *1\n", Psych.dump(mapping)
    end

    def test_preserved_unknown_tags_can_use_safe_dump_with_aliases
      value = Psych.safe_load(<<~YAML, aliases: true, preserve_unknown_tags: true)
        tagged: &tagged !svc/tag value
        aliased: *tagged
      YAML

      assert_raise(Psych::BadAlias) do
        Psych.safe_dump(value)
      end
      assert_safe_dump_output = Psych.safe_dump(value, aliases: true)
      assert_include assert_safe_dump_output, "!svc/tag"
    end

    def test_permitted_classes_still_override_preserved_unknown_tags
      yaml = <<~YAML
        --- !ruby/range
        begin: 1
        end: 3
        excl: false
      YAML

      value = Psych.safe_load(yaml, permitted_classes: [Range],
                             preserve_unknown_tags: true)

      assert_equal 1..3, value
    end

    def test_builtin_tags_still_use_existing_rules
      assert_equal 1.2, Psych.safe_load("--- !float 1.2\n",
                                        preserve_unknown_tags: true)
      assert_instance_of Psych::Omap, Psych.safe_load("--- !omap\n- name: value\n",
                                                      preserve_unknown_tags: true)
    end

    def test_permitted_object_still_uses_existing_rules
      value = Psych.safe_load("--- !ruby/object {}\n",
                              permitted_classes: [Object],
                              preserve_unknown_tags: true)

      assert_instance_of Object, value
    end

    def test_registered_load_tags_are_preserved_when_not_permitted
      Psych.add_tag "!registered/tag", RegisteredTagged

      value = Psych.safe_load("--- !registered/tag hello\n", preserve_unknown_tags: true)

      assert_instance_of Psych::UnknownTag, value
      assert_equal "!registered/tag", value.tag
      assert_equal "hello", value.value
    ensure
      Psych.load_tags.delete("!registered/tag")
      Psych.dump_tags.delete(RegisteredTagged)
    end

    def test_preserve_unknown_tags_works_from_stream_and_ast
      yaml = "--- !svc/tag value\n--- !svc/other [1]\n"

      docs = Psych.safe_load_stream(yaml, preserve_unknown_tags: true)
      assert_equal "!svc/tag", docs.first.tag
      assert_equal "value", docs.first.value
      assert_equal "!svc/other", docs.last.tag
      assert_equal [1], docs.last.value

      node = Psych.parse("--- !svc/node {a: 1}\n").root
      value = node.to_ruby(preserve_unknown_tags: true)
      assert_instance_of Psych::UnknownTag, value
      assert_equal({"a" => 1}, value.value)
    end

    def test_ruby_class_tag_is_preserved_without_constant_lookup_or_initialize
      tag = "!ruby/object:Psych::TestSafeLoad::Exploding"
      examples = {
        "scalar" => "--- #{tag} danger\n",
        "sequence" => "--- #{tag} [danger]\n",
        "mapping" => "--- #{tag}\nname: danger\n"
      }
      expected = {
        "scalar" => "danger",
        "sequence" => ["danger"],
        "mapping" => {"name" => "danger"}
      }

      examples.each do |kind, yaml|
        constant_paths = []
        initialize_calls = 0
        allocation_calls = 0
        original_allocate = Exploding.singleton_method(:allocate)
        original_new = Exploding.method(:new)
        Exploding.define_singleton_method(:allocate) do |*|
          allocation_calls += 1
          original_allocate.call
        end
        Exploding.define_singleton_method(:new) do |*|
          allocation_calls += 1
          original_new.call
        end

        begin
          tracer = TracePoint.new(:c_call, :b_call) do |event|
            case event.method_id
            when :path2class, :const_missing
              constant_paths << event.path
            when :initialize
              initialize_calls += 1 if event.self.is_a?(Exploding)
            end
          end

          value = tracer.enable do
            Psych.safe_load(yaml, preserve_unknown_tags: true)
          end
        ensure
          Exploding.define_singleton_method(:allocate, original_allocate)
          Exploding.define_singleton_method(:new, original_new)
        end

        assert_instance_of Psych::UnknownTag, value, kind
        assert_equal tag, value.tag, kind
        assert_equal expected.fetch(kind), value.value, kind
        assert_empty constant_paths, kind
        assert_equal 0, initialize_calls, kind
        assert_equal 0, allocation_calls, kind
      end
    end

    def test_safe_load_raises_on_bad_input
      assert_raise(Psych::SyntaxError) { Psych.safe_load("--- `") }
    end

    private

    def cycle object, permitted_classes: []
      Psych.safe_load(Psych.dump(object), permitted_classes: permitted_classes)
    end

    def assert_safe_cycle object, permitted_classes: []
      other = cycle object, permitted_classes: permitted_classes
      assert_equal object, other
    end
  end
end
