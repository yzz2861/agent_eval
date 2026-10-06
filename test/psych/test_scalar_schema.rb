# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestScalarSchema < TestCase
    SCALAR_CASES = [
      ['true', 'true', TrueClass, true],
      ["'true'", 'true', String, 'true'],
      ["'2020-01-01'", '2020-01-01', String, '2020-01-01'],
      ['yes', 'yes', TrueClass, true],
      ['null', 'null', NilClass, nil],
      ['1', '1', Integer, 1],
      ['1.5', '1.5', Float, 1.5],
      ['1e3', '1e3', String, '1e3'],
      ['1.', '1.', Float, 1.0],
      ['.inf', '.inf', Float, :infinity],
      ['017', '017', Integer, 15],
      ['0o18', '0o18', String, '0o18'],
      ['0o17', '0o17', String, '0o17'],
      ['0x10', '0x10', Integer, 16],
      ['0b1', '0b1', Integer, 1],
      ['12,345', '12,345', Integer, 12_345],
      ['1_000', '1_000', Integer, 1_000],
      ['2020-01-01', '2020-01-01', Date, Date.new(2020, 1, 1)],
      ['2020-13-01', '2020-13-01', String, '2020-13-01'],
      ['2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z', Time, Time.utc(2020, 1, 1)],
      [':answer', ':answer', Symbol, :answer],
      ['12:34:56', '12:34:56', Integer, 45_296],
    ].freeze

    SCHEMAS = [:compat, :json, :core].freeze

    def test_load_schema_table
      SCALAR_CASES.each do |yaml, value, compat_class, compat_value|
        SCHEMAS.each do |schema|
          expected = expected_scalar(yaml, value, compat_class, compat_value, schema)
          result = Psych.unsafe_load("--- #{yaml}\n", scalar_schema: schema)
          assert_scalar_result expected, result, "unsafe_load #{yaml.inspect} #{schema}"
        end
      end
    end

    def test_safe_load_and_stream_share_schema_table
      safe_cases = SCALAR_CASES.reject { |_, value, _, _| %w[2020-01-01 2020-01-01T00:00:00Z :answer 12:34:56].include?(value) }
      safe_cases.each do |yaml, value, compat_class, compat_value|
        SCHEMAS.each do |schema|
          expected = expected_scalar(yaml, value, compat_class, compat_value, schema)
          yaml_document = "--- #{yaml}\n"

          assert_scalar_result expected,
                               Psych.safe_load(yaml_document, scalar_schema: schema),
                               "safe_load #{yaml.inspect} #{schema}"
          assert_scalar_result expected,
                               Psych.load_stream(yaml_document, scalar_schema: schema).first,
                               "load_stream #{yaml.inspect} #{schema}"
          assert_scalar_result expected,
                               Psych.safe_load_stream(yaml_document, scalar_schema: schema).first,
                               "safe_load_stream #{yaml.inspect} #{schema}"
          assert_scalar_result expected,
                               Psych.parse_stream(yaml_document).children.first.to_ruby(scalar_schema: schema),
                               "Node#to_ruby #{yaml.inspect} #{schema}"
        end
      end
    end

    def test_schema_applies_to_every_multi_document
      yaml = "--- true\n--- 0o17\n--- 2020-01-01\n"

      assert_equal [true, '0o17', '2020-01-01'],
                   Psych.load_stream(yaml, scalar_schema: :json)
      assert_equal [true, 15, '2020-01-01'],
                   Psych.load_stream(yaml, scalar_schema: :core)
    end

    def test_safe_load_stream_keeps_alias_policy_within_each_document
      yaml = "---\n- &a true\n- *a\n"

      assert_raise(Psych::AliasesNotEnabled) do
        Psych.safe_load_stream(yaml, scalar_schema: :json)
      end
      assert_equal [[true, true]],
                   Psych.safe_load_stream(yaml, scalar_schema: :json, aliases: true)
    end

    def test_safe_load_stream_keeps_permitted_classes
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load_stream("--- !ruby/symbol answer\n", scalar_schema: :json)
      end
    end

    def test_schema_is_not_process_global
      result_before = Psych.unsafe_load('--- yes\n')
      Psych.unsafe_load('--- yes\n', scalar_schema: :core)

      assert_equal result_before, Psych.unsafe_load('--- yes\n')
    end

    def test_invalid_schema_is_rejected
      error = assert_raise(ArgumentError) do
        Psych.load('--- 1', scalar_schema: :yaml11)
      end
      assert_match(/invalid scalar schema/, error.message)
    end

    def test_invalid_schema_is_rejected_before_empty_stream_is_returned
      assert_raise(ArgumentError) do
        Psych.load_stream('', scalar_schema: :yaml11)
      end
      assert_raise(ArgumentError) do
        Psych.safe_load_stream('', scalar_schema: :yaml11)
      end
    end

    def test_explicit_standard_tag_contents_are_validated
      invalid_cases = [
        ['!!int "017"', :core],
        ['!!int "0o17"', :json],
        ['!!int 0o18', :core],
        ['!!int .inf', :compat],
        ['!!float .inf', :json],
        ['!!bool "yes"', :core],
        ['!!timestamp "2020-01-01"', :core],
        ['!!binary YWJj', :json],
        ['!!binary YWJj', :core],
      ]

      invalid_cases.each do |yaml, schema|
        assert_raise ArgumentError, "explicit tag #{yaml.inspect} #{schema} should fail" do
          Psych.unsafe_load("--- #{yaml}\n", scalar_schema: schema)
        end
      end
    end

    def test_explicit_tag_validates_but_untagged_quoted_text_stays_string
      yaml = "--- !!int \"17\"\n"

      assert_equal 17, Psych.unsafe_load(yaml, scalar_schema: :json)
      assert_equal 17, Psych.unsafe_load(yaml, scalar_schema: :core)
      assert_equal '17', Psych.unsafe_load("--- '17'\n", scalar_schema: :json)
    end

    def test_explicit_float_accepts_integer_content
      assert_equal 17.0, Psych.unsafe_load("--- !!float 17\n", scalar_schema: :json)
    end

    def test_explicit_core_octal_follows_core_schema
      assert_equal 15, Psych.unsafe_load("--- !!int 0o17\n", scalar_schema: :core)
      assert_raise ArgumentError do
        Psych.unsafe_load("--- !!int 0o17\n", scalar_schema: :json)
      end
    end

    def test_explicit_null_accepts_empty_content
      [:json, :core].each do |schema|
        assert_nil Psych.unsafe_load("--- !!null\n", scalar_schema: schema)
      end
      assert_nil Psych.unsafe_load("--- !!null\n")
    end

    def test_compat_binary_tag_continues_to_decode
      assert_equal "abc", Psych.unsafe_load("--- !!binary YWJj\n")
    end

    private

    def expected_scalar source, yaml, compat_class, compat_value, schema
      return [String.name, yaml] if source.start_with?("'") || source.start_with?('"')

      if schema == :compat
        return [compat_class.name, compat_value]
      end

      json_like = yaml.match?(/\A(?:true|false|null|[-+]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)\z/)
      if json_like
        case yaml
        when 'true' then [TrueClass.name, true]
        when 'false' then [FalseClass.name, false]
        when 'null' then [NilClass.name, nil]
        when /[.eE]/ then [Float.name, yaml.to_f]
        else [Integer.name, Integer(yaml)]
        end
      elsif schema == :core
        case yaml
        when '.inf' then [Float.name, :infinity]
        when '1.' then [Float.name, 1.0]
        when '1_000' then [Integer.name, 1_000]
        when /\A0o[0-7]+\z/ then [Integer.name, Integer(yaml.delete('_'))]
        when /\A0x[0-9a-fA-F]+\z/ then [Integer.name, Integer(yaml)]
        else [String.name, yaml]
        end
      else
        [String.name, yaml]
      end
    end

    def assert_scalar_result expected, actual, message
      class_name, value = expected
      assert_equal class_name, actual.class.name, message
      if value == :infinity
        assert_equal 1, actual.infinite?, message
      else
        assert_equal value, actual, message
      end
    end
  end
end
