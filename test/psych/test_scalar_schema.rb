# frozen_string_literal: true
require_relative 'helper'
require 'date'

module Psych
  class TestScalarSchema < TestCase
    ERROR = Object.new
    NAN   = Object.new

    INF  = Float::INFINITY
    NINF = -Float::INFINITY

    # Tricky plain scalars and the Ruby object each schema must produce.
    # [yaml input, compat result, core result, json result]
    PLAIN_SCALARS = [
      ['null',                  nil,                  nil,          nil],
      ['~',                     nil,                  nil,          '~'],
      ['Null',                  nil,                  nil,          'Null'],
      ['NULL',                  nil,                  nil,          'NULL'],
      ['true',                  true,                 true,         true],
      ['false',                 false,                false,        false],
      ['TRUE',                  true,                 true,         'TRUE'],
      ['True',                  true,                 true,         'True'],
      ['yes',                   true,                 'yes',        'yes'],
      ['no',                    false,                'no',         'no'],
      ['on',                    true,                 'on',         'on'],
      ['off',                   false,                'off',        'off'],
      ['42',                    42,                   42,           42],
      ['-7',                    -7,                   -7,           -7],
      ['052',                   42,                   52,           '052'],
      ['0o52',                  '0o52',               42,           '0o52'],
      ['0x2A',                  42,                   42,           '0x2A'],
      ['0b1010',                10,                   '0b1010',     '0b1010'],
      ['1_000',                 1000,                 '1_000',      '1_000'],
      ['1,000',                 1000,                 '1,000',      '1,000'],
      ['1.5',                   1.5,                  1.5,          1.5],
      ['.5',                    0.5,                  0.5,          '.5'],
      ['1e3',                   '1e3',                1000.0,       1000.0],
      ['.inf',                  INF,                  INF,          '.inf'],
      ['-.inf',                 NINF,                 NINF,         '-.inf'],
      ['.NaN',                  NAN,                  NAN,          '.NaN'],
      ['2024-01-15',            Date.new(2024, 1, 15), '2024-01-15', '2024-01-15'],
      ['2024-01-15 10:30:00Z',  Time.utc(2024, 1, 15, 10, 30, 0), '2024-01-15 10:30:00Z', '2024-01-15 10:30:00Z'],
      ['1:20',                  4800,                 '1:20',       '1:20'],
      [':sym',                  :sym,                 ':sym',       ':sym'],
      ['"yes"',               'yes',                'yes',        'yes'],
      ["'123'",               '123',                '123',        '123'],
    ].freeze

    # Scalars with an explicit tag.  ERROR means Psych::ScalarSchemaError
    # must be raised because the content does not satisfy the grammar the
    # schema defines for that tag.
    # [yaml input, compat result, core result, json result]
    TAGGED_SCALARS = [
      ['!!str 123',             '123',                '123',        '123'],
      ['!!int 42',              42,                   42,           42],
      ['!!int 052',             42,                   52,           ERROR],
      ['!!int 0o52',            '0o52',               42,           ERROR],
      ['!!int 0x2A',            42,                   42,           ERROR],
      ['!!int 1_000',           1000,                 ERROR,        ERROR],
      ['!!int banana',          'banana',             ERROR,        ERROR],
      ['!!float 1.5',           1.5,                  1.5,          1.5],
      ['!!float 1e3',           1000.0,               1000.0,       1000.0],
      ['!!float .inf',          INF,                  INF,          ERROR],
      ['!!float .nan',          NAN,                  NAN,          ERROR],
      ['!!bool true',           true,                 true,         true],
      ['!!bool TRUE',           true,                 true,         ERROR],
      ['!!bool yes',            true,                 ERROR,        ERROR],
      ['!!bool off',            false,                ERROR,        ERROR],
      ['!!null null',           nil,                  nil,          nil],
      ['!!null ~',              nil,                  nil,          ERROR],
      ['!!null banana',         'banana',             ERROR,        ERROR],
      ['!!timestamp 2024-01-15',           Date.new(2024, 1, 15), Date.new(2024, 1, 15), Date.new(2024, 1, 15)],
      ['!!timestamp 2024-01-15 10:30:00Z', Time.utc(2024, 1, 15, 10, 30, 0), Time.utc(2024, 1, 15, 10, 30, 0), Time.utc(2024, 1, 15, 10, 30, 0)],
      ['!!timestamp banana',    'banana',             ERROR,        ERROR],
    ].freeze

    SCHEMAS = %i[compat core json].freeze

    def test_plain_scalar_table
      assert_table PLAIN_SCALARS
    end

    def test_tagged_scalar_table
      assert_table TAGGED_SCALARS
    end

    def test_default_schema_is_compat
      assert_equal true, Psych.load('yes')
      assert_equal 42, Psych.load('052')
      assert_equal Date.new(2024, 1, 15), Psych.unsafe_load('2024-01-15')
    end

    def test_load_accepts_schema
      assert_equal 42, Psych.load('0o52', schema: :core)
      assert_equal '0o52', Psych.load('0o52', schema: :json)
    end

    def test_safe_load_accepts_schema
      assert_equal 42, Psych.safe_load('0o52', schema: :core)
      assert_equal 'yes', Psych.safe_load('yes', schema: :core)
      assert_equal 'yes', Psych.safe_load('yes', schema: :json)
    end

    def test_unsafe_load_accepts_schema
      assert_equal 42, Psych.unsafe_load('0o52', schema: :core)
      assert_equal '0o52', Psych.unsafe_load('0o52', schema: :json)
    end

    def test_load_stream_applies_schema_to_every_document
      yaml = "--- 0o52\n--- yes\n--- 2024-01-15\n"
      assert_equal [42, 'yes', '2024-01-15'], Psych.load_stream(yaml, schema: :core)
      assert_equal ['0o52', 'yes', '2024-01-15'], Psych.load_stream(yaml, schema: :json)

      yielded = []
      Psych.load_stream(yaml, schema: :core) { |doc| yielded << doc }
      assert_equal [42, 'yes', '2024-01-15'], yielded
    end

    def test_safe_load_stream_applies_schema_to_every_document
      yaml = "--- 0o52\n--- yes\n"
      assert_equal [42, 'yes'], Psych.safe_load_stream(yaml, schema: :core)
      assert_equal ['0o52', 'yes'], Psych.safe_load_stream(yaml, schema: :json)
    end

    def test_load_file_accepts_schema
      Tempfile.create('scalar_schema') do |file|
        file.write '0o52'
        file.flush
        assert_equal 42, Psych.load_file(file.path, schema: :core)
        assert_equal 42, Psych.safe_load_file(file.path, schema: :core)
        assert_equal '0o52', Psych.unsafe_load_file(file.path, schema: :json)
      end
    end

    def test_unknown_schema_raises_argument_error
      assert_raise(ArgumentError) { Psych.load('x', schema: :bogus) }
      assert_raise(ArgumentError) { Psych.safe_load('x', schema: :bogus) }
      assert_raise(ArgumentError) { Psych.unsafe_load('x', schema: :bogus) }
      assert_raise(ArgumentError) { Psych.load_stream("--- x\n", schema: :bogus) }
      assert_raise(ArgumentError) { Psych.safe_load_stream("--- x\n", schema: :bogus) }
    end

    def test_schema_does_not_leak_between_calls
      assert_equal 42, Psych.load('0o52', schema: :core)
      assert_equal '0o52', Psych.load('0o52')
      assert_equal 'yes', Psych.safe_load('yes', schema: :json)
      assert_equal true, Psych.safe_load('yes')
    end

    private

    def assert_table table
      table.each do |yaml, *expected|
        SCHEMAS.zip(expected).each do |schema, exp|
          description = "Psych.unsafe_load(#{yaml.inspect}, schema: #{schema.inspect})"

          if ERROR.equal?(exp)
            assert_raise(Psych::ScalarSchemaError, description) do
              Psych.unsafe_load(yaml, schema: schema)
            end
          elsif NAN.equal?(exp)
            assert_predicate Psych.unsafe_load(yaml, schema: schema), :nan?, description
          else
            assert_equal exp, Psych.unsafe_load(yaml, schema: schema), description
          end
        end
      end
    end
  end
end

