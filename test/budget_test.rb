require 'test_helper'

class BudgetTest < Minitest::Test
  KEYWORD_COUNT_SCHEMA = {
    'type' => 'object',
    'properties' => {
      'a' => { 'type' => 'integer' },
      'b' => { 'type' => 'string' }
    }
  }.freeze

  ERROR_COUNT_SCHEMA = {
    'type' => 'object',
    'properties' => {
      'a' => { 'type' => 'integer' },
      'b' => { 'type' => 'integer' },
      'c' => { 'type' => 'integer' }
    }
  }.freeze

  REF_CHAIN_SCHEMA = {
    '$defs' => {
      'a' => { '$ref' => '#/$defs/b' },
      'b' => { '$ref' => '#/$defs/c' },
      'c' => { 'type' => 'integer' }
    },
    '$ref' => '#/$defs/a'
  }.freeze

  def test_keyword_evaluation_budget
    schemer = JSONSchemer.schema(KEYWORD_COUNT_SCHEMA)
    data = { 'a' => 1, 'b' => 'x' }

    # root evaluates "type" and "properties"; each property subschema evaluates "type"
    assert schemer.valid?(data, max_keyword_evaluations: 4)

    error = assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?(data, max_keyword_evaluations: 3)
    end
    assert_kind_of JSONSchemer::ValidationIncomplete, error
    assert_match 'keyword evaluation', error.message
  end

  def test_keyword_evaluation_budget_is_shared_across_subschemas_and_any_of
    schemer = JSONSchemer.schema({
      'anyOf' => [
        { 'type' => 'integer' },
        { 'type' => 'string' },
        { 'type' => 'boolean' }
      ]
    })

    # "anyOf" plus one "type" evaluation per branch, even after a branch matches
    assert schemer.valid?('x', max_keyword_evaluations: 4)
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?('x', max_keyword_evaluations: 3)
    end
  end

  def test_keyword_evaluation_budget_with_explicit_budget
    schemer = JSONSchemer.schema(KEYWORD_COUNT_SCHEMA)
    budget = JSONSchemer::Budget.new(max_keyword_evaluations: 3)
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?({ 'a' => 1, 'b' => 'x' }, budget: budget)
    end
  end

  def test_budget_is_not_shared_between_validations
    schemer = JSONSchemer.schema(KEYWORD_COUNT_SCHEMA)
    data = { 'a' => 1, 'b' => 'x' }

    2.times { assert schemer.valid?(data, max_keyword_evaluations: 4) }
    2.times do
      assert_raises(JSONSchemer::BudgetExceeded) do
        schemer.valid?(data, max_keyword_evaluations: 3)
      end
    end
  end

  def test_ref_depth_budget
    schemer = JSONSchemer.schema(REF_CHAIN_SCHEMA)

    assert schemer.valid?(1, max_ref_depth: 3)

    error = assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?(1, max_ref_depth: 2)
    end
    assert_kind_of JSONSchemer::ValidationIncomplete, error
    assert_match 'reference depth', error.message
  end

  def test_ref_depth_budget_stops_self_recursive_refs
    schemer = JSONSchemer.schema({ '$ref' => '#' })
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?(1, max_ref_depth: 5)
    end
  end

  def test_ref_depth_budget_stops_recursive_items
    schemer = JSONSchemer.schema({ 'items' => { '$ref' => '#' } })
    data = []
    current = data
    20.times do
      nested = []
      current << nested
      current = nested
    end
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?(data, max_ref_depth: 10)
    end
  end

  def test_ref_depth_returns_to_zero_after_validation
    schemer = JSONSchemer.schema(REF_CHAIN_SCHEMA)
    budget = JSONSchemer::Budget.new
    assert schemer.valid?(1, budget: budget)
    assert_equal 0, budget.ref_depth
  end

  def test_error_budget_with_lazy_classic_enumerator
    schemer = JSONSchemer.schema(ERROR_COUNT_SCHEMA)
    data = { 'a' => 'x', 'b' => 'y', 'c' => 'z' }

    errors = schemer.validate(data, max_errors: 2)
    assert_equal 2, errors.first(2).size
    error = assert_raises(JSONSchemer::BudgetExceeded) { errors.to_a }
    assert_kind_of JSONSchemer::ValidationIncomplete, error
    assert_match 'error budget', error.message

    assert_equal 3, schemer.validate(data, max_errors: 3).to_a.size
  end

  def test_error_budget_with_resolve_enumerators
    schemer = JSONSchemer.schema(ERROR_COUNT_SCHEMA)
    data = { 'a' => 'x', 'b' => 'y', 'c' => 'z' }

    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.validate(data, max_errors: 2, resolve_enumerators: true)
    end
  end

  def test_error_budget_with_structured_output_formats
    schemer = JSONSchemer.schema(ERROR_COUNT_SCHEMA)
    data = { 'a' => 'x', 'b' => 'y', 'c' => 'z' }

    %w[basic detailed verbose].each do |output_format|
      output = schemer.validate(data, output_format: output_format, max_errors: 1)
      assert_raises(JSONSchemer::BudgetExceeded) { output.fetch('errors').to_a }
    end
  end

  def test_error_budget_does_not_affect_flag_output
    schemer = JSONSchemer.schema(ERROR_COUNT_SCHEMA)
    refute schemer.valid?({ 'a' => 'x', 'b' => 'y', 'c' => 'z' }, max_errors: 0)
  end

  def test_cancellation_before_validation
    schemer = JSONSchemer.schema(KEYWORD_COUNT_SCHEMA)
    budget = JSONSchemer::Budget.new
    budget.cancel!
    assert budget.cancelled?

    error = assert_raises(JSONSchemer::ValidationCancelled) do
      schemer.valid?({ 'a' => 1, 'b' => 'x' }, budget: budget)
    end
    assert_kind_of JSONSchemer::ValidationIncomplete, error
  end

  def test_cancellation_during_validation
    budget = JSONSchemer::Budget.new
    schemer = JSONSchemer.schema(
      KEYWORD_COUNT_SCHEMA,
      before_property_validation: proc { |_instance, property, _subschema, _schema| budget.cancel! if property == 'a' }
    )

    assert_raises(JSONSchemer::ValidationCancelled) do
      schemer.valid?({ 'a' => 1, 'b' => 'x' }, budget: budget)
    end
  end

  def test_cancellation_during_output_enumeration
    schemer = JSONSchemer.schema(ERROR_COUNT_SCHEMA)
    budget = JSONSchemer::Budget.new
    errors = schemer.validate({ 'a' => 'x', 'b' => 'y', 'c' => 'z' }, budget: budget)

    assert_equal '/a', errors.next.fetch('data_pointer')
    budget.cancel!
    assert_raises(JSONSchemer::ValidationCancelled) { errors.next }
  end

  def test_cancellation_after_last_keyword_evaluation
    budget = JSONSchemer::Budget.new
    schemer = JSONSchemer.schema(
      { 'even' => true },
      keywords: { 'even' => proc { |_instance, _schema, _pointer| budget.cancel! || true } }
    )

    assert_raises(JSONSchemer::ValidationCancelled) do
      schemer.valid?(2, budget: budget)
    end
  end

  def test_budget_counters
    schemer = JSONSchemer.schema(ERROR_COUNT_SCHEMA)
    budget = JSONSchemer::Budget.new(max_keyword_evaluations: 100, max_ref_depth: 100, max_errors: 100)

    errors = schemer.validate({ 'a' => 'x', 'b' => 'y', 'c' => 'z' }, budget: budget).to_a

    assert_equal 3, errors.size
    assert_equal 5, budget.keyword_evaluations
    assert_equal 3, budget.errors
    assert_equal 0, budget.ref_depth
    assert_equal 100, budget.max_keyword_evaluations
    assert_equal 100, budget.max_ref_depth
    assert_equal 100, budget.max_errors
    refute budget.cancelled?
  end

  def test_validate_schema_forwards_budget
    assert_raises(JSONSchemer::BudgetExceeded) do
      JSONSchemer.validate_schema({ 'type' => 'integer' }, max_keyword_evaluations: 1)
    end
    assert_raises(JSONSchemer::BudgetExceeded) do
      JSONSchemer.valid_schema?({ 'type' => 'integer' }, max_keyword_evaluations: 1)
    end
  end
end
