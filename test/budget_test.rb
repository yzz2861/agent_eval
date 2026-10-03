require 'test_helper'

class BudgetTest < Minitest::Test
  def test_budget_defaults_do_not_change_validation_results
    schema = JSONSchemer.schema({ 'type' => 'integer' })
    assert(schema.valid?(1, :budget => JSONSchemer::Budget.new))
    refute(schema.valid?('x', :budget => JSONSchemer::Budget.new))
    assert_equal([], schema.validate(1, :budget => JSONSchemer::Budget.new).to_a)
    assert_equal(1, schema.validate('x', :budget => JSONSchemer::Budget.new).to_a.size)
  end

  def test_budget_accepts_options_hash
    schema = JSONSchemer.schema({ 'type' => 'integer' })
    error = assert_raises(JSONSchemer::BudgetExceeded) do
      schema.validate('x', :budget => { :max_keyword_evaluations => 0 }).to_a
    end
    assert_equal('keyword evaluations', error.message[/keyword evaluations/])
  end

  def test_keyword_evaluation_budget_is_not_reported_as_valid_or_invalid
    schema = JSONSchemer.schema(
      { 'allOf' => [{ 'type' => 'integer' }, { 'minimum' => 0 }] }
    )
    assert_raises(JSONSchemer::IncompleteValidation) do
      schema.valid?('x', :budget => JSONSchemer::Budget.new(:max_keyword_evaluations => 2))
    end
    budget = JSONSchemer::Budget.new(:max_keyword_evaluations => 2)
    error = assert_raises(JSONSchemer::BudgetExceeded) do
      schema.valid?('x', :budget => budget)
    end
    assert_equal(3, error.used)
    assert_equal(2, error.limit)
    assert_equal(3, budget.keyword_evaluations)
    assert_equal(error.budget, budget)
  end

  def test_keyword_evaluation_budget_counts_all_anyof_branches
    # all branches share the same budget when neither branch matches
    schema = JSONSchemer.schema(
      { 'anyOf' => [{ 'type' => 'integer' }, { 'type' => 'string' }] }
    )
    budget = JSONSchemer::Budget.new(:max_keyword_evaluations => 2)
    error = assert_raises(JSONSchemer::BudgetExceeded) do
      schema.validate([], :budget => budget).to_a
    end
    assert_equal(3, error.used)
    assert(schema.valid?('x'))
  end

  def test_keyword_evaluation_budget_counts_custom_keywords
    schema = JSONSchemer.schema(
      { 'x-custom' => true },
      :keywords => {
        'x-custom' => proc { |instance, curr_schema| curr_schema.fetch('x-custom') == instance.is_a?(Integer) }
      }
    )
    assert(schema.valid?(1, :budget => JSONSchemer::Budget.new))
    assert_raises(JSONSchemer::BudgetExceeded) do
      schema.valid?(1, :budget => JSONSchemer::Budget.new(:max_keyword_evaluations => 1))
    end
  end

  def test_reusing_schema_does_not_share_remaining_budget
    schema = JSONSchemer.schema({ 'type' => 'integer' })
    2.times do
      budget = JSONSchemer::Budget.new(:max_keyword_evaluations => 1)
      assert(schema.valid?(1, :budget => budget))
      assert_equal(1, budget.keyword_evaluations)
    end
  end

  def test_shared_budget_instance_accumulates_across_validate_calls
    schema = JSONSchemer.schema({ 'type' => 'integer' })
    budget = JSONSchemer::Budget.new(:max_keyword_evaluations => 2)
    schema.valid?(1, :budget => budget)
    schema.valid?(1, :budget => budget)
    assert_raises(JSONSchemer::BudgetExceeded) { schema.valid?(1, :budget => budget) }
  end

  def test_ref_depth_budget_tracks_nested_reference_expansion
    schema = {
      '$defs' => {
        'a' => { '$ref' => '#/$defs/b' },
        'b' => { '$ref' => '#/$defs/c' },
        'c' => { 'type' => 'integer' }
      },
      'allOf' => [{ '$ref' => '#/$defs/a' }]
    }
    schemer = JSONSchemer.schema(schema)
    assert(schemer.valid?(1, :budget => JSONSchemer::Budget.new(:max_ref_depth => 3)))
    budget = JSONSchemer::Budget.new(:max_ref_depth => 2)
    error = assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?('x', :budget => budget)
    end
    assert_equal(3, error.used)
    assert_equal(2, error.limit)
    assert_operator(budget.ref_depth, :>=, 1)
  end

  def test_ref_depth_budget_covers_dynamic_refs
    schema = {
      '$defs' => {
        'node' => {
          '$dynamicAnchor' => 'value',
          'type' => 'integer'
        }
      },
      '$dynamicRef' => '#value'
    }
    schemer = JSONSchemer.schema(schema)
    assert(schemer.valid?(1))
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?('x', :budget => JSONSchemer::Budget.new(:max_ref_depth => 0))
    end
  end

  def test_ref_depth_budget_covers_recursive_refs
    schema = {
      '$defs' => {
        'a' => { 'type' => 'integer' }
      },
      '$recursiveRef' => '#/$defs/a'
    }
    schemer = JSONSchemer.schema(schema, :meta_schema => JSONSchemer.draft201909)
    assert(schemer.valid?(1))
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?('x', :budget => JSONSchemer::Budget.new(:max_ref_depth => 0))
    end
  end

  def test_cancellation_is_checked_when_entering_a_reference
    schema = { '$ref' => '#/$defs/target', '$defs' => { 'target' => { 'type' => 'integer' } } }
    schemer = JSONSchemer.schema(schema)
    budget = JSONSchemer::Budget.new(:max_keyword_evaluations => 1)
    assert_raises(JSONSchemer::BudgetExceeded) do
      schemer.valid?(1, :budget => budget)
    end
    # a pre-cancelled budget is checked when entering the reference
    cancelled = JSONSchemer::Budget.new
    cancelled.keyword_evaluation!
    cancelled.cancel!
    assert_raises(JSONSchemer::ValidationCancelled) do
      schemer.valid?(1, :budget => cancelled)
    end
    assert_equal(0, cancelled.ref_depth)
    # cancellation during remote reference resolution is also checked
    cancelling = JSONSchemer::Budget.new
    ref_resolver = proc do |_uri|
      cancelling.cancel!
      { 'type' => 'integer' }
    end
    remote = JSONSchemer.schema({ '$ref' => 'http://example.com/target' }, :ref_resolver => ref_resolver)
    assert_raises(JSONSchemer::ValidationCancelled) do
      remote.valid?(1, :budget => cancelling)
    end
    assert_equal(0, cancelling.ref_depth)
  end

  def test_error_budget_limits_classic_output
    schema = JSONSchemer.schema(
      { 'properties' => (1..6).to_h { |i| [i.to_s, { 'type' => 'integer' }] } }
    )
    data = (1..6).to_h { |i| [i.to_s, 'x'] }
    budget = JSONSchemer::Budget.new(:max_errors => 3)
    enumerator = schema.validate(data, :budget => budget)
    assert_raises(JSONSchemer::BudgetExceeded) { enumerator.to_a }
    assert_equal(4, budget.errors)
  end

  def test_error_budget_limits_basic_output
    schema = JSONSchemer.schema(
      { 'properties' => (1..6).to_h { |i| [i.to_s, { 'type' => 'integer' }] } }
    )
    data = (1..6).to_h { |i| [i.to_s, 'x'] }
    budget = JSONSchemer::Budget.new(:max_errors => 3)
    output = schema.validate(data, :output_format => 'basic', :budget => budget)
    assert_raises(JSONSchemer::BudgetExceeded) { output.fetch('errors').to_a }
    assert_equal(4, budget.errors)
  end

  def test_error_budget_does_not_count_valid_outputs
    schema = JSONSchemer.schema(
      { 'properties' => (1..6).to_h { |i| [i.to_s, { 'type' => 'integer' }] } }
    )
    data = (1..6).to_h { |i| [i.to_s, i] }
    budget = JSONSchemer::Budget.new(:max_errors => 0)
    output = schema.validate(data, :output_format => 'basic', :budget => budget)
    assert(output.fetch('valid'))
    assert_equal(0, budget.errors)
  end

  def test_precancelled_budget_never_returns_valid
    schema = JSONSchemer.schema({ 'type' => 'integer' })
    budget = JSONSchemer::Budget.new
    budget.cancel!
    assert_raises(JSONSchemer::ValidationCancelled) { schema.valid?(1, :budget => budget) }
    assert_raises(JSONSchemer::IncompleteValidation) { schema.valid?('x', :budget => budget) }
  end

  def test_cancel_from_property_hook
    cancelled_budget = JSONSchemer::Budget.new
    schema = JSONSchemer.schema(
      {
        'properties' => {
          'a' => { 'type' => 'integer' },
          'b' => { 'type' => 'integer' }
        }
      },
      :before_property_validation => [proc { cancelled_budget.cancel! }]
    )
    assert_raises(JSONSchemer::ValidationCancelled) do
      schema.validate({ 'a' => 1, 'b' => 'x' }, :budget => cancelled_budget).to_a
    end
  end

  def test_cancel_from_another_thread
    queue = Queue.new
    threaded_schema = JSONSchemer.schema(
      { 'type' => 'object', 'properties' => { 'a' => {} } },
      :before_property_validation => [proc { queue.pop }]
    )
    threaded_budget = JSONSchemer::Budget.new
    thread = Thread.new do
      begin
        threaded_schema.validate({ 'a' => 1 }, :budget => threaded_budget).to_a
      rescue JSONSchemer::ValidationCancelled
        nil
      end
    end
    queue.push(:go)
    threaded_budget.cancel!
    assert_nil(thread.value)
    assert(threaded_budget.cancelled?)
  end

  def test_cancel_during_error_enumeration
    schema = JSONSchemer.schema(
      { 'properties' => (1..4).to_h { |i| [i.to_s, { 'type' => 'integer' }] } }
    )
    data = (1..4).to_h { |i| [i.to_s, 'x'] }
    budget = JSONSchemer::Budget.new
    enumerator = schema.validate(data, :budget => budget)
    enumerator.next
    budget.cancel!
    assert_raises(JSONSchemer::ValidationCancelled) { enumerator.to_a }
  end

  def test_validation_runs_complete_without_budget
    schema = JSONSchemer.schema({ 'type' => 'integer' })
    assert(schema.valid?(1))
    refute(schema.valid?('x'))
    assert_equal(1, schema.validate('x').to_a.size)
  end

  def test_budget_works_with_resolved_enumerators
    schema = JSONSchemer.schema(
      { 'properties' => (1..4).to_h { |i| [i.to_s, { 'type' => 'integer' }] } }
    )
    data = (1..4).to_h { |i| [i.to_s, 'x'] }
    budget = JSONSchemer::Budget.new(:max_errors => 2)
    assert_raises(JSONSchemer::BudgetExceeded) do
      schema.validate(data, :resolve_enumerators => true, :budget => budget)
    end
  end

  def test_meta_schema_validation_passes_budget
    assert_raises(JSONSchemer::BudgetExceeded) do
      JSONSchemer.draft202012.validate(
        { 'type' => 'object' },
        :budget => { :max_keyword_evaluations => 0 }
      ).to_a
    end
  end
end
