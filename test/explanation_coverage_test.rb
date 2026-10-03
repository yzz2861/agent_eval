require 'test_helper'

# Extra edge cases for the explanation builder's internal branches.
class ExplanationCoverageTest < Minitest::Test
  def explain(schema, instance, limit = nil)
    JSONSchemer.schema(schema).validate(
      instance,
      :output_format => 'explanation',
      :explanation_limit => limit
    )
  end

  def combo(output)
    output.fetch('errors').first
  end

  def test_merged_leaves_with_different_and_same_absolute_locations
    # same absolute schema via two refs + one inline copy with a different
    # absolute location but identical message
    schema = {
      'anyOf' => [
        { '$ref' => '#/$defs/a' },
        { '$ref' => '#/$defs/a' },
        { 'allOf' => [{ 'type' => 'integer', 'minimum' => 10 }] }
      ],
      '$defs' => { 'a' => { 'type' => 'integer', 'minimum' => 10 } }
    }
    node = combo(explain(schema, 3.5))
    leaves = node.fetch('errors')
    type_leaf = leaves.find { |leaf| leaf.fetch('type') == 'integer' }
    assert_equal([0, 1], type_leaf.fetch('branchIndexes'))
    refute(type_leaf.key?('absoluteKeywordLocations'))
    minimum_leaf = leaves.find { |leaf| leaf.fetch('type') == 'minimum' }
    assert_equal([0, 1], minimum_leaf.fetch('branchIndexes'))
  end

  def test_nested_combination_inside_branch_keeps_its_own_branches
    # a branch whose only content is an inner combination: collect_leaves
    # must stop at the inner combination's boundary
    schema = {
      'anyOf' => [
        { 'oneOf' => [{ 'const' => 'a' }, { 'const' => 'b' }] },
        { 'oneOf' => [{ 'const' => 'a' }, { 'const' => 'b' }] }
      ]
    }
    node = combo(explain(schema, 'c'))
    assert_equal('all_branches_failed', node.fetch('reason'))
    node.fetch('branches').each do |branch|
      inner = branch.fetch('errors').first
      assert_equal('all_branches_failed', inner.fetch('reason'))
      assert_equal(2, inner.fetch('branchCount'))
    end
  end

  def test_if_without_subschema_results_and_empty_details
    schema = { 'if' => true, 'then' => { 'type' => 'string' } }
    # if (boolean true) matches; then fails for an integer
    node = combo(explain(schema, 5))
    condition = node
    assert_equal('then_schema_failed', condition.fetch('reason'))
    refute(condition.fetch('condition').key?('annotations'))
  end

  def test_else_not_applied_when_if_matches
    schema = { 'if' => { 'type' => 'object' }, 'else' => { 'type' => 'string' }, 'minProperties' => 3 }
    output = explain(schema, {})
    skipped_else = output.fetch('annotations').find { |unit| unit['reason'] == 'else_not_applied' }
    assert(skipped_else)
    assert_equal('/else', skipped_else.fetch('keywordLocation'))
  end

  def test_then_failure_without_nested_details
    schema = { 'if' => { 'type' => 'object' }, 'then' => false }
    conditional = combo(explain(schema, {}))
    assert_equal('then_schema_failed', conditional.fetch('reason'))
    refute(conditional.key?('errors'))
  end

  def test_valid_subtree_without_nested_results
    schema = { 'oneOf' => [true, { 'const' => 1 }] }
    node = combo(explain(schema, 1))
    assert_equal('multiple_branches_matched', node.fetch('reason'))
    boolean_branch = node.fetch('branches').find { |branch| branch.fetch('branchIndex') == 0 }
    refute(boolean_branch.key?('annotations'))
  end

  def test_annotation_and_error_omitted_counts
    schema = {
      'anyOf' => (0...5).map { { 'type' => 'object', 'required' => ['a'], 'minProperties' => 3 } }
    }
    node = combo(explain(schema, {}, 1))
    assert(node.key?('branchOmittedCount'))
    branch = node.fetch('branches').first
    # one required leaf and one minProperties leaf, capped to one
    assert_equal(1, branch.fetch('errors').size)
    assert_equal(1, branch.fetch('errorOmittedCount'))
  end

  def test_merged_leaves_differing_only_by_relative_locations
    schema = {
      'anyOf' => [
        { 'properties' => { 'x' => { '$ref' => '#/$defs/p' } } },
        { 'properties' => { 'x' => { '$ref' => '#/$defs/p' } } }
      ],
      '$defs' => { 'p' => { 'type' => 'integer' } }
    }
    node = combo(explain(schema, { 'x' => 'nope' }))
    merged = node.fetch('errors').first
    assert_equal([0, 1], merged.fetch('branchIndexes'))
    assert_equal(2, merged.fetch('keywordLocations').size)
    refute(merged.key?('absoluteKeywordLocations'))
  end

  def test_unmerged_leaves_through_generic_wrapper_keep_per_branch_paths
    # only one branch has the shared leaf: nothing is hoisted, so collection
    # traverses the generic $ref wrapper without a branchIndex and keeps the
    # original branch attribution
    schema = {
      'anyOf' => [
        { '$ref' => '#/$defs/n' },
        { 'type' => 'string', 'minLength' => 3 }
      ],
      '$defs' => { 'n' => { 'type' => 'integer' } }
    }
    node = combo(explain(schema, 1.5))
    refute(node.key?('errors'))
    ref_branch = node.fetch('branches').find { |branch| branch.fetch('branchIndex') == 0 }
    assert_equal('integer', ref_branch.fetch('errors').first.fetch('errors').first.fetch('type'))
  end


  def test_conditional_failure_with_no_leaf_errors
    schema = { 'if' => { 'type' => 'object' }, 'then' => false }
    conditional = combo(explain(schema, {}))
    assert_equal('then_schema_failed', conditional.fetch('reason'))
    refute(conditional.key?('errors'))
  end

  def test_if_without_a_subschema_and_no_condition_children
    schema = { 'if' => true, 'then' => { 'type' => 'string' } }
    conditional = combo(explain(schema, 5))
    assert_equal(true, conditional.fetch('condition').fetch('conditionMatched'))
    refute(conditional.fetch('condition').key?('annotations'))
  end

  def test_skipped_else_is_reported_when_if_matches
    schema = { 'if' => { 'type' => 'object' }, 'else' => { 'type' => 'string' }, 'minProperties' => 3 }
    skipped = explain(schema, {}).fetch('annotations').find { |unit| unit['reason'] == 'else_not_applied' }
    assert(skipped)
    assert_equal('/else', skipped.fetch('keywordLocation'))
  end

  def test_conditional_failure_unit_without_details_or_leaves
    schema = { 'if' => { 'const' => 5 }, 'then' => false }
    conditional = combo(explain(schema, 5))
    assert_equal('then_schema_failed', conditional.fetch('reason'))
    refute(conditional.key?('details'))
    refute(conditional.key?('errors'))
  end

  def test_empty_errors_array_is_removed_from_annotated_branch
    # matched branch containing a boolean subschema produces no annotations
    schema = { 'oneOf' => [true, { 'const' => 1 }] }
    branch = combo(explain(schema, 1)).fetch('branches').first
    refute(branch.key?('errors'))
  end

  def test_limit_zero_never_removes_the_combination_reason
    schema = { 'anyOf' => (0...3).map { |index| { 'const' => index } } }
    node = combo(explain(schema, 'x', 0))
    assert_equal('all_branches_failed', node.fetch('reason'))
    assert_equal(3, node.fetch('branchCount'))
    assert_equal(3, node.fetch('branchOmittedCount'))
    assert_equal([], node.fetch('branches'))
  end

  def test_limit_zero_preserves_multiple_matches_reason
    schema = { 'oneOf' => [{ 'type' => 'integer' }, { 'minimum' => 0 }, { 'type' => 'string' }] }
    node = combo(explain(schema, 5, 0))
    assert_equal('multiple_branches_matched', node.fetch('reason'))
    assert_equal([0, 1], node.fetch('matchedBranchIndexes'))
    assert(node.fetch('branches').all? { |branch| branch.fetch('valid') })
    assert(node.fetch('branchOmittedCount') >= 1)
  end


end
