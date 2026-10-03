require 'test_helper'

class ExplanationTest < Minitest::Test
  def explain(schema, instance, limit = nil, **options)
    JSONSchemer.schema(schema, **options).validate(
      instance,
      :output_format => 'explanation',
      :explanation_limit => limit
    )
  end

  def root_errors(output)
    output.fetch('errors').first
  end

  def test_valid_instance_returns_flag_like_unit
    output = explain({ 'type' => 'string' }, 'x')
    assert_equal(
      {
        'valid' => true,
        'keywordLocation' => '',
        'absoluteKeywordLocation' => 'json-schemer://schema#',
        'instanceLocation' => ''
      },
      output
    )
  end

  def test_any_of_all_branches_failed_preserves_branch_tree_and_locations
    schema = {
      'anyOf' => [
        { 'type' => 'string' },
        { 'type' => 'integer', 'minimum' => 10 }
      ]
    }
    node = root_errors(explain(schema, 3.5))

    assert_equal('anyOf', node.fetch('keyword'))
    assert_equal('all_branches_failed', node.fetch('reason'))
    assert_equal(2, node.fetch('branchCount'))
    refute(node.key?('matchedBranchIndexes'))

    branches = node.fetch('branches')
    assert_equal([0, 1], branches.map { |branch| branch.fetch('branchIndex') })
    assert_equal(['/anyOf/0', '/anyOf/1'], branches.map { |branch| branch.fetch('keywordLocation') })
    assert_equal(['', ''], branches.map { |branch| branch.fetch('instanceLocation') })

    leaf = branches.dig(1, 'errors', 1)
    assert_equal('/anyOf/1/minimum', leaf.fetch('keywordLocation'))
    assert_equal('json-schemer://schema#/anyOf/1/minimum', leaf.fetch('absoluteKeywordLocation'))
    assert_equal('minimum', leaf.fetch('type'))
  end

  def test_identical_leaves_shared_by_branches_are_merged
    schema = {
      'anyOf' => [
        { '$ref' => '#/$defs/n' },
        { '$ref' => '#/$defs/n' }
      ],
      '$defs' => { 'n' => { 'type' => 'integer', 'minimum' => 10 } }
    }
    node = root_errors(explain(schema, 3.5))

    merged = node.fetch('errors')
    assert_equal(['integer', 'minimum'], merged.map { |leaf| leaf.fetch('type') })
    type_error = merged.first
    assert_equal(2, type_error.fetch('occurrenceCount'))
    assert_equal([0, 1], type_error.fetch('branchIndexes'))
    assert_equal(['/anyOf/0/$ref/type', '/anyOf/1/$ref/type'], type_error.fetch('keywordLocations'))
    assert_equal('json-schemer://schema#/$defs/n/type', type_error.fetch('absoluteKeywordLocation'))
    # branches are retained but no longer repeat the leaf
    assert(node.fetch('branches').all? { |branch| !branch.key?('errors') })
  end

  def test_identical_leaves_in_nested_combination_branches_are_not_hoisted
    schema = {
      'anyOf' => [
        { 'oneOf' => [{ 'type' => 'integer' }, { 'minimum' => 0 }] },
        { 'oneOf' => [{ 'type' => 'integer' }, { 'minimum' => 0 }] }
      ]
    }
    node = root_errors(explain(schema, 5))
    assert_equal('all_branches_failed', node.fetch('reason'))
    refute(node.key?('errors'))
    node.fetch('branches').each do |branch|
      inner = branch.fetch('errors').first
      assert_equal('multiple_branches_matched', inner.fetch('reason'))
      assert_equal([0, 1], inner.fetch('matchedBranchIndexes'))
    end
  end

  def test_one_of_all_branches_failed_is_distinct_from_multiple_matches
    schema = { 'oneOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] }
    all_failed = root_errors(explain(schema, true))
    assert_equal('all_branches_failed', all_failed.fetch('reason'))
    refute(all_failed.key?('matchedBranchIndexes'))

    schema2 = { 'oneOf' => [{ 'type' => 'integer' }, { 'minimum' => 0 }, { 'const' => 5 }] }
    multiple = root_errors(explain(schema2, 5))
    assert_equal('multiple_branches_matched', multiple.fetch('reason'))
    assert_equal([0, 1, 2], multiple.fetch('matchedBranchIndexes'))
    branches = multiple.fetch('branches')
    assert_equal([true, true, true], branches.map { |branch| branch.fetch('valid') })
    assert_equal('type', branches.dig(0, 'annotations', 0).fetch('keywordLocation').split('/').last)
  end

  def test_all_of_reports_matched_and_failed_branches
    schema = { 'allOf' => [{ 'type' => 'integer' }, { 'minimum' => 10 }] }
    node = root_errors(explain(schema, 5))
    assert_equal('all_branches_required', node.fetch('reason'))
    assert_equal([0], node.fetch('matchedBranchIndexes'))
    branches = node.fetch('branches')
    assert_equal(true, branches.first.fetch('valid'))
    assert_equal(false, branches.last.fetch('valid'))
    assert_equal('minimum', branches.last.fetch('errors').first.fetch('type'))
  end

  def test_not_failure_explains_the_matched_schema
    schema = { 'not' => { 'type' => 'integer', 'minimum' => 5 } }
    node = root_errors(explain(schema, 7))
    assert_equal('not_schema_matched', node.fetch('reason'))
    matched = node.fetch('annotations')
    keywords = matched.map { |child| child.fetch('keywordLocation') }
    assert_includes(keywords, '/not/type')
    assert_includes(keywords, '/not/minimum')
  end

  def test_nested_not_has_accurate_meaning
    schema = { 'not' => { 'not' => { 'type' => 'integer' } } }
    # x is not an integer so the inner not matches; the outer not fails
    node = root_errors(explain(schema, 'x'))
    assert_equal('not_schema_matched', node.fetch('reason'))
    inner = node.fetch('annotations').first
    assert_equal('/not/not', inner.fetch('keywordLocation'))
    assert_equal(true, inner.fetch('valid'))
  end

  def test_not_failure_through_matched_any_of_branch
    # the value matches an anyOf branch inside not, so not fails; the matched
    # branch tree must name the matching branch.
    schema = { 'not' => { 'anyOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] } }
    node = root_errors(explain(schema, 'x'))
    any_of = node.fetch('annotations').first
    assert_equal('anyOf', any_of.fetch('keyword'))
    matched_branch = any_of.fetch('annotations').find { |branch| branch.fetch('valid') }
    assert_equal(0, matched_branch.fetch('branchIndex'))
    assert_equal('/not/anyOf/0/type', matched_branch.fetch('annotations').first.fetch('keywordLocation'))
  end

  def test_then_failure_when_if_matches
    schema = { 'if' => { 'type' => 'object' }, 'then' => { 'required' => ['a'] } }
    conditional = root_errors(explain(schema, {}))
    assert_equal('/then', conditional.fetch('keywordLocation'))
    assert_equal('then', conditional.fetch('keyword'))
    assert_equal('then_schema_failed', conditional.fetch('reason'))
    assert_equal(true, conditional.fetch('conditionMatched'))
    assert_equal('required', conditional.fetch('errors').first.fetch('type'))
    assert_equal(true, conditional.fetch('condition').fetch('conditionMatched'))
  end

  def test_else_failure_when_if_does_not_match
    schema = { 'if' => { 'type' => 'object' }, 'else' => { 'type' => 'string' } }
    conditional = root_errors(explain(schema, 5))
    assert_equal('/else', conditional.fetch('keywordLocation'))
    assert_equal('else', conditional.fetch('keyword'))
    assert_equal('else_schema_failed', conditional.fetch('reason'))
    assert_equal(true, conditional.fetch('conditionMatched'))
    condition = conditional.fetch('condition')
    assert_equal(false, condition.fetch('conditionMatched'))
    assert_equal('object', condition.fetch('errors').first.fetch('type'))
  end

  def test_non_applied_conditional_is_not_reported_as_failure
    schema = { 'if' => { 'type' => 'object' }, 'then' => { 'required' => ['a'] } }
    assert(explain(schema, 'x').fetch('valid'))
  end

  def test_skipped_then_is_informational_when_else_applied
    # if does not match: then is skipped (its result is nil) and else applies
    schema = { 'if' => { 'type' => 'object' }, 'then' => { 'required' => ['a'] }, 'else' => { 'type' => 'integer' } }
    node = root_errors(explain(schema, 'x'))
    # only the else failure is reported; there is no fabricated then failure
    conditional = node
    assert_equal('else_schema_failed', conditional.fetch('reason'))
    assert_equal('else', conditional.fetch('keyword'))
    skipped_then = explain(schema, 'x').fetch('annotations').find { |unit| unit['reason'] == 'then_not_applied' }
    assert(skipped_then)
    assert_equal(true, skipped_then.fetch('valid'))
  end

  def test_matched_one_of_branch_with_inner_combination
    schema = {
      'oneOf' => [
        { 'anyOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] },
        { 'const' => 'x' }
      ]
    }
    # "x" matches both branch 0 (inner string) and branch 1 (const)
    node = root_errors(explain(schema, 'x'))
    assert_equal('multiple_branches_matched', node.fetch('reason'))
    inner_any_of = node.fetch('branches').first.fetch('annotations').first
    assert_equal('anyOf', inner_any_of.fetch('keyword'))
    matched = inner_any_of.fetch('annotations').find { |branch| branch.fetch('valid') }
    assert_equal(0, matched.fetch('branchIndex'))
    # 5 matches only the inner integer, so one top branch matches -> valid
    assert(explain(schema, 5).fetch('valid'))
  end

  def test_invalid_nested_result_inside_matched_subtree_is_rendered
    # the matched oneOf branch contains an inner `not` (whose subschema fails),
    # exercising the nested combination path inside a successful subtree
    schema = {
      'oneOf' => [
        { 'allOf' => [{ 'type' => 'integer' }, { 'not' => { 'const' => 9 } }] },
        { 'minimum' => 0 }
      ]
    }
    node = root_errors(explain(schema, 5))
    assert_equal('multiple_branches_matched', node.fetch('reason'))
    matched = node.fetch('branches').first
    all_of = matched.fetch('annotations').first
    not_branch = all_of.fetch('annotations').find { |branch| branch.fetch('branchIndex') == 1 }
    not_node = not_branch.fetch('annotations').first
    assert_equal(true, not_node.fetch('valid'))
    inner = not_node.fetch('annotations').first
    assert_equal('const', inner.fetch('errors').first.fetch('type'))
  end

  def test_skipped_conditional_branch_is_informational
    schema = {
      'if' => { 'type' => 'object' },
      'then' => { 'required' => ['a'] },
      'else' => { 'type' => 'string' },
      'minLength' => 2
    }
    output = explain(schema, 'x')
    else_node = output.fetch('annotations').first
    assert_equal('else_schema_passed', else_node.fetch('reason'))
    assert_equal(true, else_node.fetch('valid'))
    assert_equal(true, else_node.fetch('conditionMatched'))
    refute(else_node.key?('error'))
    # the real failure is still reported
    assert_equal('minLength', root_errors(output).fetch('type'))
  end

  def test_absent_else_when_if_matches_is_not_reported
    schema = { 'if' => { 'type' => 'object' }, 'then' => { 'required' => ['a'] }, 'minProperties' => 5 }
    node = root_errors(explain(schema, {}))
    reasons = [node, *node.fetch('errors')].map { |unit| unit['reason'] }.compact
    assert_includes(reasons, 'then_schema_failed')
    refute_includes(reasons, 'else_not_applied')
  end

  def test_passed_applied_conditional_is_informational
    schema = {
      'if' => { 'type' => 'object' },
      'then' => { 'required' => ['a'] },
      'minProperties' => 5
    }
    output = explain(schema, { 'a' => 1 })
    then_node = output.fetch('annotations').first
    assert_equal('then_schema_passed', then_node.fetch('reason'))
    assert_equal(true, then_node.fetch('valid'))
    assert_equal('minProperties', root_errors(output).fetch('type'))
  end

  def test_limit_caps_branches_and_reports_omitted_count
    schema = { 'anyOf' => (0...6).map { |index| { 'const' => 'v' + index.to_s } } }
    node = root_errors(explain(schema, 'x', 2))
    assert_equal(6, node.fetch('branchCount'))
    assert_equal(2, node.fetch('branches').size)
    assert_equal(4, node.fetch('branchOmittedCount'))
  end

  def test_limit_keeps_matched_one_of_branches
    schema = {
      'oneOf' => [
        { 'type' => 'integer' },
        { 'minimum' => 0 },
        { 'const' => 5 },
        { 'type' => 'string' }
      ]
    }
    node = root_errors(explain(schema, 5, 2))
    assert_equal('multiple_branches_matched', node.fetch('reason'))
    assert_equal([0, 1, 2], node.fetch('matchedBranchIndexes'))
    assert(node.fetch('branches').all? { |branch| branch.fetch('valid') })
    # all 3 matched branches are protected even though the limit is 2; only the
    # failing branch is omitted
    assert_equal(1, node.fetch('branchOmittedCount'))
  end

  def test_limit_caps_leaves_and_reports_error_omitted_count
    schema = { 'allOf' => [{ 'type' => 'object', 'required' => ['a'], 'minProperties' => 3 }] }
    node = root_errors(explain(schema, {}, 1))
    branch = node.fetch('branches').first
    assert_equal(1, branch.fetch('errors').size)
    assert_equal(1, branch.fetch('errorOmittedCount'))
  end

  def test_details_are_preserved_in_leaves
    schema = { 'anyOf' => [{ '$ref' => '#/$defs/o' }], '$defs' => { 'o' => { 'required' => ['a'] } } }
    leaf = root_errors(explain(schema, {})).fetch('branches').first
    required = leaf.fetch('errors').first.fetch('errors').first
    assert_equal('required', required.fetch('type'))
    assert_equal({ 'missing_keys' => ['a'] }, required.fetch('details'))
  end

  def test_explanation_agrees_with_valid_for_branched_cases
    schema = {
      'anyOf' => [{ 'type' => 'string' }, { 'oneOf' => [{ 'minimum' => 0 }, { 'const' => 5 }] }],
      'not' => { 'const' => 'bad' }
    }
    schemer = JSONSchemer.schema(schema)
    ['x', 5, -1, 10, 'bad'].each do |instance|
      explanation = schemer.validate(instance, :output_format => 'explanation')
      assert_equal(schemer.valid?(instance), explanation.fetch('valid'), instance.inspect)
    end
  end

  def test_standard_output_formats_are_unchanged
    schema = { 'anyOf' => [{ 'type' => 'string' }] }
    schemer = JSONSchemer.schema(schema)
    ['classic', 'flag', 'basic', 'detailed', 'verbose'].each do |format|
      output = schemer.validate(5, :output_format => format, :resolve_enumerators => true)
      refute_nil(output)
    end
    assert_equal(false, schemer.valid?(5))
  end

  def test_x_error_marker_is_retained
    schema = { 'anyOf' => [{ 'type' => 'string', 'x-error' => 'must be string' }] }
    leaf = root_errors(explain(schema, 5)).fetch('branches').first.fetch('errors').first
    assert_equal('must be string', leaf.fetch('error'))
    assert(leaf.fetch('x-error'))
  end
end
