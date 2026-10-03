require 'test_helper'

class ExplanationTest < Minitest::Test
  def explained(schemer, instance, **options)
    output = schemer.validate(instance, :output_format => 'explained', **options)
    assert_equal(schemer.valid?(instance), output.fetch('valid'), 'explained output disagrees with valid?')
    output
  end

  def leaf(message, keyword, instance_location, schema_location, type, extra = {})
    {
      'message' => message,
      'keyword' => keyword,
      'instanceLocation' => instance_location,
      'schemaLocation' => schema_location,
      'type' => type
    }.merge(extra)
  end

  def any_of_schemer
    JSONSchemer.schema({
      'properties' => {
        'value' => {
          'anyOf' => [
            { 'type' => 'string', 'minLength' => 5 },
            { 'type' => 'string', 'pattern' => '^a' },
            { 'type' => 'integer', 'minimum' => 10 }
          ]
        }
      }
    })
  end

  def one_of_schemer
    JSONSchemer.schema({
      'oneOf' => [
        { 'type' => 'string' },
        { 'type' => 'string', 'minLength' => 2 },
        { 'type' => 'integer' }
      ]
    })
  end

  def pattern_any_of_schemer(branch_count, **options)
    JSONSchemer.schema({ 'anyOf' => (1..branch_count).map { |i| { 'type' => 'string', 'pattern' => "^p#{i}" } } }, **options)
  end

  def test_explained_any_of_all_branches_failed
    output = explained(any_of_schemer, { 'value' => 3 })
    assert_equal(false, output['valid'])

    root = output['explanation']
    assert_equal('value at root does not match schema', root['message'])
    assert_equal('', root['instanceLocation'])
    assert_equal('', root['schemaLocation'])

    properties = root['errors'].first
    assert_equal('properties', properties['keyword'])

    value = properties['errors'].first
    assert_equal('/value', value['instanceLocation'])
    assert_equal('/properties/value', value['schemaLocation'])

    any_of = value['errors'].first
    assert_equal('value at `/value` does not match any `anyOf` schemas', any_of['message'])
    assert_equal('anyOf', any_of['keyword'])
    assert_equal('no_branch_matched', any_of['reason'])
    assert_equal('/value', any_of['instanceLocation'])
    assert_equal('/properties/value/anyOf', any_of['schemaLocation'])

    branches = any_of['branches']
    assert_equal([0, 1, 2], branches.map { |branch| branch['branch'] })
    assert_equal([false, false, false], branches.map { |branch| branch['valid'] })
    assert_equal(
      ['/properties/value/anyOf/0', '/properties/value/anyOf/1', '/properties/value/anyOf/2'],
      branches.map { |branch| branch['schemaLocation'] }
    )
    assert_equal(
      [leaf('value at `/value` is not a string', 'type', '/value', '/properties/value/anyOf/0/type', 'string')],
      branches[0]['errors']
    )
    assert_equal(
      [leaf('number at `/value` is less than: 10', 'minimum', '/value', '/properties/value/anyOf/2/minimum', 'minimum')],
      branches[2]['errors']
    )

    # identical leaf errors from branches 0 and 1 are merged in the summary
    assert_equal(
      [
        leaf(
          'value at `/value` is not a string', 'type', '/value', '/properties/value/anyOf/0/type', 'string',
          'count' => 2,
          'schemaLocations' => ['/properties/value/anyOf/0/type', '/properties/value/anyOf/1/type'],
          'branchIndices' => [0, 1]
        ),
        leaf(
          'number at `/value` is less than: 10', 'minimum', '/value', '/properties/value/anyOf/2/minimum', 'minimum',
          'branchIndices' => [2]
        )
      ],
      any_of['errors']
    )
  end

  def test_explained_one_of_multiple_branches_matched
    output = explained(one_of_schemer, 'abc')

    assert_equal(
      {
        'valid' => false,
        'explanation' => {
          'message' => 'value at root does not match schema',
          'instanceLocation' => '',
          'schemaLocation' => '',
          'errors' => [
            {
              'message' => 'value at root does not match exactly one `oneOf` schema',
              'keyword' => 'oneOf',
              'instanceLocation' => '',
              'schemaLocation' => '/oneOf',
              'reason' => 'multiple_branches_matched',
              'matchedBranches' => [0, 1],
              'branches' => [
                { 'branch' => 0, 'valid' => true, 'instanceLocation' => '', 'schemaLocation' => '/oneOf/0' },
                { 'branch' => 1, 'valid' => true, 'instanceLocation' => '', 'schemaLocation' => '/oneOf/1' },
                {
                  'branch' => 2,
                  'valid' => false,
                  'message' => 'value at root does not match schema',
                  'instanceLocation' => '',
                  'schemaLocation' => '/oneOf/2',
                  'errors' => [leaf('value at root is not an integer', 'type', '', '/oneOf/2/type', 'integer')]
                }
              ],
              'errors' => [
                leaf('value at root is not an integer', 'type', '', '/oneOf/2/type', 'integer', 'branchIndices' => [2])
              ]
            }
          ]
        }
      },
      output
    )
  end

  def test_explained_one_of_no_branch_matched
    output = explained(one_of_schemer, 1.5)
    one_of = output['explanation']['errors'].first

    assert_equal('no_branch_matched', one_of['reason'])
    refute(one_of.key?('matchedBranches'))
    assert_equal([0, 1, 2], one_of['branches'].map { |branch| branch['branch'] })
    assert(one_of['branches'].none? { |branch| branch['valid'] })
  end

  def test_explained_one_of_exactly_one_branch_matched_is_valid
    assert_equal({ 'valid' => true }, explained(one_of_schemer, 5))
  end

  def test_explained_valid_instance
    assert_equal({ 'valid' => true }, explained(JSONSchemer.schema({ 'type' => 'string' }), 'ok'))
  end

  def test_explained_all_of_lists_failed_branches_only
    schemer = JSONSchemer.schema({
      'allOf' => [{ 'type' => 'string' }, { 'minLength' => 10 }, { 'pattern' => '^z' }]
    })
    all_of = explained(schemer, 'abc')['explanation']['errors'].first

    assert_equal('allOf', all_of['keyword'])
    assert_equal('not_all_branches_matched', all_of['reason'])
    assert_equal([1, 2], all_of['branches'].map { |branch| branch['branch'] })
    assert_equal(
      [
        leaf('string length at root is less than: 10', 'minLength', '', '/allOf/1/minLength', 'minLength', 'branchIndices' => [1]),
        leaf('string at root does not match pattern: ^z', 'pattern', '', '/allOf/2/pattern', 'pattern', 'branchIndices' => [2])
      ],
      all_of['errors']
    )
  end

  def test_explained_not
    output = explained(JSONSchemer.schema({ 'not' => { 'type' => 'string' } }), 'x')

    assert_equal(
      {
        'valid' => false,
        'explanation' => {
          'message' => 'value at root does not match schema',
          'instanceLocation' => '',
          'schemaLocation' => '',
          'errors' => [
            {
              'message' => 'value at root matches `not` schema',
              'keyword' => 'not',
              'instanceLocation' => '',
              'schemaLocation' => '/not',
              'reason' => 'forbidden_schema_matched',
              'type' => 'not'
            }
          ]
        }
      },
      output
    )
  end

  def test_explained_if_then
    schemer = JSONSchemer.schema({
      'if' => { 'type' => 'string' },
      'then' => { 'minLength' => 5 },
      'else' => { 'type' => 'integer' }
    })
    then_node = explained(schemer, 'ab')['explanation']['errors'].first

    assert_equal('then', then_node['keyword'])
    assert_equal('if_matched_then_failed', then_node['reason'])
    assert_equal('/then', then_node['schemaLocation'])
    assert_equal(
      [leaf('string length at root is less than: 5', 'minLength', '', '/then/minLength', 'minLength')],
      then_node['errors']
    )
  end

  def test_explained_if_else
    schemer = JSONSchemer.schema({
      'if' => { 'type' => 'string' },
      'then' => { 'minLength' => 5 },
      'else' => { 'type' => 'integer' }
    })
    else_node = explained(schemer, 1.5)['explanation']['errors'].first

    assert_equal('else', else_node['keyword'])
    assert_equal('if_not_matched_else_failed', else_node['reason'])
    assert_equal('/else', else_node['schemaLocation'])
    assert_equal(
      [leaf('value at root is not an integer', 'type', '', '/else/type', 'integer')],
      else_node['errors']
    )
  end

  def test_explained_then_with_false_schema
    schemer = JSONSchemer.schema({ 'if' => { 'type' => 'string' }, 'then' => false })
    then_node = explained(schemer, 'x')['explanation']['errors'].first

    assert_equal('then', then_node['keyword'])
    assert_equal('if_matched_then_failed', then_node['reason'])
    refute(then_node.key?('errors'))
  end

  def test_explained_nested_combinators
    schemer = JSONSchemer.schema({
      'oneOf' => [
        { 'anyOf' => [{ 'type' => 'string' }, { 'type' => 'boolean' }] },
        { 'type' => 'null' }
      ]
    })
    one_of = explained(schemer, 1)['explanation']['errors'].first

    assert_equal('oneOf', one_of['keyword'])
    assert_equal('no_branch_matched', one_of['reason'])

    any_of = one_of['branches'].first['errors'].first
    assert_equal('anyOf', any_of['keyword'])
    assert_equal('no_branch_matched', any_of['reason'])
    assert_equal('/oneOf/0/anyOf', any_of['schemaLocation'])

    # the outer summary flattens nested leaves and keeps the outer branch index
    assert_equal(
      [
        ['value at root is not a string', [0]],
        ['value at root is not a boolean', [0]],
        ['value at root is not null', [1]]
      ],
      one_of['errors'].map { |error| [error['message'], error['branchIndices']] }
    )
  end

  def test_explained_truncation_marks_omitted
    any_of = explained(pattern_any_of_schemer(6), 'nope', :explanation_limit => 2)['explanation']['errors'].first

    assert_equal(2, any_of['branches'].size)
    assert_equal(4, any_of['omittedBranches'])
    assert_equal(2, any_of['errors'].size)
    assert_equal(4, any_of['omittedErrors'])
  end

  def test_explained_truncation_never_hides_matched_branches
    output = explained(one_of_schemer, 'abc', :explanation_limit => 0)

    assert_equal(
      {
        'valid' => false,
        'explanation' => {
          'message' => 'value at root does not match schema',
          'instanceLocation' => '',
          'schemaLocation' => '',
          'errors' => [
            {
              'message' => 'value at root does not match exactly one `oneOf` schema',
              'keyword' => 'oneOf',
              'instanceLocation' => '',
              'schemaLocation' => '/oneOf',
              'reason' => 'multiple_branches_matched',
              'matchedBranches' => [0, 1],
              'branches' => [
                { 'branch' => 0, 'valid' => true, 'instanceLocation' => '', 'schemaLocation' => '/oneOf/0' },
                { 'branch' => 1, 'valid' => true, 'instanceLocation' => '', 'schemaLocation' => '/oneOf/1' }
              ],
              'errors' => [],
              'omittedBranches' => 1,
              'omittedErrors' => 1
            }
          ]
        }
      },
      output
    )
  end

  def test_explained_default_limit
    any_of = explained(pattern_any_of_schemer(15), 'nope')['explanation']['errors'].first

    assert_equal(10, any_of['branches'].size)
    assert_equal(5, any_of['omittedBranches'])
  end

  def test_explained_limit_from_schema_option
    schemer = pattern_any_of_schemer(6, :explanation_limit => 1)
    any_of = explained(schemer, 'nope')['explanation']['errors'].first

    assert_equal(1, any_of['branches'].size)
    assert_equal(5, any_of['omittedBranches'])
    assert_equal(5, any_of['omittedErrors'])
  end

  def test_explained_limit_per_call_override
    schemer = pattern_any_of_schemer(6, :explanation_limit => 1)
    any_of = explained(schemer, 'nope', :explanation_limit => 3)['explanation']['errors'].first

    assert_equal(3, any_of['branches'].size)
    assert_equal(3, any_of['omittedBranches'])
  end

  def test_explained_limit_false_is_unlimited
    any_of = explained(pattern_any_of_schemer(6), 'nope', :explanation_limit => false)['explanation']['errors'].first

    assert_equal(6, any_of['branches'].size)
    assert_equal(6, any_of['errors'].size)
    refute(any_of.key?('omittedBranches'))
    refute(any_of.key?('omittedErrors'))
  end

  def test_explained_contains_ignores_nested
    contains = explained(JSONSchemer.schema({ 'contains' => { 'type' => 'string' } }), [1, 2])['explanation']['errors'].first

    assert_equal('contains', contains['keyword'])
    assert_equal('contains', contains['type'])
    refute(contains.key?('errors'))
  end

  def test_explained_false_schema
    output = explained(JSONSchemer.schema(false), 1)

    assert_equal(
      {
        'valid' => false,
        'explanation' => {
          'message' => 'value at root does not match schema',
          'instanceLocation' => '',
          'schemaLocation' => '',
          'type' => 'schema'
        }
      },
      output
    )
  end

  def test_explained_any_of_false_branch
    schemer = JSONSchemer.schema({ 'anyOf' => [false, { 'type' => 'string' }] })
    any_of = explained(schemer, 1)['explanation']['errors'].first

    assert_equal(
      [
        {
          'message' => 'value at root does not match schema',
          'instanceLocation' => '',
          'schemaLocation' => '/anyOf/0',
          'type' => 'schema',
          'branchIndices' => [0]
        },
        leaf('value at root is not a string', 'type', '', '/anyOf/1/type', 'string', 'branchIndices' => [1])
      ],
      any_of['errors']
    )
  end

  def test_explained_leaf_details
    required = explained(JSONSchemer.schema({ 'required' => ['a', 'b'] }), {})['explanation']['errors'].first

    assert_equal('required', required['type'])
    assert_equal({ 'missing_keys' => ['a', 'b'] }, required['details'])
  end

  def test_explained_draft7
    schemer = JSONSchemer.schema({
      '$schema' => 'http://json-schema.org/draft-07/schema#',
      'anyOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }]
    })
    any_of = explained(schemer, 1.5)['explanation']['errors'].first

    assert_equal('anyOf', any_of['keyword'])
    assert_equal('no_branch_matched', any_of['reason'])
    assert_equal([0, 1], any_of['branches'].map { |branch| branch['branch'] })
  end

  def test_explained_agrees_with_valid
    cases = [
      [{ 'anyOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] }, 'ok', true],
      [{ 'anyOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] }, 1.5, false],
      [{ 'oneOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] }, 'ok', true],
      [{ 'oneOf' => [{ 'type' => 'string' }, { 'type' => 'string' }] }, 'ok', false],
      [{ 'oneOf' => [{ 'type' => 'string' }, { 'type' => 'integer' }] }, 1.5, false],
      [{ 'not' => { 'type' => 'string' } }, 'x', false],
      [{ 'not' => { 'type' => 'string' } }, 1, true],
      [{ 'if' => { 'type' => 'string' }, 'then' => { 'minLength' => 3 }, 'else' => { 'type' => 'integer' } }, 'abcd', true],
      [{ 'if' => { 'type' => 'string' }, 'then' => { 'minLength' => 3 }, 'else' => { 'type' => 'integer' } }, 'ab', false],
      [{ 'if' => { 'type' => 'string' }, 'then' => { 'minLength' => 3 }, 'else' => { 'type' => 'integer' } }, 1.5, false],
      [{ 'allOf' => [{ 'type' => 'string' }, { 'minLength' => 2 }] }, 'ab', true],
      [{ 'allOf' => [{ 'type' => 'string' }, { 'minLength' => 2 }] }, 'a', false]
    ]

    cases.each do |schema, instance, expected_valid|
      schemer = JSONSchemer.schema(schema)
      output = schemer.validate(instance, :output_format => 'explained')

      assert_equal(expected_valid, schemer.valid?(instance), schema.inspect)
      assert_equal(expected_valid, output.fetch('valid'), schema.inspect)
      assert_equal(!expected_valid, output.key?('explanation'), schema.inspect)
    end
  end

  def test_classic_output_is_unchanged
    classic = any_of_schemer.validate({ 'value' => 3 }).to_a

    assert_equal(3, classic.size)
    assert_equal(['string', 'string', 'minimum'], classic.map { |error| error['type'] })
    assert_equal(['/properties/value/anyOf/0', '/properties/value/anyOf/1', '/properties/value/anyOf/2'], classic.map { |error| error['schema_pointer'] })
    assert(classic.none? { |error| error.key?('explanation') })
  end
end
