# frozen_string_literal: true
require 'test_helper'

class OpenAPIRequestTest < Minitest::Test
  COLOR_SCHEMA = {
    'type' => 'object',
    'required' => %w[R G],
    'properties' => {
      'R' => { 'type' => 'integer' },
      'G' => { 'type' => 'integer' },
      'B' => { 'type' => 'integer' }
    }
  }

  DOCUMENT = {
    'openapi' => '3.1.0',
    'info' => { 'title' => 'request parameter test', 'version' => '1.0.0' },
    'paths' => {
      '/pets/{pet_id}' => {
        'parameters' => [
          { '$ref' => '#/components/parameters/TraceHeader' },
          { 'name' => 'pet_id', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer' } }
        ],
        'get' => {
          'parameters' => [
            { 'name' => 'tag', 'in' => 'query', 'required' => true, 'schema' => { 'type' => 'string', 'minLength' => 2 } },
            { 'name' => 'tags', 'in' => 'query', 'schema' => { 'type' => 'array', 'items' => { 'type' => 'string' } } },
            { 'name' => 'tags_csv', 'in' => 'query', 'style' => 'form', 'explode' => false, 'schema' => { 'type' => 'array', 'items' => { 'type' => 'integer' } } },
            { 'name' => 'color', 'in' => 'query', 'style' => 'deepObject', 'schema' => COLOR_SCHEMA },
            { 'name' => 'point', 'in' => 'query', 'style' => 'form', 'schema' => {
              'type' => 'object',
              'properties' => { 'x' => { 'type' => 'integer' }, 'y' => { 'type' => 'integer' } }
            } },
            { 'name' => 'point_csv', 'in' => 'query', 'style' => 'form', 'explode' => false, 'schema' => {
              'type' => 'object',
              'properties' => { 'x' => { 'type' => 'integer' }, 'y' => { 'type' => 'integer' } }
            } },
            { 'name' => 'mode', 'in' => 'query', 'allowEmptyValue' => true, 'schema' => { 'type' => 'string' } },
            { 'name' => 'verbose', 'in' => 'header', 'schema' => { 'type' => 'boolean' } },
            { 'name' => 'segments', 'in' => 'path', 'style' => 'simple', 'explode' => false, 'schema' => { 'type' => 'array', 'items' => { 'type' => 'string' } } }
          ]
        }
      },
      '/colors/{color}' => {
        'get' => {
          'parameters' => [
            { 'name' => 'color', 'in' => 'path', 'style' => 'simple', 'explode' => false, 'required' => true, 'schema' => COLOR_SCHEMA }
          ]
        }
      },
      '/colors2/{color}' => {
        'get' => {
          'parameters' => [
            { 'name' => 'color', 'in' => 'path', 'style' => 'simple', 'explode' => true, 'required' => true, 'schema' => COLOR_SCHEMA }
          ]
        }
      }
    },
    'components' => {
      'parameters' => {
        'TraceHeader' => { 'name' => 'X-Trace', 'in' => 'header', 'required' => true, 'schema' => { 'type' => 'string', 'pattern' => '\A[a-z0-9]+\z' } }
      }
    }
  }.freeze

  def operation(path, method = 'get', document = DOCUMENT)
    JSONSchemer.openapi(document).operation(path, method)
  end

  def request(path, method: 'get', query: nil, raw_path: nil, headers: nil)
    operation(path, method).request(:query => query, :path => raw_path, :headers => headers)
  end

  def test_valid_request_with_all_styles
    request = request(
      '/pets/{pet_id}',
      :query => 'tag=cat&tags=a&tags=b&tags_csv=1,2&color[R]=1&color[G]=2&x=3&y=4&point_csv=x,1,y,2',
      :raw_path => '/pets/7',
      :headers => [['X-Trace', 'abc123'], ['verbose', 'true']]
    )
    assert(request.valid?, request.validate.map(&:inspect).join("\n"))
    assert_equal(
      {
        'X-Trace' => 'abc123',
        'pet_id' => 7,
        'tag' => 'cat',
        'tags' => %w[a b],
        'tags_csv' => [1, 2],
        'color' => { 'R' => 1, 'G' => 2 },
        'point' => { 'x' => 3, 'y' => 4 },
        'point_csv' => { 'x' => 1, 'y' => 2 },
        'mode' => nil,
        'verbose' => true
      }.compact.transform_keys { |key| key },
      request.parameters.merge('mode' => nil).compact
    )
  end

  def test_parameters_returns_present_values_only
    request = request('/pets/{pet_id}', :query => 'tag=cat', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']])
    refute(request.parameters.key?('color'))
    assert_equal(%w[X-Trace pet_id tag], request.parameters.keys)
  end

  def test_missing_required_query_parameter
    errors = request('/pets/{pet_id}', :query => '', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal(%w[missing_parameter], errors.map { |error| error['type'] })
    assert_equal('tag', errors.first['parameter'])
    assert_equal('query', errors.first['parameter_in'])
    refute(errors.first.key?('source'))
  end

  def test_missing_required_path_parameter_via_template
    error = assert_raises(ArgumentError) do
      request('/pets/{pet_id}', :query => 'tag=cat', :raw_path => '/other/7', :headers => [['X-Trace', 'z']])
    end
    assert_match(%r{does not match template}, error.message)
  end

  def test_missing_required_header
    errors = request('/pets/{pet_id}', :query => 'tag=cat', :raw_path => '/pets/7').validate.to_a
    assert_equal(%w[missing_parameter], errors.map { |error| error['type'] })
    assert_equal('X-Trace', errors.first['parameter'])
    assert_equal('header', errors.first['parameter_in'])
  end

  def test_empty_value_distinct_from_missing
    errors = request(
      '/pets/{pet_id}',
      :query => 'tag=&tags_csv=',
      :raw_path => '/pets/7',
      :headers => [['X-Trace', 'z']]
    ).validate.to_a
    assert_equal(%w[empty_value empty_value], errors.map { |error| error['type'] })
    assert_equal(%w[tag tags_csv], errors.map { |error| error['parameter'] })
  end

  def test_allow_empty_value
    request = request(
      '/pets/{pet_id}',
      :query => 'tag=cat&mode=',
      :raw_path => '/pets/7',
      :headers => [['X-Trace', 'z']]
    )
    assert(request.valid?)
    assert_equal('', request.parameters['mode'])
  end

  def test_invalid_percent_encoding_in_query_value
    errors = request('/pets/{pet_id}', :query => 'tag=%zz', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    source = errors.first['source']
    assert_equal(4, source['offset'])
    assert_equal('%zz', source['raw'])
  end

  def test_invalid_percent_encoding_in_deep_object_key
    errors = request('/pets/{pet_id}', :query => 'tag=cat&color[%R]=1', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('color', errors.first['parameter'])
  end

  def test_invalid_percent_encoding_in_path
    errors = request('/colors/{color}', :query => nil, :raw_path => '/colors/R,%2z,G,3').validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('path', errors.first['parameter_in'])
    assert_equal(2, errors.first['source']['offset'])
  end

  def test_deep_object_key_conflict
    errors = request('/pets/{pet_id}', :query => 'tag=cat&color[R]=1&color[R]=2', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('object_key_conflict', errors.first['type'])
    assert_equal('R', errors.first['error'].match(/key "([^"]+)"/)[1])
  end

  def test_form_explode_object_key_conflict
    errors = request('/pets/{pet_id}', :query => 'tag=cat&x=1&x=2', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('object_key_conflict', errors.first['type'])
    assert_equal('point', errors.first['parameter'])
  end

  def test_simple_object_key_conflict
    errors = request('/colors/{color}', :raw_path => '/colors/R,1,R,2').validate.to_a
    assert_equal('object_key_conflict', errors.first['type'])
    assert_equal('color', errors.first['parameter'])
  end

  def test_simple_styles_path_and_header
    request = request('/colors/{color}', :raw_path => '/colors/R,1,G,2')
    assert(request.valid?)
    assert_equal({ 'R' => 1, 'G' => 2 }, request.parameters['color'])

    request = request('/colors2/{color}', :raw_path => '/colors2/R=1,G=2')
    assert(request.valid?)
    assert_equal({ 'R' => 1, 'G' => 2 }, request.parameters['color'])
  end

  def test_simple_array_path
    errors = request('/pets/{pet_id}', :query => 'tag=cat', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_empty(errors)
  end

  def test_schema_error_points_to_original_parameter
    errors = request('/pets/{pet_id}', :query => 'tag=cat&tags_csv=x,y', :raw_path => '/pets/nope', :headers => [['X-Trace', 'BAD !']]).validate.to_a
    types = errors.map { |error| error['type'] }
    assert_includes(types, 'integer')
    assert_includes(types, 'pattern')
    path_error = errors.find { |error| error['parameter'] == 'pet_id' }
    assert_equal('path', path_error['parameter_in'])
    assert_equal('nope', path_error['source']['raw'])
    assert_equal('/paths/~1pets~1{pet_id}/parameters/1/schema', path_error['parameter_pointer'])
  end

  def test_deep_object_schema_error_points_to_field
    errors = request('/pets/{pet_id}', :query => 'tag=cat&color[R]=x&color[G]=2', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    error = errors.find { |item| item['parameter'] == 'color' }
    assert_equal('integer', error['type'])
    assert_equal('/R', error['data_pointer'])
    assert_equal('x', error['source']['raw'])
  end

  def test_duplicate_scalar_query_parameter
    errors = request('/pets/{pet_id}', :query => 'tag=cat&tag=dog', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('duplicate_parameter', errors.first['type'])
    assert_equal('tag', errors.first['parameter'])
  end

  def test_duplicate_header_parameter
    errors = request(
      '/pets/{pet_id}',
      :query => 'tag=cat',
      :raw_path => '/pets/7',
      :headers => [['verbose', 'true'], ['verbose', 'false'], ['X-Trace', 'z']]
    ).validate.to_a
    assert_equal('duplicate_parameter', errors.first['type'])
    assert_equal('verbose', errors.first['parameter'])
  end

  def test_malformed_non_explode_object
    errors = request('/pets/{pet_id}', :query => 'tag=cat&point_csv=x,1,y', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_parameter_value', errors.first['type'])
  end

  def test_repeated_fields_preserved_from_array_input
    request = operation('/pets/{pet_id}').request(
      :query => [%w[tag cat], %w[tags a], %w[tags b]],
      :path => '/pets/7',
      :headers => [['X-Trace', 'z']]
    )
    assert(request.valid?)
    assert_equal(%w[a b], request.parameters['tags'])
  end

  def test_percent_and_plus_decoding
    request = request(
      '/pets/{pet_id}',
      :query => 'tag=ca%74%20dog&tags=a+b',
      :raw_path => '/pets/7',
      :headers => [['X-Trace', 'z']]
    )
    assert(request.valid?)
    assert_equal('cat dog', request.parameters['tag'])
    assert_equal(['a b'], request.parameters['tags'])
  end

  def test_unsupported_query_style_reported_when_preparing
    document = document_with_parameter(
      'name' => 'ids', 'in' => 'query', 'style' => 'pipeDelimited',
      'schema' => { 'type' => 'array' }
    )
    error = assert_raises(JSONSchemer::UnsupportedOpenAPIParameterStyle) do
      operation('/x/{id}', 'get', document)
    end
    assert_match(/pipeDelimited/, error.message)
  end

  def test_unsupported_path_style_reported_when_preparing
    document = document_with_parameter(
      'name' => 'ids', 'in' => 'path', 'style' => 'label', 'required' => true,
      'schema' => { 'type' => 'array' }
    )
    assert_raises(JSONSchemer::UnsupportedOpenAPIParameterStyle) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_unsupported_header_style_reported_when_preparing
    document = document_with_parameter(
      'name' => 'X-Ids', 'in' => 'header', 'style' => 'label',
      'schema' => { 'type' => 'array' }
    )
    assert_raises(JSONSchemer::UnsupportedOpenAPIParameterStyle) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_deep_object_requires_explode_true
    document = document_with_parameter(
      'name' => 'color', 'in' => 'query', 'style' => 'deepObject', 'explode' => false,
      'schema' => { 'type' => 'object' }
    )
    assert_raises(JSONSchemer::UnsupportedOpenAPIParameterStyle) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_cookie_parameters_are_unsupported
    document = document_with_parameter(
      'name' => 'session', 'in' => 'cookie',
      'schema' => { 'type' => 'string' }
    )
    assert_raises(JSONSchemer::UnsupportedOpenAPIParameterLocation) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_content_parameter_is_unsupported
    document = document_with_parameter(
      'name' => 'payload', 'in' => 'query',
      'content' => { 'application/json' => {} }
    )
    assert_raises(JSONSchemer::UnsupportedOpenAPIParameterContent) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_unknown_operation_raises
    assert_raises(ArgumentError) { operation('/nope') }
    assert_raises(ArgumentError) { operation('/pets/{pet_id}', 'post') }
  end

  def test_openapi30_request_parameters
    document = {
      'openapi' => '3.0.3',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x/{id}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'id', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer', 'nullable' => true } },
              { 'name' => 'tags', 'in' => 'query', 'schema' => { 'type' => 'array', 'items' => { 'type' => 'string' } } }
            ]
          }
        }
      }
    }
    request = operation('/x/{id}', 'get', document).request(:query => 'tags=a&tags=b', :path => '/x/5')
    assert(request.valid?)
    assert_equal(5, request.parameters['id'])
  end

  def test_hash_and_header_array_inputs
    request = operation('/pets/{pet_id}').request(
      :query => { 'tag' => 'cat', 'tags' => %w[a b] },
      :path => '/pets/7',
      :headers => { 'X-Trace' => 'z' }
    )
    assert(request.valid?, request.validate.map(&:inspect).join("\n"))
    assert_equal(%w[a b], request.parameters['tags'])
  end

  def test_field_without_equals_is_empty
    request = request('/pets/{pet_id}', :query => 'tag', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']])
    error = request.validate.find { |item| item['type'] == 'empty_value' }
    assert(error)
    assert_nil(error['source']['value_offset'])
  end

  def test_invalid_query_input_type
    assert_raises(ArgumentError) do
      operation('/pets/{pet_id}').request(:query => 42, :path => '/pets/7')
    end
  end

  def test_invalid_headers_input_type
    assert_raises(ArgumentError) do
      operation('/pets/{pet_id}').request(:path => '/pets/7', :headers => 'X-Trace: z')
    end
  end

  def test_required_parameter_with_invalid_percent_in_name
    errors = request('/pets/{pet_id}', :query => 'ta%zz=x', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('tag', errors.first['parameter'])
  end

  def test_non_explode_array_invalid_percent
    errors = request('/pets/{pet_id}', :query => 'tag=cat&tags_csv=1,%2z', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('tags_csv', errors.first['parameter'])
  end

  def test_non_explode_object_invalid_percent
    errors = request('/pets/{pet_id}', :query => 'tag=cat&point_csv=x,%2z', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('point_csv', errors.first['parameter'])
  end

  def test_explode_array_empty_value
    errors = request('/pets/{pet_id}', :query => 'tag=cat&tags=', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('empty_value', errors.first['type'])
  end

  def test_explode_array_invalid_percent
    errors = request('/pets/{pet_id}', :query => 'tag=cat&tags=a&tags=%zz', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('tags', errors.first['parameter'])
  end

  def test_explode_object_invalid_percent
    errors = request('/pets/{pet_id}', :query => 'tag=cat&x=%zz', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
    assert_equal('point', errors.first['parameter'])
  end

  def test_non_explode_array_empty_value
    errors = request('/pets/{pet_id}', :query => 'tag=cat&tags_csv=', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('empty_value', errors.first['type'])
  end

  def test_non_explode_object_empty_value
    errors = request('/pets/{pet_id}', :query => 'tag=cat&point_csv=', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('empty_value', errors.first['type'])
  end

  def test_simple_path_array
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/s/{segments}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'segments', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'array', 'items' => { 'type' => 'string' } } }
            ]
          }
        }
      }
    }
    request = operation('/s/{segments}', 'get', document).request(:path => '/s/a,b,c')
    assert(request.valid?)
    assert_equal(%w[a b c], request.parameters['segments'])
  end

  def test_coercer_passes_through_non_strings_and_unknown_properties
    schema = JSONSchemer.schema({
      'type' => 'object',
      'properties' => { 'known' => { 'type' => 'integer' } }
    })
    assert_equal({ 'known' => 1, 'other' => true }, JSONSchemer::OpenAPI::Coercer.coerce({ 'known' => '1', 'other' => true }, schema))
    assert_nil(JSONSchemer::OpenAPI::Coercer.coerce(nil, schema))
  end

  def test_coercer_arrays_and_objects_without_keywords_pass_through
    array_schema = JSONSchemer.schema({ 'type' => 'array' })
    object_schema = JSONSchemer.schema({ 'type' => 'object' })
    assert_equal(%w[1 2], JSONSchemer::OpenAPI::Coercer.coerce(%w[1 2], array_schema))
    assert_equal({ 'x' => '1' }, JSONSchemer::OpenAPI::Coercer.coerce({ 'x' => '1' }, object_schema))
    number_schema = JSONSchemer.schema({ 'type' => 'number' })
    assert_in_delta(10.0, JSONSchemer::OpenAPI::Coercer.coerce('1e1', number_schema))
    assert_equal('1.x', JSONSchemer::OpenAPI::Coercer.coerce('1.x', number_schema))
  end

  def test_remote_parameter_ref_is_unsupported_at_preparation
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x/{id}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'id', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer' } },
              { '$ref' => 'https://example.com/parameters#/Limit' }
            ]
          }
        }
      }
    }
    assert_raises(JSONSchemer::InvalidRefResolution) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_broken_local_parameter_ref_raises
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x/{id}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'id', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer' } },
              { '$ref' => '#/components/parameters/Missing' }
            ]
          }
        }
      }
    }
    assert_raises(JSONSchemer::InvalidRefPointer) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_non_hash_parameter_entry_is_ignored
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x/{id}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'id', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer' } }
            ]
          }
        }
      }
    }
    document['paths']['/x/{id}']['get']['parameters'].unshift(nil)
    assert_raises(JSONSchemer::UnsupportedOpenAPIParameterLocation) do
      operation('/x/{id}', 'get', document)
    end
  end

  def test_optional_deep_object_missing_is_absent
    request = request('/pets/{pet_id}', :query => 'tag=cat', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']])
    assert_nil(request.parameters['color'])
    assert(request.valid?)
  end

  def test_simple_decode_with_errors_skips_termination
    errors = request('/colors/{color}', :raw_path => '/colors/R,1,R,2').validate.to_a
    assert(errors.any? { |error| error['type'] == 'object_key_conflict' })
  end

  def test_percent_sign_at_end_of_value
    errors = request('/pets/{pet_id}', :query => 'tag=%', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
  end

  def test_query_and_headers_support_nil_values
    request = operation('/pets/{pet_id}').request(
      :query => [['tags', %w[a b]]],
      :path => '/pets/7',
      :headers => [['X-Trace', nil]]
    )
    assert_nil(request.parameters['X-Trace'])
    assert_equal(%w[a b], request.parameters['tags'])
    assert_equal('empty_value', request.validate.first['type'])
  end

  def test_schema_error_source_nil_for_root_without_recorded_source
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x' => {
          'get' => {
            'parameters' => [
              { 'name' => 'n', 'in' => 'query', 'schema' => { 'type' => 'integer' } }
            ]
          }
        }
      }
    }
    request = operation('/x', 'get', document).request(:query => 'n=1.5')
    error = request.validate.first
    assert_equal('integer', error['type'])
    assert_equal('n', error['parameter'])
  end

  def test_optional_path_parameter_with_no_match_is_absent
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x' => {
          'get' => {
            'parameters' => [
              { 'name' => 'maybe', 'in' => 'query', 'style' => 'deepObject', 'schema' => { 'type' => 'object' } },
              { 'name' => 'mode', 'in' => 'query', 'schema' => { 'type' => 'string' } }
            ]
          }
        }
      }
    }
    request = operation('/x', 'get', document).request(:query => 'mode=on')
    assert(request.valid?)
    assert_nil(request.parameters['maybe'])
  end

  def test_required_deep_object_missing_is_an_error
    document = document_with_parameter(
      'name' => 'color', 'in' => 'query', 'style' => 'deepObject', 'required' => true,
      'schema' => { 'type' => 'object' }
    )
    request = operation('/x/{id}', 'get', document).request(:query => nil, :path => '/x/9')
    assert_equal('missing_parameter', request.validate.first['type'])
  end

  def test_non_explode_object_with_trailing_comma_conflicts
    errors = request('/pets/{pet_id}', :query => 'tag=cat&point_csv=x,1,y,2,y,3', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert(errors.any? { |error| error['type'] == 'object_key_conflict' })
  end

  def test_percent_decode_hex_valid
    request = request('/pets/{pet_id}', :query => 'tag=%41%42', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']])
    assert(request.valid?)
    assert_equal('AB', request.parameters['tag'])
  end

  def test_coercer_integer_without_number_type_passes_through
    schema = JSONSchemer.schema({ 'type' => 'string' })
    assert_equal('5', JSONSchemer::OpenAPI::Coercer.coerce('5', schema))
    integer_schema = JSONSchemer.schema({ 'type' => 'integer' })
    assert_equal('1.5', JSONSchemer::OpenAPI::Coercer.coerce('1.5', integer_schema))
    assert_equal('5', JSONSchemer::OpenAPI::Coercer.coerce('5', JSONSchemer.schema({})))
  end

  def test_non_hash_path_item_returns_empty_parameters
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => { '/x' => nil }
    }
    assert_raises(ArgumentError) do
      JSONSchemer.openapi(document).operation('/x', 'get')
    end
  end

  def test_simple_explode_object_key_conflict
    errors = request('/colors2/{color}', :raw_path => '/colors2/R=1,R=2').validate.to_a
    assert_equal('object_key_conflict', errors.first['type'])
  end

  def test_path_item_parameters_merged_when_path_item_has_parameters
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x/{id}' => nil
      }
    }
    assert_raises(ArgumentError) { JSONSchemer.openapi(document).operation('/x/{id}', 'get') }
  end

  def test_parameter_without_document_pointer_uses_inline_schema
    parameter = JSONSchemer::OpenAPI::PreparedParameter.new(
      operation('/pets/{pet_id}').instance_variable_get(:@openapi),
      { 'name' => 'solo', 'in' => 'query', 'schema' => { 'type' => 'string' } },
      nil
    )
    assert(parameter.schema.valid?('x'))
  end

  def test_deep_object_invalid_percent_in_value
    errors = request('/pets/{pet_id}', :query => 'tag=cat&color[R]=%2z', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']]).validate.to_a
    assert_equal('invalid_percent_encoding', errors.first['type'])
  end

  def test_simple_explode_object_with_missing_value
    errors = request('/colors2/{color}', :raw_path => '/colors2/R,G').validate.to_a
    assert_equal('invalid_parameter_value', errors.first['type'])
  end

  def test_simple_array_decoding
    request = request('/pets/{pet_id}', :query => 'tag=cat', :raw_path => '/pets/7', :headers => [['X-Trace', 'z']])
    assert(request.valid?)
  end

  def test_number_and_string_coercion
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x' => {
          'get' => {
            'parameters' => [
              { 'name' => 'ratio', 'in' => 'query', 'schema' => { 'type' => 'number' } },
              { 'name' => 'label', 'in' => 'query', 'schema' => { 'type' => 'string' } },
              { 'name' => 'on', 'in' => 'query', 'schema' => { 'type' => 'boolean' } }
            ]
          }
        }
      }
    }
    request = operation('/x', 'get', document).request(:query => 'ratio=1.5&label=hello&on=true')
    assert(request.valid?)
    assert_in_delta(1.5, request.parameters['ratio'])
    assert_equal('hello', request.parameters['label'])
    assert_equal(true, request.parameters['on'])
  end

  def test_parameter_schema_ref_is_resolved
    document = {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x' => {
          'get' => {
            'parameters' => [
              { 'name' => 'count', 'in' => 'query', 'schema' => { '$ref' => '#/components/schemas/Count' } }
            ]
          }
        }
      },
      'components' => {
        'schemas' => { 'Count' => { 'type' => 'integer' } }
      }
    }
    request = operation('/x', 'get', document).request(:query => 'count=3')
    assert(request.valid?)
    assert_equal(3, request.parameters['count'])
  end

  private

  def document_with_parameter(parameter)
    {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/x/{id}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'id', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer' } },
              parameter
            ]
          }
        }
      }
    }
  end
end
