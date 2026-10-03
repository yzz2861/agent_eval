require 'test_helper'

class OpenAPIOperationTest < Minitest::Test
  def openapi_document
    {
      'openapi' => '3.1.0',
      'info' => { 'title' => 'pets', 'version' => '1.0.0' },
      'paths' => {
        '/pets/{petId}' => {
          'parameters' => [
            { 'name' => 'petId', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'integer' } },
            { 'name' => 'X-Request-Id', 'in' => 'header', 'schema' => { 'type' => 'string', 'minLength' => 2 } }
          ],
          'get' => {
            'parameters' => [
              { 'name' => 'X-Request-Id', 'in' => 'header', 'schema' => { 'type' => 'string', 'minLength' => 5 } },
              { 'name' => 'limit', 'in' => 'query', 'required' => true, 'schema' => { 'type' => 'integer', 'minimum' => 1, 'maximum' => 100 } },
              { 'name' => 'tags', 'in' => 'query', 'schema' => { 'type' => 'array', 'items' => { 'type' => 'string' } } },
              { 'name' => 'scores', 'in' => 'query', 'explode' => false, 'schema' => { 'type' => 'array', 'items' => { 'type' => 'integer' } } },
              { 'name' => 'filter', 'in' => 'query', 'style' => 'deepObject', 'schema' => { 'type' => 'object', 'properties' => { 'color' => { 'type' => 'string' }, 'size' => { 'type' => 'integer' } }, 'required' => ['color'] } },
              { 'name' => 'coords', 'in' => 'query', 'explode' => false, 'schema' => { 'type' => 'object', 'properties' => { 'x' => { 'type' => 'integer' }, 'y' => { 'type' => 'integer' } }, 'additionalProperties' => false } },
              { 'name' => 'flags', 'in' => 'query', 'schema' => { 'type' => 'object', 'properties' => { 'a' => { 'type' => 'boolean' }, 'b' => { 'type' => 'integer' } } } },
              { 'name' => 'q', 'in' => 'query', 'schema' => { 'type' => 'string', 'minLength' => 1 } },
              { 'name' => 'ratio', 'in' => 'query', 'schema' => { 'type' => 'number' } },
              { 'name' => 'refParam', 'in' => 'query', 'schema' => { '$ref' => '#/components/schemas/PositiveInt' } },
              { '$ref' => '#/components/parameters/Verbose' },
              { 'name' => 'untypedIds', 'in' => 'query', 'schema' => { 'items' => { 'type' => 'integer' } } },
              { 'name' => 'untypedObj', 'in' => 'query', 'explode' => false, 'schema' => { 'properties' => { 'x' => { 'type' => 'integer' } } } },
              { 'name' => 'rawObj', 'in' => 'query', 'explode' => false, 'schema' => { 'type' => 'object' } },
              { 'name' => 'rawArr', 'in' => 'query', 'schema' => { 'type' => 'array' } },
              { 'name' => 'openObj', 'in' => 'query', 'schema' => { 'type' => 'object' } },
              { 'name' => 'anything', 'in' => 'query', 'schema' => true },
              { 'name' => 'noSchema', 'in' => 'query' },
              { 'name' => 'cyclic', 'in' => 'query', 'schema' => { '$ref' => '#/components/schemas/CycleA' } }
            ]
          }
        },
        '/files/{name}' => {
          'get' => {
            'parameters' => [
              { 'name' => 'name', 'in' => 'path', 'required' => true, 'schema' => { 'type' => 'string' } },
              { 'name' => 'ids', 'in' => 'path', 'schema' => { 'type' => 'array', 'items' => { 'type' => 'integer' } } },
              { 'name' => 'map', 'in' => 'path', 'explode' => true, 'schema' => { 'type' => 'object', 'properties' => { 'x' => { 'type' => 'integer' } } } },
              { 'name' => 'point', 'in' => 'path', 'schema' => { 'type' => 'object', 'properties' => { 'x' => { 'type' => 'integer' } } } }
            ]
          }
        },
        '/headers' => {
          'get' => {
            'parameters' => [
              { 'name' => 'X-Ids', 'in' => 'header', 'schema' => { 'type' => 'array', 'items' => { 'type' => 'integer' } } },
              { 'name' => 'X-Flags', 'in' => 'header', 'explode' => true, 'schema' => { 'type' => 'object', 'properties' => { 'debug' => { 'type' => 'boolean' } } } },
              { 'name' => 'X-Coords', 'in' => 'header', 'schema' => { 'type' => 'object', 'properties' => { 'x' => { 'type' => 'integer' } } } },
              { 'name' => 'X-Token', 'in' => 'header', 'required' => true, 'schema' => { 'type' => 'string' } }
            ]
          }
        }
      },
      'components' => {
        'parameters' => {
          'Verbose' => { 'name' => 'verbose', 'in' => 'query', 'schema' => { 'type' => 'boolean' } }
        },
        'schemas' => {
          'PositiveInt' => { 'type' => 'integer', 'minimum' => 1 },
          'CycleA' => { '$ref' => '#/components/schemas/CycleB' },
          'CycleB' => { '$ref' => '#/components/schemas/CycleA' }
        }
      }
    }
  end

  def operation
    @operation ||= JSONSchemer.openapi(openapi_document).operation('/pets/{petId}', 'get')
  end

  def files_operation
    @files_operation ||= JSONSchemer.openapi(openapi_document).operation('/files/{name}', 'get')
  end

  def headers_operation
    @headers_operation ||= JSONSchemer.openapi(openapi_document).operation('/headers', 'get')
  end

  def validate_query(query)
    operation.validate(:query => query, :path => { 'petId' => '5' })
  end

  def assert_valid_query(query)
    assert_empty(validate_query(query))
  end

  def error_types(errors)
    errors.map { |error| error['type'] }
  end
  def test_lists_operation_parameters
    assert_kind_of(JSONSchemer::OpenAPI::Operation, operation)
    names = operation.parameters.map(&:name)
    assert_includes(names, 'petId')
    assert_includes(names, 'limit')
    assert_includes(names, 'verbose')
  end

  def test_valid?
    assert(operation.valid?(:query => 'limit=1', :path => { 'petId' => '5' }))
    refute(operation.valid?(:query => 'limit=nope', :path => { 'petId' => '5' }))
  end

  def test_operation_level_parameter_overrides_path_level
    errors = operation.validate(:query => 'limit=1', :path => { 'petId' => '5' }, :headers => { 'X-Request-Id' => 'abcd' })
    assert_equal(%w[minLength], error_types(errors))
    assert_equal('X-Request-Id', errors.first['parameter'])
    assert_equal('header', errors.first['in'])
    assert_empty(operation.validate(:query => 'limit=1', :path => { 'petId' => '5' }, :headers => { 'X-Request-Id' => 'abcde' }))
  end

  def test_query_form_primitive
    assert_valid_query('limit=10')
    assert_valid_query('?limit=10')
    assert_valid_query('limit=1&limit=2')

    errors = validate_query('limit=200')
    assert_equal(%w[maximum], error_types(errors))
    assert_equal('limit', errors.first['parameter'])
    assert_equal('query', errors.first['in'])

    errors = validate_query('limit=ten')
    assert_equal(%w[integer], error_types(errors))
    assert_equal('limit', errors.first['parameter'])
  end

  def test_query_missing_vs_empty
    errors = validate_query('tags=a')
    assert_equal(%w[required], error_types(errors))
    assert_equal('limit', errors.first['parameter'])
    assert_equal('query', errors.first['in'])

    errors = validate_query('limit=')
    assert_equal(%w[integer], error_types(errors))
    assert_equal('limit', errors.first['parameter'])
  end

  def test_query_form_array
    assert_valid_query('limit=1&tags=a&tags=b')
    assert_valid_query('limit=1&scores=1,2,3')

    errors = validate_query('limit=1&scores=1,x')
    assert_equal(%w[integer], error_types(errors))
    assert_equal('scores', errors.first['parameter'])
    assert_equal('/1', errors.first['data_pointer'])
  end

  def test_query_deep_object
    assert_valid_query('limit=1&filter[color]=blue&filter[size]=3')
    assert_valid_query('limit=1&filter%5Bcolor%5D=blue')
    assert_valid_query('limit=1&filter[color]=blue&filter[unknown]=x')

    errors = validate_query('limit=1&filter[size]=3')
    assert_equal(%w[required], error_types(errors))
    assert_equal('filter', errors.first['parameter'])

    errors = validate_query('limit=1&filter[color]=a&filter[color]=b')
    assert_equal(%w[key_conflict], error_types(errors))
    assert_equal('filter', errors.first['parameter'])
    assert_equal('color', errors.first['key'])

    errors = validate_query('limit=1&filter[color]=blue&filter[size]=big')
    assert_equal(%w[integer], error_types(errors))
    assert_equal('filter', errors.first['parameter'])
  end

  def test_query_form_object_explode
    assert_valid_query('limit=1&a=true&b=2')

    errors = validate_query('limit=1&a=true&a=false')
    assert_equal(%w[key_conflict], error_types(errors))
    assert_equal('flags', errors.first['parameter'])
    assert_equal('a', errors.first['key'])

    errors = validate_query('limit=1&b=notint')
    assert_equal(%w[integer], error_types(errors))
    assert_equal('flags', errors.first['parameter'])
  end

  def test_query_form_object_no_explode
    assert_valid_query('limit=1&coords=x,1,y,2')
    assert_valid_query('limit=1&untypedObj=x,1')
    assert_valid_query('limit=1&rawObj=a,1')

    errors = validate_query('limit=1&coords=x,1,y')
    assert_equal(%w[invalid_object], error_types(errors))
    assert_equal('coords', errors.first['parameter'])

    errors = validate_query('limit=1&coords=x,1,x,2')
    assert_equal(%w[key_conflict], error_types(errors))
    assert_equal('x', errors.first['key'])

    errors = validate_query('limit=1&coords=x,1,z,2')
    assert_equal(%w[schema], error_types(errors))
    assert_equal('coords', errors.first['parameter'])
    assert_includes(errors.first['schema_pointer'], 'additionalProperties')
  end

  def test_query_string_and_plus_decoding
    assert_valid_query('limit=1&q=hello+world')

    errors = validate_query('limit=1&q=')
    assert_equal(%w[minLength], error_types(errors))
    assert_equal('q', errors.first['parameter'])
  end

  def test_query_number_coercion
    assert_valid_query('limit=1&ratio=1.5')

    errors = validate_query('limit=1&ratio=abc')
    assert_equal(%w[number], error_types(errors))
    assert_equal('ratio', errors.first['parameter'])
  end

  def test_query_boolean_and_ref_parameter
    assert_valid_query('limit=1&verbose=true')
    assert_valid_query('limit=1&verbose=false')

    errors = validate_query('limit=1&verbose=yes')
    assert_equal(%w[boolean], error_types(errors))
    assert_equal('verbose', errors.first['parameter'])
  end

  def test_query_ref_schema
    assert_valid_query('limit=1&refParam=5')

    errors = validate_query('limit=1&refParam=0')
    assert_equal(%w[minimum], error_types(errors))
    assert_equal('refParam', errors.first['parameter'])
  end

  def test_query_untyped_and_open_schemas
    assert_valid_query('limit=1&untypedIds=1&untypedIds=2')
    assert_valid_query('limit=1&rawArr=a&rawArr=b')
    assert_valid_query('limit=1&anything=whatever')
    assert_valid_query('limit=1&noSchema=x')
    assert_valid_query('limit=1')
  end

  def test_query_input_as_pairs_and_hash
    assert_empty(operation.validate(:query => [['limit', '1'], ['tags', 'a'], ['tags', 'b']], :path => { 'petId' => '5' }))
    assert_empty(operation.validate(:query => { 'limit' => '1' }, :path => { 'petId' => '5' }))
    assert_empty(operation.validate(:query => '&&limit=1&', :path => { 'petId' => '5' }))
  end

  def test_query_invalid_percent_encoding
    errors = validate_query('limit=%zz')
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('limit', errors.first['parameter'])
    assert_equal(0, errors.first['position'])

    errors = validate_query('%zz=1&limit=2')
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    refute(errors.first.key?('parameter'))
    assert_equal(0, errors.first['position'])

    errors = validate_query('limit=1&q=%FF')
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('q', errors.first['parameter'])
    assert_equal(1, errors.first['position'])
  end

  def test_query_invalid_percent_encoding_owns_pair
    errors = validate_query('limit=1&filter[color]=%zz')
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('filter[color]', errors.first['parameter'])

    errors = validate_query('limit=1&a=%zz')
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('a', errors.first['parameter'])

    errors = validate_query('other=%zz&limit=5')
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('other', errors.first['parameter'])
  end
  def test_path_simple_primitive
    assert_empty(files_operation.validate(:path => { 'name' => 'report' }))
    assert_empty(files_operation.validate(:path => { 'name' => 'a%20b' }))
    assert_empty(files_operation.validate(:path => { 'name' => 'a+b' }))

    errors = files_operation.validate(:path => {})
    assert_equal(%w[required], error_types(errors))
    assert_equal('name', errors.first['parameter'])
    assert_equal('path', errors.first['in'])

    errors = files_operation.validate(:path => { 'name' => '%zz' })
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('name', errors.first['parameter'])

    errors = files_operation.validate(:path => { 'name' => '%FF' })
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
  end

  def test_path_simple_type_error
    errors = operation.validate(:query => 'limit=1', :path => { 'petId' => 'abc' })
    assert_equal(%w[integer], error_types(errors))
    assert_equal('petId', errors.first['parameter'])
    assert_equal('path', errors.first['in'])
  end

  def test_path_input_as_pairs
    assert_empty(operation.validate(:query => 'limit=1', :path => [['petId', '5']]))
  end

  def test_missing_path_input
    errors = operation.validate(:query => 'limit=1')
    assert_equal(%w[required], error_types(errors))
    assert_equal('petId', errors.first['parameter'])
  end

  def test_path_simple_array
    assert_empty(files_operation.validate(:path => { 'name' => 'x', 'ids' => '1,2,3' }))

    errors = files_operation.validate(:path => { 'name' => 'x', 'ids' => '1,%zz' })
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('ids', errors.first['parameter'])

    errors = files_operation.validate(:path => { 'name' => 'x', 'ids' => '1,a' })
    assert_equal(%w[integer], error_types(errors))
    assert_equal('ids', errors.first['parameter'])
  end

  def test_path_simple_object_explode
    assert_empty(files_operation.validate(:path => { 'name' => 'x', 'map' => 'x=1,y=2' }))

    errors = files_operation.validate(:path => { 'name' => 'x', 'map' => 'x=1,x=2' })
    assert_equal(%w[key_conflict], error_types(errors))
    assert_equal('x', errors.first['key'])

    errors = files_operation.validate(:path => { 'name' => 'x', 'map' => 'x=1,bad' })
    assert_equal(%w[invalid_object], error_types(errors))
    assert_equal('map', errors.first['parameter'])

    errors = files_operation.validate(:path => { 'name' => 'x', 'map' => 'x=%zz' })
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
    assert_equal('map', errors.first['parameter'])

    errors = files_operation.validate(:path => { 'name' => 'x', 'map' => '%zz=1' })
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
  end

  def test_path_simple_object_no_explode
    assert_empty(files_operation.validate(:path => { 'name' => 'x', 'point' => 'x,1' }))

    errors = files_operation.validate(:path => { 'name' => 'x', 'point' => '1,2,3' })
    assert_equal(%w[invalid_object], error_types(errors))
    assert_equal('point', errors.first['parameter'])

    errors = files_operation.validate(:path => { 'name' => 'x', 'point' => 'x,1,x,2' })
    assert_equal(%w[key_conflict], error_types(errors))

    errors = files_operation.validate(:path => { 'name' => 'x', 'point' => 'x,%zz' })
    assert_equal(%w[invalid_percent_encoding], error_types(errors))
  end

  def test_header_simple
    assert_empty(headers_operation.validate(:headers => { 'X-Token' => 'abc', 'x-ids' => '1,2,3' }))

    errors = headers_operation.validate(:headers => { 'X-Token' => 'abc', 'X-Ids' => '1,a' })
    assert_equal(%w[integer], error_types(errors))
    assert_equal('X-Ids', errors.first['parameter'])
    assert_equal('header', errors.first['in'])

    errors = headers_operation.validate(:headers => {})
    assert_equal(%w[required], error_types(errors))
    assert_equal('X-Token', errors.first['parameter'])
  end

  def test_header_simple_object_explode
    assert_empty(headers_operation.validate(:headers => { 'X-Token' => 't', 'X-Flags' => 'debug=true' }))

    errors = headers_operation.validate(:headers => { 'X-Token' => 't', 'X-Flags' => 'debug=true,debug=false' })
    assert_equal(%w[key_conflict], error_types(errors))
    assert_equal('debug', errors.first['key'])

    errors = headers_operation.validate(:headers => { 'X-Token' => 't', 'X-Flags' => 'bad' })
    assert_equal(%w[invalid_object], error_types(errors))
  end

  def test_header_simple_object_no_explode
    assert_empty(headers_operation.validate(:headers => { 'X-Token' => 't', 'X-Coords' => 'x,1' }))

    errors = headers_operation.validate(:headers => { 'X-Token' => 't', 'X-Coords' => 'x,1,x,2' })
    assert_equal(%w[key_conflict], error_types(errors))

    errors = headers_operation.validate(:headers => { 'X-Token' => 't', 'X-Coords' => 'x' })
    assert_equal(%w[invalid_object], error_types(errors))
  end

  def test_header_input_as_pairs_with_duplicates
    headers = [['X-Token', 't'], ['X-Ids', '1,2'], ['X-Ids', '3']]
    assert_empty(headers_operation.validate(:headers => headers))
  end
  def document_with(parameters)
    {
      'openapi' => '3.1.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/things' => {
          'get' => {
            'parameters' => parameters
          }
        }
      }
    }
  end

  def operation_for(document, path: '/things', method: 'get')
    JSONSchemer.openapi(document).operation(path, method)
  end

  def test_unknown_operation
    document = JSONSchemer.openapi(document_with([]))
    assert_empty(document.operation('/things', 'get').parameters)
    assert_raises(JSONSchemer::UnknownOperation) { document.operation('/nope', 'get') }
    assert_raises(JSONSchemer::UnknownOperation) { document.operation('/things', 'post') }
    no_paths = JSONSchemer.openapi({ 'openapi' => '3.1.0', 'info' => { 'title' => 't', 'version' => '1' } })
    assert_raises(JSONSchemer::UnknownOperation) { no_paths.operation('/things', 'get') }
  end

  def test_unsupported_parameter_style
    assert_raises(JSONSchemer::UnsupportedParameterStyle) do
      operation_for(document_with([{ 'name' => 'id', 'in' => 'path', 'style' => 'label', 'schema' => {} }]))
    end
    assert_raises(JSONSchemer::UnsupportedParameterStyle) do
      operation_for(document_with([{ 'name' => 'ids', 'in' => 'query', 'style' => 'spaceDelimited', 'schema' => {} }]))
    end
    assert_raises(JSONSchemer::UnsupportedParameterStyle) do
      operation_for(document_with([{ 'name' => 'id', 'in' => 'path', 'style' => 'form', 'schema' => {} }]))
    end
  end

  def test_unsupported_deep_object_no_explode
    assert_raises(JSONSchemer::UnsupportedParameterStyle) do
      operation_for(document_with([{ 'name' => 'filter', 'in' => 'query', 'style' => 'deepObject', 'explode' => false, 'schema' => {} }]))
    end
  end

  def test_deep_object_explicit_explode
    document = document_with([{ 'name' => 'filter', 'in' => 'query', 'style' => 'deepObject', 'explode' => true, 'schema' => { 'type' => 'object' } }])
    assert_empty(operation_for(document).validate(:query => 'filter[a]=1'))
  end

  def test_unsupported_parameter_location
    assert_raises(JSONSchemer::UnsupportedParameterLocation) do
      operation_for(document_with([{ 'name' => 'session', 'in' => 'cookie', 'schema' => {} }]))
    end
  end

  def test_invalid_parameter
    assert_raises(JSONSchemer::InvalidParameter) { operation_for(document_with([true])) }
    assert_raises(JSONSchemer::InvalidParameter) { operation_for(document_with([{ 'in' => 'query' }])) }
    assert_raises(JSONSchemer::InvalidParameter) { operation_for(document_with([{ 'name' => 'x' }])) }
  end

  def test_cyclic_parameter_ref
    document = document_with([{ '$ref' => '#/components/parameters/A' }]).merge(
      'components' => {
        'parameters' => {
          'A' => { '$ref' => '#/components/parameters/B' },
          'B' => { '$ref' => '#/components/parameters/A' }
        }
      }
    )
    assert_raises(JSONSchemer::InvalidParameter) { operation_for(document) }
  end

  def test_openapi30
    document = {
      'openapi' => '3.0.0',
      'info' => { 'title' => 't', 'version' => '1' },
      'paths' => {
        '/things' => {
          'get' => {
            'parameters' => [
              { 'name' => 'limit', 'in' => 'query', 'schema' => { '$ref' => '#/components/schemas/Limit' } },
              { 'name' => 'tags', 'in' => 'query', 'explode' => false, 'schema' => { 'type' => 'array', 'items' => { 'type' => 'string' } } }
            ]
          }
        }
      },
      'components' => {
        'schemas' => {
          'Limit' => { 'type' => 'integer', 'maximum' => 10 }
        }
      }
    }
    op = JSONSchemer.openapi(document).operation('/things', 'get')
    assert_empty(op.validate(:query => 'limit=5&tags=a,b'))
    errors = op.validate(:query => 'limit=50')
    assert_equal(%w[maximum], error_types(errors))
    assert_equal('limit', errors.first['parameter'])
  end
end
