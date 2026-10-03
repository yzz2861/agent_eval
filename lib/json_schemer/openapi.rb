# frozen_string_literal: true
module JSONSchemer
  class OpenAPI
    HTTP_METHODS = %w[get put post delete options head patch trace].freeze

    def initialize(document, **options)
      @document = document

      version = document['openapi']
      case version
      when /\A3\.1\.\d+\z/
        @document_schema = JSONSchemer.openapi31_document
        meta_schema = document.fetch('jsonSchemaDialect') { OpenAPI31::BASE_URI.to_s }
      when /\A3\.0\.\d+\z/
        @document_schema = JSONSchemer.openapi30_document
        meta_schema = OpenAPI30::BASE_URI.to_s
      else
        raise UnsupportedOpenAPIVersion, version
      end

      @schema = JSONSchemer.schema(@document, :meta_schema => meta_schema, **options)
    end

    attr_reader :document

    def valid?
      @document_schema.valid?(@document)
    end

    def validate(**options)
      @document_schema.validate(@document, **options)
    end

    def ref(value)
      @schema.ref(value)
    end

    def schema(name)
      ref("#/components/schemas/#{name}")
    end

    def operation(path, method = 'get')
      path_item = resolve_document_pointer(@document.fetch('paths', {}), "/#{pointer_token(path)}")
      method = method.to_s.downcase
      raise ArgumentError, "unknown operation: #{method.upcase} #{path}" unless path_item.is_a?(Hash) && HTTP_METHODS.include?(method) && path_item.key?(method)
      operation = path_item.fetch(method)
      OpenAPI::Operation.new(
        self,
        path,
        method,
        resolve_parameters(path, method, path_item, operation)
      )
    end

    def document_schema_for_pointer(pointer)
      @schema.ref("##{fragment_pointer(pointer)}")
    end

    def resolve_document_pointer(node, pointer)
      Hana::Pointer.parse(pointer).reduce(node) do |object, token|
        object.fetch(token)
      end
    rescue IndexError, KeyError
      nil
    end

    def pointer_token(token)
      Location.escape_json_pointer_token(token)
    end

    def fragment_pointer(pointer)
      pointer.split('/').map do |token|
        token.gsub(/[^A-Za-z0-9\-._~!$&'()*+,;=:@?\/]/) do |character|
          '%' + character.ord.to_s(16).upcase.rjust(2, '0')
        end
      end.join('/')
    end

  private

    def resolve_parameters(path, method, path_item, operation)
      path_pointer = "/paths/#{pointer_token(path)}"
      path_item_parameters = Array(path_item['parameters'])
      operation_parameters = Array(operation['parameters'])
      path_item_parameters.each_with_index.map do |parameter, index|
        definition, pointer = resolve_parameter_ref(parameter, "#{path_pointer}/parameters/#{index}")
        OpenAPI::PreparedParameter.new(self, definition, pointer)
      end + operation_parameters.each_with_index.map do |parameter, index|
        definition, pointer = resolve_parameter_ref(parameter, "#{path_pointer}/#{method}/parameters/#{index}")
        OpenAPI::PreparedParameter.new(self, definition, pointer)
      end
    end

    def resolve_parameter_ref(parameter, inline_pointer)
      ref = parameter.is_a?(Hash) ? parameter['$ref'] : nil
      return [parameter, inline_pointer] unless ref
      raise InvalidRefResolution, ref unless ref.start_with?('#')
      pointer = ref[1..-1]
      resolved = resolve_document_pointer(@document, pointer)
      raise InvalidRefPointer, pointer unless resolved.is_a?(Hash)
      [resolved, pointer]
    end
  end
end
