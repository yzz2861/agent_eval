# frozen_string_literal: true
module JSONSchemer
  class InvalidJSONData < StandardError
    attr_reader :errors

    def initialize(errors)
      @errors = errors.freeze
      message = errors.first.message
      message = "#{message} (and #{errors.size - 1} more)" if errors.size > 1
      super("invalid JSON data: #{message}")
    end
  end

  # Strict JSON data domain check. Only values that JSON can represent are
  # allowed: hashes with string keys, arrays, strings, integers, finite
  # floats, true, false, and nil. Instances are inspected as-is without
  # calling `to_json`, `to_hash`, or any other coercion method, and the
  # check never modifies the data it traverses.
  module JSONData
    DEFAULT_MAX_DEPTH = 100
    DEFAULT_MAX_NODES = 10_000

    Error = Struct.new(:path, :type, :message, keyword_init: true)

    class << self
      def validate(data, max_depth: DEFAULT_MAX_DEPTH, max_nodes: DEFAULT_MAX_NODES)
        errors = []
        nodes = 0
        ancestors = []
        stack = [[data, '', 1, 0]]

        until stack.empty?
          value, path, depth, ancestor_size = stack.pop
          ancestors.slice!(ancestor_size..-1) if ancestors.size > ancestor_size

          nodes += 1
          if nodes > max_nodes
            errors << build_error(path, 'max_nodes_exceeded', "exceeded maximum of #{max_nodes} nodes at #{location(path)}")
            break
          end

          if (value.is_a?(Hash) || value.is_a?(Array)) && depth > max_depth
            errors << build_error(path, 'max_depth_exceeded', "exceeded maximum depth of #{max_depth} at #{location(path)}")
            break
          end

          case value
          when Hash
            if ancestors.include?(value.object_id)
              errors << build_error(path, 'circular_reference', "circular reference at #{location(path)}")
            else
              ancestors << value.object_id
              child_ancestor_size = ancestors.size
              children = []
              value.each do |key, child|
                child_path = join_path(path, key)
                unless key.is_a?(String)
                  type = key.is_a?(Symbol) ? 'symbol_key' : 'unsupported_key_type'
                  errors << build_error(child_path, type, "#{key.class} key at #{location(child_path)}")
                end
                children << [child, child_path, depth + 1, child_ancestor_size]
              end
              stack.concat(children.reverse!)
            end
          when Array
            if ancestors.include?(value.object_id)
              errors << build_error(path, 'circular_reference', "circular reference at #{location(path)}")
            else
              ancestors << value.object_id
              child_ancestor_size = ancestors.size
              children = []
              value.each_with_index do |child, index|
                children << [child, join_path(path, index), depth + 1, child_ancestor_size]
              end
              stack.concat(children.reverse!)
            end
          when String, Integer, true, false, nil
            # valid JSON data
          when Float
            if value.nan?
              errors << build_error(path, 'nan', "NaN at #{location(path)}")
            elsif value.infinite?
              errors << build_error(path, 'infinity', "Infinity at #{location(path)}")
            end
          else
            errors << build_error(path, 'unsupported_type', "unsupported type #{value.class} at #{location(path)}")
          end
        end

        errors
      end

      def validate!(data, **options)
        errors = validate(data, **options)
        raise InvalidJSONData, errors unless errors.empty?
        data
      end

    private

      def build_error(path, type, message)
        Error.new(:path => path, :type => type, :message => message).freeze
      end

      def join_path(path, token)
        "#{path}/#{Location.escape_json_pointer_token(token.to_s)}"
      end

      def location(path)
        path.empty? ? 'root' : "`#{path}`"
      end
    end
  end
end
