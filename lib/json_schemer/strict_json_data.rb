# frozen_string_literal: true
module JSONSchemer
  class InvalidJSONData < StandardError
    attr_reader :reason, :path, :offending_type

    def initialize(reason, path, message, offending_type: nil)
      @reason = reason
      @path = path
      @offending_type = offending_type
      super(message)
    end
  end

  # Optional strict check that instance data belongs to the JSON data domain
  # (objects with string keys, arrays, strings, finite numbers, true, false, null)
  # before it is evaluated against a schema. The check never mutates the input
  # and never calls to_json/to_hash on foreign objects.
  module StrictJSONData
    DEFAULT_MAX_DEPTH = 512
    DEFAULT_MAX_NODES = 100_000

    class << self
      def validate!(instance, options)
        return unless options

        max_depth = DEFAULT_MAX_DEPTH
        max_nodes = DEFAULT_MAX_NODES
        if options.is_a?(Hash)
          max_depth = options.fetch(:max_depth, max_depth)
          max_nodes = options.fetch(:max_nodes, max_nodes)
        end

        check(instance, max_depth, max_nodes)
        nil
      end

    private

      def check(instance, max_depth, max_nodes)
        nodes = 0
        active_object_ids = Set.new
        stack = [[:enter, instance, '', 0]]

        until stack.empty?
          action, value, path, depth = stack.pop

          if action == :exit
            active_object_ids.delete(value)
            next
          end

          nodes += 1
          if nodes > max_nodes
            raise InvalidJSONData.new(:max_nodes, path, "JSON data exceeds maximum node count of #{max_nodes} at #{display_path(path)}")
          end
          if depth > max_depth
            raise InvalidJSONData.new(:max_depth, path, "JSON data exceeds maximum depth of #{max_depth} at #{display_path(path)}")
          end

          case value
          when Hash
            enter_container(value, path, active_object_ids)
            stack << [:exit, value.object_id]
            value.each do |key, child|
              unless key.is_a?(String)
                key_path = join(path, key_segment(key))
                raise InvalidJSONData.new(:invalid_key, key_path, "JSON object key at #{display_path(key_path)} is a #{key.class}, expected a String", :offending_type => key.class.name)
              end
              stack << [:enter, child, join(path, key), depth + 1]
            end
          when Array
            enter_container(value, path, active_object_ids)
            stack << [:exit, value.object_id]
            value.each_with_index do |child, index|
              stack << [:enter, child, "#{path}/#{index}", depth + 1]
            end
          when String, Integer, true, false, nil
            # valid JSON scalar
          when Float
            raise InvalidJSONData.new(:non_finite_number, path, "non-finite Float at #{display_path(path)} is not valid JSON", :offending_type => 'Float') unless value.finite?
          when BigDecimal
            raise InvalidJSONData.new(:non_finite_number, path, "non-finite BigDecimal at #{display_path(path)} is not valid JSON", :offending_type => 'BigDecimal') unless value.finite?
          else
            raise InvalidJSONData.new(:invalid_type, path, "#{value.class} at #{display_path(path)} is not a valid JSON type", :offending_type => value.class.name)
          end
        end
        nil
      end

      def enter_container(container, path, active_object_ids)
        object_id = container.object_id
        if active_object_ids.include?(object_id)
          raise InvalidJSONData.new(:circular_reference, path, "circular reference to #{container.class} at #{display_path(path)}", :offending_type => container.class.name)
        end
        active_object_ids << object_id
      end

      def join(path, key)
        "#{path}/#{Location.escape_json_pointer_token(key)}"
      end

      def key_segment(key)
        case key
        when Symbol, Integer, Float, true, false, nil
          key.to_s
        else
          "<#{key.class.name}>"
        end
      end

      def display_path(path)
        path.empty? ? '/' : path
      end
    end
  end
end
