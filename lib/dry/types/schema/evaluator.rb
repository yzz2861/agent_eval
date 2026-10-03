# frozen_string_literal: true

module Dry
  module Types
    class Schema < Hash
      class Evaluator
        def initialize(schema, input, options, mode:)
          @schema = schema
          @input = input
          @options = options
          @mode = mode
          @output = {}
          @raw = {}
          @errors = []
          @member_results = {}
          @halted = false
        end

        def call
          unless input.is_a?(::Hash)
            return Result::Failure.new(input, CoercionError.new("#{input.inspect} must be a hash"))
          end

          process_members
          return failure if halted?

          validate_groups(:before_defaults, raw)
          return failure if stop_before_defaults?
          resolve_missing_keys
          return failure if halted?

          validate_groups(:after_defaults, output)

          errors.empty? && schema.primitive?(output) ? Result::Success.new(output) : failure
        end

        private

        attr_reader :schema, :input, :options, :mode, :output, :raw,
                    :errors, :member_results

        def process_members
          input.each do |input_key, value|
            key = schema.transform_key.(input_key)
            key_type = schema.name_key_map[key]

            if key_type
              process_member(key, key_type, value)
            elsif schema.strict?
              add_error(schema.send(:unexpected_keys, input.keys))
              halt
            end

            return if halted?
          end
        end

        def process_member(name, key_type, value)
          raw[name] = value

          case mode
          when :try
            member_result = key_type.try(value)
            member_results[name] = member_result
            output[name] = member_result.input
            add_error(member_result.error) unless member_result.success?
          when :safe
            output[name] = key_type.call_safe(value) { halt }
          when :unsafe
            output[name] = key_type.call_unsafe(value)
          end
        rescue ConstraintError => exception
          add_error(SchemaError.new(name, value, exception.result))
        rescue CoercionError => exception
          add_error(member_error(name, value, exception))
        end

        def member_error(name, value, exception)
          if group_error?(exception)
            exception
          else
            SchemaError.new(name, value, exception.message)
          end
        end

        def group_error?(error)
          error.is_a?(FieldGroupError) ||
            (error.is_a?(MultipleError) &&
              error.errors.any? { |child| child.is_a?(FieldGroupError) })
        end

        def validate_groups(phase, source)
          schema.field_groups.each do |group|
            next unless group.check == phase

            present = group.paths.select { |path| path_present?(path, source) }
            add_error(FieldGroupError.new(group, present)) unless valid_group?(group, present.size)
          end
        end

        def valid_group?(group, count)
          case group.kind
          when :exactly_one
            count == 1
          when :at_least_one
            count >= 1
          when :all_or_none
            count.zero? || count == group.paths.size
          end
        end

        def path_present?(path, source) = traverse_path(schema, path, source)

        def traverse_path(current_schema, path, source)
          return false unless source.is_a?(::Hash)

          key = path.first
          key_type = current_schema.name_key_map[key]
          return false unless key_type

          transformed_key = current_schema.transform_key.(key)
          return false unless source.key?(transformed_key)
          return true if path.size == 1

          child_schema = schema_for(key_type)
          child_schema && traverse_path(child_schema, path[1..], source[transformed_key])
        end

        def schema_for(key_type)
          type = key_type
          while type.respond_to?(:type) && !type.is_a?(Schema)
            type = type.type
          end
          type if type.is_a?(Schema)
        end

        def resolve_missing_keys
          skip = options.fetch(:skip_missing, false)
          resolve_defaults = options.fetch(:resolve_defaults, true)

          schema.keys.each do |key|
            next if output.key?(key.name) || raw.key?(key.name)

            if key.default? && resolve_defaults
              output[key.name] = resolve_default(key)
            elsif key.required? && !skip
              add_error(MissingKeyError.new(key.name))
              halt unless mode == :try
            end

            return if halted?
          end
        end

        def resolve_default(key)
          case mode
          when :try
            result = key.try(Undefined)
            add_error(result.error) unless result.success?
            result.input
          when :safe
            key.call_safe(Undefined) { halt }
          when :unsafe
            key.call_unsafe(Undefined)
          end
        end

        def add_error(error)
          errors << error unless error.is_a?(FieldGroupError) && errors.include?(error)
        end

        def halt
          @halted = true
        end

        def stop_before_defaults?
          errors.any? { |error| error.is_a?(FieldGroupError) } ||
            (mode != :try && errors.any?)
        end

        def halted? = @halted

        def failure = Result::Failure.new(output, failure_error)

        def failure_error
          if member_results.any?
            return CoercionError.new("#{input} doesn't conform schema", meta: failure_meta)
          end

          return errors.first if errors.size == 1
          MultipleError.new(errors)
        end

        def failure_meta
          member_results.merge(group_error_meta)
        end

        def group_error_meta
          groups = errors.select { |error| error.is_a?(FieldGroupError) }
          groups.empty? ? EMPTY_HASH : {groups: groups}
        end
      end
    end
  end
end
