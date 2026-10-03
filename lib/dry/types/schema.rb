# frozen_string_literal: true

module Dry
  module Types
    # The built-in Hash type can be defined in terms of keys and associated types
    # its values can contain. Such definitions are named {Schema}s and defined
    # as lists of {Key} types.
    #
    # @see Dry::Types::Schema::Key
    #
    # {Schema} evaluates default values for keys missing in input hash
    #
    # @see Dry::Types::Default#evaluate
    # @see Dry::Types::Default::Callable#evaluate
    #
    # {Schema} implements Enumerable using its keys as collection.
    #
    # @api public
    class Schema < Hash
      NO_TRANSFORM = ::Dry::Types::FnContainer.register { |x| x }
      SYMBOLIZE_KEY = ::Dry::Types::FnContainer.register(:to_sym.to_proc)

      include ::Enumerable

      # @return [Array[Dry::Types::Schema::Key]]
      attr_reader :keys

      # @return [Hash[Symbol, Dry::Types::Schema::Key]]
      attr_reader :name_key_map

      # @return [Array[Dry::Types::Schema::KeyGroup]]
      attr_reader :key_groups

      # @return [#call]
      attr_reader :transform_key

      # @param [Class] _primitive
      # @param [Hash] options
      #
      # @option options [Array[Dry::Types::Schema::Key]] :keys
      # @option options [String] :key_transform_fn
      #
      # @api private
      def initialize(_primitive, **options)
        @keys = options.fetch(:keys)
        @name_key_map = keys.each_with_object({}) do |key, idx|
          idx[key.name] = key
        end

        raw_groups = options.fetch(:key_groups, EMPTY_ARRAY)
        @key_groups = raw_groups.map { |group| KeyGroup.coerce(group) }
        if @key_groups.empty?
          options.delete(:key_groups)
        else
          options[:key_groups] = @key_groups
        end

        validate_key_groups!

        key_fn = options.fetch(:key_transform_fn, NO_TRANSFORM)

        @transform_key = ::Dry::Types::FnContainer[key_fn]

        super
      end

      # Groups of keys of which exactly one must be present
      #
      # Each member is a key name, a fixed nested path wrapped in an array
      # (+[[:creds, :token]]+) or a bundle of keys/paths required together
      # (+[:username, :password]+).
      #
      # @param paths [Array<Symbol, Array>] group members
      # @param check [Symbol] +:before_defaults+ (default) or +:after_defaults+
      #
      # @return [Schema]
      #
      # @api public
      def exactly_one(*paths, check: :before_defaults)
        add_key_group(KeyGroup.new(:exactly_one, paths, check: check))
      end

      # Groups of keys of which at least one must be present
      #
      # @param paths (see #exactly_one)
      # @param check (see #exactly_one)
      #
      # @return [Schema]
      #
      # @api public
      def at_least_one(*paths, check: :before_defaults)
        add_key_group(KeyGroup.new(:at_least_one, paths, check: check))
      end

      # Groups of keys that must all be present or all missing
      #
      # @param paths (see #exactly_one)
      # @param check (see #exactly_one)
      #
      # @return [Schema]
      #
      # @api public
      def all_or_none(*paths, check: :before_defaults)
        add_key_group(KeyGroup.new(:all_or_none, paths, check: check))
      end

      # @param [Hash] hash
      #
      # @return [Hash{Symbol => Object}]
      #
      # @api private
      def call_unsafe(hash, options = EMPTY_HASH)
        resolve_unsafe(coerce(hash), options)
      end

      # @param [Hash] hash
      #
      # @return [Hash{Symbol => Object}]
      #
      # @api private
      def call_safe(hash, options = EMPTY_HASH)
        resolve_safe(coerce(hash) { return yield }, options) { return yield }
      end

      # @param [Hash] hash
      #
      # @option options [Boolean] :skip_missing If true don't raise error if on missing keys
      # @option options [Boolean] :resolve_defaults If false default value
      #                                             won't be evaluated for missing key
      # @return [Hash{Symbol => Object}]
      #
      # @api public
      def apply(hash, options = EMPTY_HASH) = call_unsafe(hash, options)

      # @param input [Hash] hash
      #
      # @yieldparam [Failure] failure
      # @yieldreturn [Result]
      #
      # @return [Logic::Result]
      # @return [Object] if coercion fails and a block is given
      #
      # @api public
      # rubocop:disable Metrics/AbcSize
      # rubocop:disable Metrics/PerceivedComplexity
      def try(input)
        if primitive?(input)
          success = true
          output = {}
          result = {}

          input.each do |key, value|
            k = @transform_key.(key)
            type = @name_key_map[k]

            if type
              key_result = type.try(value)
              result[k] = key_result
              output[k] = key_result.input
              success &&= key_result.success?
            elsif strict?
              success = false
            end
          end

          group_errors = evaluate_key_groups(input, :before_defaults)
          success &&= group_errors.empty?

          if output.size < keys.size
            resolve_missing_keys(output, options) do
              success = false
            end
          end

          group_errors.concat(evaluate_key_groups(output, :after_defaults))
          success &&= group_errors.empty?

          success &&= primitive?(output)

          if success
            failure = nil
          else
            error = CoercionError.new("#{input} doesn't conform schema", meta: result)
            error.group_errors = group_errors
            failure = failure(output, error)
          end
        else
          failure = failure(input, CoercionError.new("#{input} must be a hash"))
        end

        if failure.nil?
          success(output)
        elsif block_given?
          yield(failure)
        else
          failure
        end
      end
      # rubocop:enable Metrics/AbcSize
      # rubocop:enable Metrics/PerceivedComplexity

      # @param meta [Boolean] Whether to dump the meta to the AST
      #
      # @return [Array] An AST representation
      #
      # @api public
      def to_ast(meta: true)
        [
          :schema,
          [keys.map { |key| key.to_ast(meta: meta) },
           options.slice(
             :key_transform_fn, :type_transform_fn, :strict, :namespace, :key_groups
           ).then { |opts| serialize_key_groups(opts) },
           meta_ast(meta)]
        ]
      end

      # Whether the schema rejects unknown keys
      #
      # @return [Boolean]
      #
      # @api public
      def strict?
        options.fetch(:strict, false)
      end

      # Make the schema intolerant to unknown keys
      #
      # @return [Schema]
      #
      # @api public
      def strict(strict = true)
        with(strict: strict)
      end

      # Inject a key transformation function
      #
      # @param [#call,nil] proc
      # @param [#call,nil] block
      #
      # @return [Schema]
      #
      # @api public
      def with_key_transform(proc = nil, &block)
        fn = proc || block

        raise ::ArgumentError, "a block or callable argument is required" if fn.nil?

        handle = ::Dry::Types::FnContainer.register(fn)
        with(key_transform_fn: handle)
      end

      # Whether the schema transforms input keys
      #
      # @return [Boolean]
      #
      # @api public
      def transform_keys?
        !options[:key_transform_fn].nil?
      end

      # @overload schema(type_map, meta = EMPTY_HASH)
      #   @param [{Symbol => Dry::Types::Nominal}] type_map
      #   @param [Hash] meta
      #   @return [Dry::Types::Schema]
      #
      # @overload schema(keys)
      #   @param [Array<Dry::Types::Schema::Key>] key List of schema keys
      #   @param [Hash] meta
      #   @return [Dry::Types::Schema]
      #
      # @api public
      def schema(keys_or_map)
        if keys_or_map.is_a?(::Array)
          new_keys = keys_or_map
        else
          new_keys = build_keys(keys_or_map)
        end

        keys = merge_keys(self.keys, new_keys)
        Schema.new(primitive, **options, keys: keys, meta: meta)
      end

      # Iterate over each key type
      #
      # @return [Array<Dry::Types::Schema::Key>,Enumerator]
      #
      # @api public
      def each(&)
        keys.each(&)
      end

      # Whether the schema has the given key
      #
      # @param [Symbol] name Key name
      #
      # @return [Boolean]
      #
      # @api public
      def key?(name)
        name_key_map.key?(name)
      end

      # Fetch key type by a key name
      #
      # Behaves as ::Hash#fetch
      #
      # @overload key(name, fallback = Undefined)
      #   @param [Symbol] name Key name
      #   @param [Object] fallback Optional fallback, returned if key is missing
      #   @return [Dry::Types::Schema::Key,Object] key type or fallback if key is not in schema
      #
      # @overload key(name, &block)
      #   @param [Symbol] name Key name
      #   @param [Proc] block Fallback block, runs if key is missing
      #   @return [Dry::Types::Schema::Key,Object] key type or block value if key is not in schema
      #
      # @api public
      def key(name, fallback = Undefined, &)
        if Undefined.equal?(fallback)
          name_key_map.fetch(name, &)
        else
          name_key_map.fetch(name, fallback)
        end
      end

      # @return [Boolean]
      #
      # @api public
      def constrained?
        true
      end

      # @return [Lax]
      #
      # @api public
      def lax
        Lax.new(schema(keys.map(&:lax)).with(key_groups: EMPTY_ARRAY))
      end

      # Merge given schema keys into current schema
      #
      # A new instance is returned.
      #
      # @param other [Schema] schema
      # @return [Schema]
      #
      # @api public
      def merge(other)
        schema(other.keys)
      end

      # Empty schema with the same options
      #
      # @return [Schema]
      #
      # @api public
      def clear
        with(keys: EMPTY_ARRAY, key_groups: EMPTY_ARRAY)
      end

      # Build a hash with keys transformed by this schema's key transform
      # without invoking any member constructors
      #
      # @api private
      def transformed_input(input)
        return input unless transform_keys?
        return input unless input.is_a?(::Hash)

        input.each_with_object({}) do |(raw_key, value), normalized|
          normalized[@transform_key.(raw_key)] = value
        end
      end

      private

      # @param [Array<Dry::Types::Schema::Keys>] keys
      #
      # @return [Dry::Types::Schema]
      #
      # @api private
      def merge_keys(*keys)
        keys
          .flatten(1)
          .each_with_object({}) { |key, merged| merged[key.name] = key }
          .values
      end

      # Validate and coerce a hash. Raise an exception on any error
      #
      # @api private
      #
      # @return [Hash]
      def resolve_unsafe(hash, options = EMPTY_HASH)
        result = {}
        aggregate = !key_groups.empty?
        errors = []

        hash.each do |key, value|
          k = @transform_key.(key)
          type = @name_key_map[k]

          if type
            begin
              result[k] = type.call_unsafe(value)
            rescue ConstraintError => exception
              error = SchemaError.new(type.name, value, exception.result)
              raise error unless aggregate
              errors << error
            rescue CoercionError => exception
              error = SchemaError.new(type.name, value, exception.message)
              raise error unless aggregate
              errors << error
            end
          elsif strict?
            raise unexpected_keys(hash.keys)
          end
        end

        before_errors = evaluate_key_groups(hash, :before_defaults)
        after_errors = []

        if aggregate
          errors.concat(before_errors)

          if result.size < keys.size
            resolve_missing_keys(result, options) { |error| errors << error }
          end

          after_errors = evaluate_key_groups(result, :after_defaults)
          errors.concat(after_errors)
          raise_errors(errors)
        else
          raise before_errors.first unless before_errors.empty?

          if result.size < keys.size
            resolve_missing_keys(result, options) { |error| raise error }
          end

          raise after_errors.first unless after_errors.empty?
        end

        result
      end

      # Validate and coerce a hash. Call a block and halt on any error
      #
      # @api private
      #
      # @return [Hash]
      def resolve_safe(hash, options = EMPTY_HASH, &block)
        result = {}

        hash.each do |key, value|
          k = @transform_key.(key)
          type = @name_key_map[k]

          if type
            result[k] = type.call_safe(value, &block)
          elsif strict?
            yield
          end
        end

        return yield(result) unless evaluate_key_groups(hash, :before_defaults).empty?

        if result.size < keys.size
          resolve_missing_keys(result, options) { return yield(result) }
        end

        return yield(result) unless evaluate_key_groups(result, :after_defaults).empty?

        result
      end

      # Try to add missing keys to the hash
      #
      # @api private
      def resolve_missing_keys(hash, options) # rubocop:disable Metrics/PerceivedComplexity
        skip_missing = options.fetch(:skip_missing, false)
        resolve_defaults = options.fetch(:resolve_defaults, true)

        keys.each do |key|
          next if hash.key?(key.name)

          if key.default? && resolve_defaults
            hash[key.name] = key.call_unsafe(Undefined)
          elsif key.required? && !skip_missing
            error = missing_key(key.name)
            block_given? ? yield(error) : raise(error)
          end
        end
      end

      # @param hash_keys [Array<Symbol>]
      #
      # @return [UnknownKeysError]
      #
      # @api private
      def unexpected_keys(hash_keys)
        extra_keys = hash_keys.map(&transform_key) - name_key_map.keys
        UnknownKeysError.new(extra_keys)
      end

      # Raise the only error or a MultipleError aggregating all of them
      #
      # @api private
      def raise_errors(errors)
        return if errors.empty?

        raise errors.first if errors.size == 1

        raise MultipleError.new(errors)
      end

      # @return [Schema]
      #
      # @api private
      def add_key_group(group)
        validate_group_paths!(group)
        with(key_groups: [*key_groups, group])
      end

      # Make sure every group references an existing fixed path
      #
      # @api private
      def validate_key_groups!
        key_groups.each { |group| validate_group_paths!(group) }
      end

      # @api private
      def validate_group_paths!(group)
        group.paths.each do |path|
          validate_path!(path)
        end
      end

      # @api private
      def validate_path!(path)
        schema = self

        path.each_with_index do |segment, index|
          key = schema.name_key_map[segment]

          if key.nil?
            raise ::ArgumentError,
              "cannot define a group on #{path.inspect}: " \
              "#{path[0..index].inspect} is not a key of the schema"
          end

          nested = unwrap_schema(key.type)

          if index < path.size - 1 && nested.nil?
            raise ::ArgumentError,
              "cannot define a group on #{path.inspect}: " \
              "#{path[0..index].inspect} is not a nested schema"
          end

          schema = nested
        end
      end

      # Unwrap decorators until a Schema is found
      #
      # @api private
      def unwrap_schema(type)
        seen = {}

        while type.respond_to?(:type) && !type.is_a?(Schema)
          break if seen.key?(type.object_id)

          seen[type.object_id] = true
          type = type.type
        end

        type if type.is_a?(Schema)
      end

      # Evaluate groups assigned to a given phase against raw input
      #
      # @param input [Hash]
      # @param moment [Symbol]
      #
      # @return [Array<KeyGroupError>]
      #
      # @api private
      def evaluate_key_groups(input, moment)
        key_groups.each_with_object([]) do |group, errors|
          next unless group.check == moment

          present, missing = partition_members(group.members, input)
          error = group_violation(group, present, missing)
          errors << error if error
        end
      end

      # @return [KeyGroupError, nil]
      #
      # @api private
      def group_violation(group, present, missing) # rubocop:disable Metrics/PerceivedComplexity
        count = present.size

        violated =
          case group.kind
          when :exactly_one then count != 1
          when :at_least_one then count.zero?
          when :all_or_none then !present.empty? && !missing.empty?
          end

        KeyGroupError.new(group.kind, group.members, present, missing) if violated
      end

      # Split group members into present and missing ones without
      # running any constructors
      #
      # @return [Array(Array, Array)]
      #
      # @api private
      def partition_members(members, input)
        present = []
        missing = []

        members.each do |paths|
          if paths.all? { |path| path_present?(input, path) }
            present << paths
          else
            missing << paths
          end
        end

        [present, missing]
      end

      # Whether a fixed nested path exists in raw input. An explicit nil
      # counts as present.
      #
      # @api private
      def path_present?(input, path)
        schema = self
        current = input

        path.each do |segment|
          current = schema.transformed_input(current)
          return false unless current.is_a?(::Hash)
          return false unless current.key?(segment)

          current = current[segment]
          next_schema = unwrap_schema(schema.name_key_map[segment].type)
          schema = next_schema if next_schema
        end

        true
      end


      # @return [Hash]
      #
      # @api private
      def serialize_key_groups(options)
        return options unless options.key?(:key_groups)

        groups = options[:key_groups].map do |group|
          group = KeyGroup.coerce(group)
          {kind: group.kind, members: group.members, check: group.check}
        end

        options.merge(key_groups: groups)
      end

      # @return [MissingKeyError]
      #
      # @api private
      def missing_key(key)
        MissingKeyError.new(key)
      end
    end
  end
end
