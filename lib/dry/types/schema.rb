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

      # @return [#call]
      attr_reader :transform_key

      # @return [Array[Dry::Types::Schema::FieldGroup]]
      attr_reader :field_groups

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

        key_fn = options.fetch(:key_transform_fn, NO_TRANSFORM)

        @transform_key = ::Dry::Types::FnContainer[key_fn]
        @field_groups = options.fetch(:field_groups, EMPTY_ARRAY).map do |group|
          normalized = group.is_a?(FieldGroup) ? group : FieldGroup.from_ast(group)
          validate_group_paths!(normalized)
          normalized
        end.freeze
        options = options.merge(field_groups: field_groups) unless field_groups.empty?

        super
      end

      # @param [Hash] hash
      #
      # @return [Hash{Symbol => Object}]
      #
      # @api private
      def call_unsafe(hash, options = EMPTY_HASH)
        result = Evaluator.new(self, coerce(hash), options, mode: :unsafe).call
        result.success? ? result.input : raise(result.error)
      end

      # @param [Hash] hash
      #
      # @return [Hash{Symbol => Object}]
      #
      # @api private
      def call_safe(hash, options = EMPTY_HASH)
        result = Evaluator.new(self, coerce(hash) { return yield }, options, mode: :safe).call
        return result.input if result.success?

        yield(result.input)
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
      def try(input)
        result = Evaluator.new(self, input, EMPTY_HASH, mode: :try).call
        block_given? && result.failure? ? yield(result) : result
      end

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
             :key_transform_fn, :type_transform_fn, :strict, :namespace
           ).merge(field_groups_ast),
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

      # Require exactly one field or nested field to be present.
      #
      # @param paths [Array<Symbol, Array<Symbol>>]
      # @param name [Symbol, nil]
      # @param check [Symbol] :before_defaults or :after_defaults
      #
      # @return [Schema]
      #
      # @api public
      def exactly_one(
        *paths, name: nil, check: nil,
        before_defaults: false, after_defaults: false
      )
        add_field_group(
          :exactly_one, paths,
          name: name,
          check: resolve_group_check(check, before_defaults, after_defaults)
        )
      end

      # Require at least one field or nested field to be present.
      #
      # @param (see #exactly_one)
      #
      # @return [Schema]
      #
      # @api public
      def at_least_one(
        *paths, name: nil, check: nil,
        before_defaults: false, after_defaults: false
      )
        add_field_group(
          :at_least_one, paths,
          name: name,
          check: resolve_group_check(check, before_defaults, after_defaults)
        )
      end

      # Require all members of a group to be present together or absent.
      #
      # @param (see #exactly_one)
      #
      # @return [Schema]
      #
      # @api public
      def all_or_none(
        *paths, name: nil, check: nil,
        before_defaults: false, after_defaults: false
      )
        add_field_group(
          :all_or_none, paths,
          name: name,
          check: resolve_group_check(check, before_defaults, after_defaults)
        )
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
        Lax.new(schema(keys.map(&:lax)))
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
        with(keys: EMPTY_ARRAY, **field_groups_ast)
      end

      private

      def resolve_group_check(check, before_defaults, after_defaults)
        if before_defaults && after_defaults
          raise ::ArgumentError, "choose either before_defaults: true or after_defaults: true"
        end

        check || (after_defaults ? :after_defaults : :before_defaults)
      end

      def add_field_group(kind, paths, name:, check:)
        group = FieldGroup.[](kind, paths, name: name, check: check)
        validate_group_paths!(group)
        with(field_groups: field_groups + [group])
      end

      def validate_group_paths!(group)
        group.paths.each do |path|
          unless path_present_in_schema?(self, path)
            raise ::ArgumentError, "field group path #{path.inspect} is not defined in schema"
          end
        end
      end

      def path_present_in_schema?(current_schema, path)
        key_type = current_schema.name_key_map[path.first]
        return false unless key_type
        return true if path.size == 1

        nested_schema = schema_for_validation(key_type)
        nested_schema && path_present_in_schema?(nested_schema, path[1..])
      end

      def schema_for_validation(key_type)
        type = key_type
        while type.respond_to?(:type) && !type.is_a?(Schema)
          type = type.type
        end
        type if type.is_a?(Schema)
      end

      def field_groups_ast
        field_groups.empty? ? EMPTY_HASH : {field_groups: field_groups.map(&:to_ast)}
      end

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

      # @param hash_keys [Array<Symbol>]
      #
      # @return [UnknownKeysError]
      #
      # @api private
      def unexpected_keys(hash_keys)
        extra_keys = hash_keys.map(&transform_key) - name_key_map.keys
        UnknownKeysError.new(extra_keys)
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
