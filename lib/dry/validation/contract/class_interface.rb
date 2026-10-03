# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    class Contract
      # Contract's class interface
      #
      # @see Contract
      #
      # @api public
      module ClassInterface
        include Macros::Registrar

        # @api private
        def inherited(klass)
          super
          klass.instance_variable_set("@config", config.dup)
        end

        # Configuration
        #
        # @example
        #   class MyContract < Dry::Validation::Contract
        #     config.messages.backend = :i18n
        #   end
        #
        # @return [Config]
        #
        # @api public
        def config
          @config ||= Validation::Config.new
        end

        # Return macros registered for this class
        #
        # @return [Macros::Container]
        #
        # @api public
        def macros
          config.macros
        end

        # Define a params schema for your contract
        #
        # This type of schema is suitable for HTTP parameters
        #
        # @return [Dry::Schema::Params,NilClass]
        # @see https://dry-rb.org/gems/dry-schema/params/
        #
        # @api public
        def params(*external_schemas, &)
          define(:Params, external_schemas, &)
        end

        # Define a JSON schema for your contract
        #
        # This type of schema is suitable for JSON data
        #
        # @return [Dry::Schema::JSON,NilClass]
        # @see https://dry-rb.org/gems/dry-schema/json/
        #
        # @api public
        def json(*external_schemas, &)
          define(:JSON, external_schemas, &)
        end

        # Define a plain schema for your contract
        #
        # This type of schema does not offer coercion out of the box
        #
        # @return [Dry::Schema::Processor,NilClass]
        # @see https://dry-rb.org/gems/dry-schema/
        #
        # @api public
        def schema(*external_schemas, &)
          define(:schema, external_schemas, &)
        end

        # Define a rule for your contract
        #
        # @example using a symbol
        #   rule(:age) do
        #     failure('must be at least 18') if values[:age] < 18
        #   end
        #
        # @example using a path to a value and a custom predicate
        #   rule('address.street') do
        #     failure('please provide a valid street address') if valid_street?(values[:street])
        #   end
        #
        # @return [Rule]
        #
        # @api public
        def rule(*keys, &block)
          ensure_valid_keys(*keys) if __schema__

          Rule.new(keys: keys, block: block).tap do |rule|
            rules << rule
          end
        end

        # Apply another contract to a nested value or to each element of an
        # array value
        #
        # The nested contract's schema and rules are applied to the value
        # found under the given key. Its output replaces the value in the
        # result and its errors are imported with the key path (and the
        # element index for arrays) prepended to their paths
        #
        # The nested contract is not applied when the parent schema rejected
        # the value or when there's no value under the key
        #
        # @example nested hash
        #   class OrderContract < Dry::Validation::Contract
        #     params do
        #       required(:address).filled(:hash)
        #     end
        #
        #     contract :address, AddressContract
        #   end
        #
        # @example array of hashes
        #   contract :line_items, LineItemContract, each: true
        #
        # @example passing parent context values to the nested contract
        #   contract :address, AddressContract, context: %i[account_id]
        #
        # @example passing parent context values under different names
        #   contract :address, AddressContract, context: {account_id: :current_account_id}
        #
        # @param [Symbol, String, Hash] key Path to the nested value
        # @param [Class, Contract] contract Contract class or instance to apply
        # @param [Boolean] each Apply the contract to each element of an array
        # @param [Array<Symbol>, Hash] context Context keys to pass down to the
        #   nested contract, either as a list of keys or as a mapping of nested
        #   context keys to parent context keys
        #
        # @return [Array<NestedContract>]
        #
        # @api public
        def contract(key, contract, each: false, context: EMPTY_HASH)
          ensure_valid_keys(key, source: :contract) if __schema__

          nested = contract.is_a?(Class) ? contract.new : contract

          unless nested.is_a?(Contract)
            raise ::ArgumentError, "+contract+ must be a #{Contract} class or instance"
          end

          context_keys =
            case context
            when ::Array then context.to_h { |name| [name, name] }
            when ::Hash then context
            else
              raise ::ArgumentError, "+context+ must be an Array or a Hash"
            end

          path = Schema::Path[key]
          paths = path.multi_value? ? path.expand.map(&:to_a) : [path.to_a]

          paths.map { |nested_path|
            NestedContract.new(
              path: nested_path,
              contract: nested,
              each: each,
              context_keys: context_keys
            ).tap { |nested_contract| nested_contracts << nested_contract }
          }
        end

        # A shortcut that can be used to define contracts that won't be reused or inherited
        #
        # @example
        #   my_contract = Dry::Validation::Contract.build do
        #     params do
        #       required(:name).filled(:string)
        #     end
        #   end
        #
        #   my_contract.call(name: "Jane")
        #
        # @return [Contract]
        #
        # @api public
        def build(options = EMPTY_HASH, &)
          Class.new(self, &).new(**options)
        end

        # @api private
        def __schema__
          @__schema__ if defined?(@__schema__)
        end

        # Return rules defined in this class
        #
        # @return [Array<Rule>]
        #
        # @api private
        def rules
          @rules ||= EMPTY_ARRAY
            .dup
            .concat(superclass.respond_to?(:rules) ? superclass.rules : EMPTY_ARRAY)
        end

        # Return nested contracts defined in this class
        #
        # @return [Array<NestedContract>]
        #
        # @api private
        def nested_contracts
          @nested_contracts ||= EMPTY_ARRAY
            .dup
            .concat(
              superclass.respond_to?(:nested_contracts) ? superclass.nested_contracts : EMPTY_ARRAY
            )
        end

        # Return messages configured for this class
        #
        # @return [Dry::Schema::Messages]
        #
        # @api private
        def messages
          @messages ||= Schema::Messages.setup(config.messages)
        end

        private

        # @api private
        def ensure_valid_keys(*keys, source: :rule)
          valid_paths = key_map.to_dot_notation
          key_paths = key_paths(keys)

          invalid_keys = key_paths.filter_map { |(key, path)|
            if valid_paths.none? { |vp|
                 vp == path || vp.start_with?("#{path}.", "#{path}[]")
               }
              key
            end
          }.uniq

          return if invalid_keys.empty?

          raise InvalidKeysError, <<~STR.strip
            #{name}.#{source} specifies keys that are not defined by the schema: #{invalid_keys.inspect}
          STR
        end

        # @api private
        def key_paths(keys)
          keys.map { |key|
            case key
            when Hash
              path = Schema::Path[key]
              if path.multi_value?
                *head, tail = Array(path)
                [key].product(
                  tail.map { |el| [*head, *el] }.map { |parts| parts.join(DOT) }
                )
              else
                [[key, path.to_a.join(DOT)]]
              end
            when Array
              [[key, Schema::Path[key].to_a.join(DOT)]]
            else
              [[key, key.to_s]]
            end
          }.flatten(1)
        end

        # @api private
        def key_map
          __schema__.key_map
        end

        # @api private
        def core_schema_opts
          {parent: superclass&.__schema__, config: config}
        end

        # @api private
        def define(method_name, external_schemas, &block)
          return __schema__ if external_schemas.empty? && block.nil?

          unless __schema__.nil?
            raise ::Dry::Validation::DuplicateSchemaError, "Schema has already been defined"
          end

          schema_opts = core_schema_opts

          schema_opts.update(parent: external_schemas) if external_schemas.any?

          case method_name
          when :schema
            @__schema__ = Schema.define(**schema_opts, &block)
          when :Params
            @__schema__ = Schema.Params(**schema_opts, &block)
          when :JSON
            @__schema__ = Schema.JSON(**schema_opts, &block)
          end
        end
      end
    end
  end
end
