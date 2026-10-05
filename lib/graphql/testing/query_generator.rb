# frozen_string_literal: true

module GraphQL
  module Testing
    # Generates valid GraphQL operations and matching variable values from a
    # schema, for use in test harnesses and fuzzing tools.
    #
    # @example Generate a query and variables for a schema
    #   generator = GraphQL::Testing::QueryGenerator.new(MySchema, seed: 42, max_depth: 3)
    #   result = generator.generate
    #   result.query     # => "query ($v0: Int!) { ... }"
    #   result.variables # => { "v0" => 7 }
    #
    # The generator only produces selections and input values that are valid
    # for the schema:
    #
    # - Non-null input cycles that can never be satisfied (for example,
    #   `input A { b: B! }` where `B` requires `A!`) are detected up front and
    #   never appear in generated operations. Fields whose required arguments
    #   can't be constructed are skipped instead of being padded with `null`.
    # - Union and interface fields are selected with inline fragments on
    #   possible types.
    # - Enum values are drawn from the schema definition and arguments with
    #   default values may be omitted so the schema default applies.
    # - Samples for custom scalars are supplied by the caller via
    #   `scalar_samples:`; fields that require an un-sampleable scalar are
    #   skipped.
    class QueryGenerator
      # A generated operation and the variable values that satisfy it.
      class Result
        # @return [String] a GraphQL operation string
        attr_reader :query

        # @return [Hash] variable values keyed by variable name, ready to pass to `Schema.execute`
        attr_reader :variables

        def initialize(query:, variables:)
          @query = query
          @variables = variables
        end
      end

      BUILTIN_SCALAR_SAMPLES = {
        "String" => ->(random) { "string-#{random.rand(10_000)}" },
        "Int" => ->(random) { random.rand(10_000) },
        "Float" => ->(random) { (random.rand * 10_000).round(2) },
        "Boolean" => ->(random) { random.rand < 0.5 },
        "ID" => ->(random) { random.rand(10_000).to_s },
      }

      # @param schema [Class<GraphQL::Schema>] the schema to generate operations for
      # @param seed [Integer] seed for the internal random generator; reuse a seed to reproduce a result
      # @param max_depth [Integer] maximum nesting of selection sets below the root
      # @param max_list_length [Integer] maximum number of items in generated list values
      # @param scalar_samples [Hash{String => Object, #call}] sample values for custom scalars,
      #   keyed by GraphQL name. A callable is invoked with the generator's `Random` instance.
      def initialize(schema, seed: Random.new_seed, max_depth: 3, max_list_length: 2, scalar_samples: {})
        @schema = schema
        @random = Random.new(seed)
        @max_depth = max_depth
        @max_list_length = max_list_length
        @scalar_samples = scalar_samples
        @constructible_input_types = {}
      end

      # @param operation_type [Symbol] `:query` or `:mutation`
      # @return [Result] a valid operation and matching variables
      def generate(operation_type: :query)
        root_type = @schema.public_send(operation_type)
        if root_type.nil?
          raise ArgumentError, "#{@schema} has no #{operation_type} root type to generate operations for"
        end

        @variables = {}
        @variable_definitions = []
        @variable_counter = 0

        selections = selections_for(root_type, @max_depth).join(" ")
        definitions = @variable_definitions.empty? ? "" : "(#{@variable_definitions.join(", ")})"
        Result.new(query: "#{operation_type} #{definitions} { #{selections} }", variables: @variables)
      end

      private

      # True when a non-null value of `type` can actually be constructed.
      # Nullable positions can always be omitted, so this is only consulted
      # for required arguments and for optional ones we choose to provide.
      def constructible_input_type?(type, visiting = [])
        if type.non_null? || type.list?
          constructible_input_type?(type.of_type, visiting)
        elsif type.kind.input_object?
          type_name = type.graphql_name
          # A required cycle back to a type already on the stack can never terminate:
          return false if visiting.include?(type_name)
          if visiting.empty? && @constructible_input_types.key?(type_name)
            return @constructible_input_types[type_name]
          end
          result = type.all_argument_definitions.all? do |arg_defn|
            !required_argument?(arg_defn) || constructible_input_type?(arg_defn.type, visiting + [type_name])
          end
          @constructible_input_types[type_name] = result if visiting.empty?
          result
        elsif type.kind.enum?
          true
        else # scalar
          BUILTIN_SCALAR_SAMPLES.key?(type.graphql_name) || @scalar_samples.key?(type.graphql_name)
        end
      end

      def required_argument?(arg_defn)
        arg_defn.type.non_null? && !arg_defn.default_value?
      end

      def usable_field?(field_defn, depth)
        if field_defn.all_argument_definitions.any? { |arg_defn| required_argument?(arg_defn) && !constructible_input_type?(arg_defn.type) }
          return false
        end

        return_type = field_defn.type.unwrap
        if return_type.kind.composite?
          # Abstract types also need a selection set for their inline fragments,
          # so they cost one extra level of depth.
          selectable_type?(return_type) && (return_type.kind.abstract? ? depth > 1 : depth > 0)
        else
          true
        end
      end

      def selectable_type?(type)
        if type.kind.abstract?
          !@schema.possible_types(type).empty?
        else
          true
        end
      end

      def selections_for(object_type, depth)
        usable_fields = object_type.fields.values.select { |field_defn| usable_field?(field_defn, depth) }
        return ["__typename"] if usable_fields.empty?

        count = @random.rand(1..usable_fields.size)
        usable_fields.shuffle(random: @random).first(count).map { |field_defn| field_selection(field_defn, depth) }
      end

      def field_selection(field_defn, depth)
        name = field_defn.graphql_name
        arguments = arguments_string(field_defn)
        return_type = field_defn.type.unwrap
        if return_type.kind.composite?
          "#{name}#{arguments} { #{subselections(return_type, depth - 1)} }"
        else
          "#{name}#{arguments}"
        end
      end

      def subselections(type, depth)
        if type.kind.abstract?
          possible_types = @schema.possible_types(type)
          chosen = possible_types.shuffle(random: @random).first(@random.rand(1..possible_types.size))
          chosen.map { |possible_type|
            "... on #{possible_type.graphql_name} { #{selections_for(possible_type, depth - 1).join(" ")} }"
          }.join(" ")
        else
          selections_for(type, depth).join(" ")
        end
      end

      def arguments_string(field_defn)
        parts = []
        field_defn.all_argument_definitions.each do |arg_defn|
          next unless required_argument?(arg_defn) || (constructible_input_type?(arg_defn.type) && @random.rand < 0.5)

          variable_name = "v#{@variable_counter}"
          @variable_counter += 1
          @variable_definitions << "$#{variable_name}: #{arg_defn.type.to_type_signature}"
          @variables[variable_name] = sample_input_value(arg_defn.type)
          parts << "#{arg_defn.graphql_name}: $#{variable_name}"
        end
        parts.empty? ? "" : "(#{parts.join(", ")})"
      end

      def sample_input_value(type)
        if type.non_null?
          sample_input_value(type.of_type)
        elsif type.list?
          Array.new(@random.rand(@max_list_length + 1)) { sample_input_value(type.of_type) }
        elsif type.kind.input_object?
          type.all_argument_definitions.each_with_object({}) do |arg_defn, value|
            if required_argument?(arg_defn) || (constructible_input_type?(arg_defn.type) && @random.rand < 0.5)
              value[arg_defn.graphql_name] = sample_input_value(arg_defn.type)
            end
          end
        elsif type.kind.enum?
          type.values.values.sample(random: @random).graphql_name
        else
          sample = @scalar_samples.fetch(type.graphql_name) { BUILTIN_SCALAR_SAMPLES[type.graphql_name] }
          if sample.respond_to?(:call)
            sample.arity == 0 ? sample.call : sample.call(@random)
          else
            sample
          end
        end
      end
    end
  end
end
