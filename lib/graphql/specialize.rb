# frozen_string_literal: true

module GraphQL
  # Specialize a GraphQL operation for repeated execution (for example, in a
  # batch job) by binding constant variable values directly into the document.
  #
  # Specializing an operation:
  #
  # - Validates each bound value against its variable's type (unbound variables
  #   are left alone and remain runtime parameters);
  # - Replaces bound variable usages with equivalent literals;
  # - Evaluates @skip / @include directives whose outcome is determined by
  #   bound values, removing branches that can never run (custom directives are
  #   never executed or removed -- they're kept as-is);
  # - Removes variable definitions and fragment definitions that are no longer
  #   used.
  #
  # The operation's remaining selections are never reordered, so mutation
  # top-level fields keep their original order.
  #
  # @example Specialize an operation with a constant flag
  #   result = GraphQL::Specialize.call(MySchema, query_string, variables: { "verbose" => false })
  #   if result.success?
  #     MySchema.execute(result.query_string, variables: remaining_variables)
  #   else
  #     raise result.errors.join(", ")
  #   end
  module Specialize
    # The outcome of GraphQL::Specialize.call.
    class Result
      def initialize(document:, errors:, variables:)
        @document = document
        @errors = errors
        @variables = variables
      end

      # @return [GraphQL::Language::Nodes::Document, nil] the specialized document, if successful
      attr_reader :document

      # @return [Array<String>] problems that prevented specialization
      attr_reader :errors

      # @return [Array<String>] names of variables still required at runtime
      attr_reader :variables

      # @return [Boolean] true if a valid specialized document was produced
      def success?
        @errors.empty?
      end

      # @return [String, nil] the specialized operation as a query string
      def query_string
        @document&.to_query_string
      end
    end

    class << self
      # Bind constant +variables+ into the given operation, returning a Result.
      #
      # @param schema [Class<GraphQL::Schema>] the schema this operation runs against
      # @param query [String, GraphQL::Language::Nodes::Document, GraphQL::Query] the operation(s) to specialize
      # @param operation_name [String, nil] which operation to specialize, if the document has several
      # @param variables [Hash] constant values to bind, keyed by variable name (String or Symbol)
      # @return [GraphQL::Specialize::Result]
      def call(schema, query, operation_name: nil, variables: {})
        document = case query
        when String
          begin
            GraphQL.parse(query)
          rescue GraphQL::ParseError => err
            return failure([err.message])
          end
        when GraphQL::Language::Nodes::Document
          query
        when GraphQL::Query
          operation_name ||= query.operation_name
          query.document
        else
          raise ArgumentError, "expected query to be a String, GraphQL::Language::Nodes::Document, or GraphQL::Query, got #{query.class}"
        end

        operations = document.definitions.select { |defn| defn.is_a?(GraphQL::Language::Nodes::OperationDefinition) }
        operation = if operation_name
          operations.find { |op| op.name == operation_name }
        elsif operations.size == 1
          operations.first
        else
          return failure(["Can't specialize a document with #{operations.size} operations; provide an operation name to select one."])
        end

        if operation.nil?
          return failure(["Couldn't find an operation named \"#{operation_name}\" in the document."])
        end

        bindings = {}
        variables.each { |key, value| bindings[key.to_s] = value }

        bound_values = {}
        bound_types = {}
        errors = []

        operation.variables.each do |var_def|
          var_name = var_def.name
          next if !bindings.key?(var_name)

          var_type = schema.type_from_ast(var_def.type)
          if var_type.nil?
            errors << "Can't specialize $#{var_name}: its type (#{var_def.type.to_query_string}) isn't defined in the schema."
            next
          end

          value = bindings[var_name]
          validation = var_type.validate_input(value, GraphQL::Query::NullContext.instance)
          if validation.valid?
            bound_values[var_name] = value
            bound_types[var_name] = var_type
          else
            problems = validation.problems ? validation.problems.map { |p| p["explanation"] }.join(", ") : "invalid input"
            errors << "Can't bind $#{var_name} (#{var_type.to_type_signature}): #{problems}."
          end
        end

        return failure(errors) if errors.any?

        fragment_definitions = {}
        document.definitions.each do |defn|
          if defn.is_a?(GraphQL::Language::Nodes::FragmentDefinition)
            fragment_definitions[defn.name] = defn
          end
        end

        rewriter = Rewriter.new(bound_values, bound_types, fragment_definitions)
        new_operation = rewriter.rewrite_operation(operation)
        if rewriter.invalid_reason
          return failure([rewriter.invalid_reason])
        end

        used_variables = rewriter.used_variables(new_operation)
        new_variables = new_operation.variables.select { |var_def| used_variables.include?(var_def.name) }
        new_operation = new_operation.merge(variables: new_variables)

        new_document = GraphQL::Language::Nodes::Document.new(
          definitions: [new_operation, *rewriter.used_fragment_definitions],
        )

        validation_errors = schema.validate(new_document)
        if validation_errors.any?
          messages = validation_errors.map { |err| "Specialized document is invalid: #{err.message}" }
          return failure(messages)
        end

        Result.new(
          document: new_document,
          errors: [],
          variables: new_variables.map(&:name),
        )
      end

      private

      def failure(errors)
        Result.new(document: nil, errors: errors, variables: [])
      end
    end

    # @api private
    class Rewriter
      def initialize(bound_values, bound_types, fragment_definitions)
        @bound_values = bound_values
        @bound_types = bound_types
        @fragment_definitions = fragment_definitions
        @rewritten_fragments = {}
        @fragment_queue = []
        @invalid_reason = nil
      end

      # @return [String, nil] why the document couldn't be specialized, if it couldn't
      attr_reader :invalid_reason

      def rewrite_operation(operation)
        selections = rewrite_selections(operation.selections)
        if selections.empty?
          op_description = operation.name ? "operation \"#{operation.name}\"" : "the anonymous operation"
          @invalid_reason ||= "Specializing #{op_description} left it with no selections, which isn't a valid document."
          return operation
        end
        variables = operation.variables.reject { |var_def| @bound_values.key?(var_def.name) }
        directives = rewrite_directives(operation.directives)
        directives = [] if directives == :drop
        operation.merge(selections: selections, variables: variables, directives: directives)
      end

      # Fragment definitions that are still referenced, in the order they were reached.
      # @return [Array<GraphQL::Language::Nodes::FragmentDefinition>]
      def used_fragment_definitions
        @fragment_queue.each_with_object([]) do |name, defs|
          defn = @rewritten_fragments[name]
          defs << defn if defn
        end
      end

      # Names of variables used anywhere in the rewritten operation and its fragments.
      # @return [Array<String>]
      def used_variables(operation)
        names = []
        each_variable_identifier([operation, *used_fragment_definitions]) do |identifier|
          names << identifier.name
        end
        names.uniq
      end

      private

      def rewrite_selections(selections)
        rewritten = []
        selections.each do |selection|
          node = rewrite_selection(selection)
          rewritten << node if node
        end
        rewritten
      end

      # @return [GraphQL::Language::Nodes::AbstractNode, nil] the rewritten node, or nil to remove it
      def rewrite_selection(selection)
        directives = rewrite_directives(selection.directives)
        return nil if directives == :drop

        case selection
        when GraphQL::Language::Nodes::Field
          selections = rewrite_selections(selection.selections)
          if selections.empty? && !selection.selections.empty?
            @invalid_reason ||= "Specializing field \"#{selection.name}\" left it with an empty selection set, which isn't a valid document."
          end
          selection.merge(
            arguments: rewrite_arguments(selection.arguments),
            directives: directives,
            selections: selections,
          )
        when GraphQL::Language::Nodes::InlineFragment
          selections = rewrite_selections(selection.selections)
          if selections.empty? && !selection.selections.empty?
            if directives.empty?
              # An empty inline fragment with no directives selects nothing; drop it.
              return nil
            else
              @invalid_reason ||= "Specializing an inline fragment left it with an empty selection set, which isn't a valid document."
            end
          end
          selection.merge(directives: directives, selections: selections)
        when GraphQL::Language::Nodes::FragmentSpread
          enqueue_fragment(selection.name)
          selection.merge(directives: directives)
        else
          selection
        end
      end

      def enqueue_fragment(name)
        return if @rewritten_fragments.key?(name)

        definition = @fragment_definitions[name]
        if definition.nil?
          @invalid_reason ||= "The document spreads fragment \"#{name}\", but that fragment isn't defined."
          return
        end

        @fragment_queue << name
        @rewritten_fragments[name] = nil # placeholder to break cycles
        directives = rewrite_directives(definition.directives)
        if directives == :drop
          @invalid_reason ||= "Specializing fragment \"#{name}\" removed it entirely, but it's still spread in the document."
          return
        end
        selections = rewrite_selections(definition.selections)
        if selections.empty?
          @invalid_reason ||= "Specializing fragment \"#{name}\" left it with an empty selection set, which isn't a valid document."
          return
        end
        @rewritten_fragments[name] = definition.merge(directives: directives, selections: selections)
      end

      # @return [Array, :drop] rewritten directives, or :drop if a directive removes this node
      def rewrite_directives(directives)
        kept = []
        directives.each do |directive|
          if directive.name == "skip" || directive.name == "include"
            if_argument = directive.arguments.find { |arg| arg.name == "if" }
            known = static_boolean(if_argument && if_argument.value)
            if !known.nil?
              keep_node = directive.name == "skip" ? !known : known
              return :drop if !keep_node
              next # always-applied directive; remove it
            end
          end
          kept << directive.merge(arguments: rewrite_arguments(directive.arguments))
        end
        kept
      end

      # @return [Boolean, nil] the known value, or nil if it can't be determined
      def static_boolean(value)
        case value
        when true, false
          value
        when GraphQL::Language::Nodes::VariableIdentifier
          if @bound_values.key?(value.name)
            bound = @bound_values[value.name]
            if bound == true || bound == false
              bound
            else
              @invalid_reason ||= "Can't determine @skip/@include: bound value for $#{value.name} isn't a boolean."
              nil
            end
          end
        end
      end

      def rewrite_arguments(arguments)
        arguments.map do |argument|
          argument.merge(value: rewrite_value(argument.value))
        end
      end

      def rewrite_value(value)
        case value
        when GraphQL::Language::Nodes::VariableIdentifier
          if @bound_values.key?(value.name)
            literal_for(@bound_types[value.name], @bound_values[value.name])
          else
            value
          end
        when GraphQL::Language::Nodes::InputObject
          value.merge(arguments: rewrite_arguments(value.arguments))
        when Array
          value.map { |item| rewrite_value(item) }
        else
          value
        end
      end

      # Build a GraphQL literal for +value+, using +type+ (the variable's
      # declared type) to render enums and input objects correctly.
      def literal_for(type, value)
        if type.is_a?(GraphQL::Schema::NonNull)
          return literal_for(type.of_type, value)
        end

        case value
        when nil
          GraphQL::Language::Nodes::NullValue.new(name: "null")
        when Array
          inner_type = type.respond_to?(:of_type) ? type.of_type : nil
          value.map { |item| literal_for(inner_type, item) }
        when Hash
          arguments = value.map do |key, item|
            item_type = input_object_argument_type(type, key)
            GraphQL::Language::Nodes::Argument.new(name: key.to_s, value: literal_for(item_type, item))
          end
          GraphQL::Language::Nodes::InputObject.new(arguments: arguments)
        when String, Symbol
          if enum_type?(type)
            GraphQL::Language::Nodes::Enum.new(name: value.to_s)
          else
            value.to_s
          end
        when true, false, Integer, Float
          value
        else
          @invalid_reason ||= "Can't write bound value #{value.inspect} as a GraphQL literal."
          nil
        end
      end

      def enum_type?(type)
        type.is_a?(Class) && type < GraphQL::Schema::Enum
      end

      def input_object_argument_type(type, key)
        return nil if !(type.is_a?(Class) && type.respond_to?(:arguments))

        key = key.to_s
        argument = type.arguments[key]
        argument ||= type.arguments.values.find { |arg| arg.keyword.to_s == key }
        argument&.type
      end

      def each_variable_identifier(node, &block)
        case node
        when GraphQL::Language::Nodes::VariableIdentifier
          yield node
        when GraphQL::Language::Nodes::Argument
          each_variable_identifier(node.value, &block)
        when GraphQL::Language::Nodes::Directive
          each_variable_identifier(node.arguments, &block)
        when GraphQL::Language::Nodes::InputObject
          each_variable_identifier(node.arguments, &block)
        when GraphQL::Language::Nodes::Field
          each_variable_identifier(node.arguments, &block)
          each_variable_identifier(node.directives, &block)
          each_variable_identifier(node.selections, &block)
        when GraphQL::Language::Nodes::InlineFragment
          each_variable_identifier(node.directives, &block)
          each_variable_identifier(node.selections, &block)
        when GraphQL::Language::Nodes::FragmentSpread
          each_variable_identifier(node.directives, &block)
        when GraphQL::Language::Nodes::FragmentDefinition, GraphQL::Language::Nodes::OperationDefinition
          each_variable_identifier(node.directives, &block)
          each_variable_identifier(node.selections, &block)
        when Array
          node.each { |item| each_variable_identifier(item, &block) }
        end
      end
    end
  end
end
