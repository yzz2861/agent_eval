# frozen_string_literal: true

module GraphQL
  # Specializes a GraphQL operation for a recurring batch job by binding
  # constant variable values ahead of time.
  #
  # Given a query and a set of variable bindings, it produces a new query
  # string where:
  #
  # - Bound variable values are checked against their declared types first;
  #   invalid bindings are rejected with a clear error.
  # - Bound variables are inlined as literals and removed from the operation's
  #   variable definitions. Unbound variables remain runtime parameters.
  # - @skip / @include directives whose `if:` value is decided by a binding
  #   (or a literal) are resolved: impossible selections are removed and
  #   always-applied directives are dropped. Custom directives are never
  #   evaluated -- they are left untouched.
  # - Variable definitions and fragment definitions that are no longer used
  #   are removed. Selection order is never changed (in particular, mutation
  #   top-level fields keep their original order).
  #
  # If pruning would produce an invalid document, the result reports errors
  # instead of returning a broken query string.
  #
  # @example
  #   result = GraphQL::Specialization.specialize(MySchema, query_string, variables: { "flag" => true })
  #   if result.ok?
  #     MySchema.execute(result.query_string, variables: remaining_variables)
  #   else
  #     warn result.errors
  #   end
  module Specialization
    # The outcome of a specialization attempt.
    class Result
      # @return [String, nil] the specialized query string, or nil when specialization failed
      attr_reader :query_string

      # @return [Array<String>] human-readable reasons specialization failed
      attr_reader :errors

      def initialize(query_string:, errors:)
        @query_string = query_string
        @errors = errors
      end

      # @return [Boolean] true when a usable specialized query string was produced
      def ok?
        @errors.empty?
      end
    end

    SKIP_INCLUDE = ["skip", "include"].freeze

    module_function

    # @param schema [Class<GraphQL::Schema>] the schema the query runs against
    # @param query_string [String] a GraphQL query document
    # @param variables [Hash{String, Symbol => Object}] constant values to bind, keyed by variable name
    # @param operation_name [String, nil] which operation to specialize (required when the document has several)
    # @return [Result]
    def specialize(schema, query_string, variables: {}, operation_name: nil)
      bindings = variables.each_with_object({}) { |(k, v), h| h[k.to_s] = v }

      document = GraphQL.parse(query_string)

      operations = document.definitions.select { |d| d.is_a?(GraphQL::Language::Nodes::OperationDefinition) }
      fragments = document.definitions.select { |d| d.is_a?(GraphQL::Language::Nodes::FragmentDefinition) }
      other_definitions = document.definitions - operations - fragments

      operation = if operation_name
        operations.find { |op| op.name == operation_name }
      elsif operations.length == 1
        operations.first
      elsif operations.empty?
        nil
      else
        :ambiguous
      end

      if operation.nil?
        return failure("Couldn't find an operation to specialize#{operation_name ? " named #{operation_name.inspect}" : ""} in the document")
      elsif operation == :ambiguous
        return failure("The document contains several operations; pass operation_name: to choose one to specialize")
      end

      original_errors = schema.validate(document)
      if original_errors.any?
        return failure(original_errors.map { |e| "The original query is invalid: #{e.message}" })
      end

      variable_types = {}
      operation.variables.each do |var_def|
        type = schema.type_from_ast(var_def.type)
        if type.nil?
          return failure("Couldn't find a type for variable $#{var_def.name} in the schema")
        end
        variable_types[var_def.name] = type
      end

      literals = {}
      bindings.each do |name, value|
        type = variable_types[name]
        if type.nil?
          return failure("Can't bind $#{name}: no such variable is defined by operation #{operation_label(operation)}")
        elsif value.nil? && type.non_null?
          return failure("Can't bind $#{name}: nil isn't valid for non-null type #{type.to_type_signature}")
        end
        unwrapped_type = type
        unwrapped_type = unwrapped_type.of_type while unwrapped_type.non_null?
        if !value.nil? && unwrapped_type.kind.enum?
          # Accept enum values given by name or by application value
          value = enum_literal_name(value, unwrapped_type)
        end
        if !type.valid_isolated_input?(value)
          return failure("Can't bind $#{name}: #{value.inspect} isn't valid for type #{type.to_type_signature}")
        end
        literals[name] = value_to_ast(value, type)
      end

      fragments_by_name = fragments.to_h { |f| [f.name, f] }
      other_operations = operations - [operation]
      target_fragment_names = reachable_fragment_names(operation, fragments_by_name)
      other_fragment_names = other_operations.reduce(Set.new) do |acc, op|
        acc.merge(reachable_fragment_names(op, fragments_by_name))
      end
      # Fragments shared with other operations keep their original text so
      # those operations still see their own variables.
      rewritable_names = target_fragment_names - other_fragment_names

      rewritten_fragments = fragments.map do |fragment|
        rewritable_names.include?(fragment.name) ? rewrite_fragment(fragment, bindings, literals) : fragment
      end
      rewritten_fragments_by_name = rewritten_fragments.to_h { |f| [f.name, f] }

      new_operation = rewrite_operation(operation, bindings, literals)

      # Fragments and variables may have become unreachable through pruning;
      # measure from the rewritten operation.
      new_target_fragment_names = reachable_fragment_names(new_operation, rewritten_fragments_by_name)

      used_variable_names = collect_variables(new_operation, Set.new)
      collect_variables_from_fragments(new_target_fragment_names, rewritten_fragments_by_name, used_variable_names)
      new_operation = new_operation.merge(
        variables: new_operation.variables.select { |var_def| used_variable_names.include?(var_def.name) }
      )

      kept_fragment_names = new_target_fragment_names | other_fragment_names
      kept_fragments = rewritten_fragments.select { |f| kept_fragment_names.include?(f.name) }

      new_definitions = other_definitions + other_operations + [new_operation] + kept_fragments

      if new_operation.selections.empty?
        return failure("Specialization removed every selection from operation #{operation_label(operation)}; the result wouldn't be a valid document")
      end
      empty_fragment = kept_fragments.find { |f| f.selections.empty? }
      if empty_fragment
        return failure("Specialization removed every selection from fragment #{empty_fragment.name.inspect}; the result wouldn't be a valid document")
      end

      new_document = document.merge(definitions: new_definitions)
      validation_errors = schema.validate(new_document)
      if validation_errors.any?
        messages = validation_errors.map { |e| "The specialized query is invalid: #{e.message}" }
        return failure(messages)
      end

      Result.new(query_string: new_document.to_query_string, errors: [])
    rescue GraphQL::ParseError => err
      failure("Couldn't parse the query: #{err.message}")
    rescue GraphQL::CoercionError, JSON::GeneratorError => err
      failure("Couldn't bind variables: #{err.message}")
    end

    alias_method :call, :specialize

    def failure(messages)
      Result.new(query_string: nil, errors: Array(messages))
    end

    def operation_label(operation)
      operation.name ? operation.name.inspect : "(anonymous)"
    end

    # Rewrite one operation: resolve decided skip/include directives,
    # inline bound variables, and prune its selections.
    def rewrite_operation(operation, bindings, literals)
      operation.merge(
        directives: rewrite_directives(operation.directives, bindings, literals),
        selections: rewrite_selections(operation.selections, bindings, literals),
      )
    end

    def rewrite_fragment(fragment, bindings, literals)
      fragment.merge(
        directives: rewrite_directives(fragment.directives, bindings, literals),
        selections: rewrite_selections(fragment.selections, bindings, literals),
      )
    end

    def rewrite_selections(selections, bindings, literals)
      selections.each_with_object([]) do |selection, kept|
        next if selection_dropped?(selection.directives, bindings)

        new_directives = rewrite_directives(selection.directives, bindings, literals)
        case selection
        when GraphQL::Language::Nodes::Field
          kept << selection.merge(
            arguments: selection.arguments.map { |arg| arg.merge(value: rewrite_value(arg.value, literals)) },
            directives: new_directives,
            selections: rewrite_selections(selection.selections, bindings, literals),
          )
        when GraphQL::Language::Nodes::InlineFragment
          kept << selection.merge(
            directives: new_directives,
            selections: rewrite_selections(selection.selections, bindings, literals),
          )
        when GraphQL::Language::Nodes::FragmentSpread
          kept << selection.merge(directives: new_directives)
        else
          kept << selection
        end
      end
    end

    # Drop skip/include directives whose outcome is decided; keep everything
    # else (including custom directives), inlining bound variables in their
    # arguments without ever evaluating them.
    def rewrite_directives(directives, bindings, literals)
      directives.each_with_object([]) do |directive, kept|
        decided = decided_directive_value(directive, bindings)
        if decided.nil?
          kept << directive.merge(
            arguments: directive.arguments.map { |arg| arg.merge(value: rewrite_value(arg.value, literals)) }
          )
        end
      end
    end

    # @return [Boolean, nil] true/false when the directive's if: is known, nil otherwise
    def decided_directive_value(directive, bindings)
      return nil unless SKIP_INCLUDE.include?(directive.name)

      if_argument = directive.arguments.find { |arg| arg.name == "if" }
      return nil if if_argument.nil?

      static_boolean(if_argument.value, bindings)
    end

    def selection_dropped?(directives, bindings)
      directives.any? do |directive|
        decided = decided_directive_value(directive, bindings)
        !decided.nil? && (directive.name == "skip" ? decided : !decided)
      end
    end

    # @return [Boolean, nil]
    def static_boolean(value, bindings)
      case value
      when true, false
        value
      when GraphQL::Language::Nodes::VariableIdentifier
        bound = bindings[value.name]
        bound == true || bound == false ? bound : nil
      end
    end

    # Replace bound variable references with literals, deep inside lists and
    # input objects. Unbound variables are left as runtime parameters.
    def rewrite_value(value, literals)
      case value
      when GraphQL::Language::Nodes::VariableIdentifier
        literals.key?(value.name) ? literals[value.name] : value
      when Array
        value.map { |v| rewrite_value(v, literals) }
      when GraphQL::Language::Nodes::InputObject
        value.merge(arguments: value.arguments.map { |arg| arg.merge(value: rewrite_value(arg.value, literals)) })
      else
        value
      end
    end

    # Convert a Ruby value into something the query printer emits as a
    # GraphQL literal, guided by the variable's declared type.
    def value_to_ast(value, type)
      return value if type.nil?

      type = type.of_type while type.non_null?

      if value.nil?
        nil
      elsif type.kind.input_object?
        hash = value.respond_to?(:to_unsafe_h) ? value.to_unsafe_h : value.to_h
        arguments = hash.map do |key, sub_value|
          argument = type.get_argument(key.to_s) ||
            type.get_argument(GraphQL::Schema::Member::BuildType.camelize(key.to_s))
          literal_key = argument ? argument.graphql_name : key.to_s
          GraphQL::Language::Nodes::Argument.new(
            name: literal_key,
            value: value_to_ast(sub_value, argument ? argument.type : nil),
          )
        end
        GraphQL::Language::Nodes::InputObject.new(arguments: arguments)
      elsif type.kind.list?
        values = value.is_a?(Array) ? value : [value]
        values.map { |v| value_to_ast(v, type.of_type) }
      elsif type.kind.enum?
        GraphQL::Language::Nodes::Enum.new(name: enum_literal_name(value, type))
      else
        value
      end
    end

    def enum_literal_name(value, type)
      name = value.to_s
      enum_values = type.values
      if enum_values.key?(name)
        name
      elsif (enum_value = enum_values.each_value.find { |ev| ev.value == value || ev.value.to_s == name })
        enum_value.graphql_name
      else
        name
      end
    end

    # Names of fragments transitively spread from this operation.
    def reachable_fragment_names(operation, fragments_by_name)
      names = Set.new
      queue = collect_fragment_spreads(operation, [])
      until queue.empty?
        name = queue.shift
        next if names.include?(name)

        names << name
        fragment = fragments_by_name[name]
        queue.concat(collect_fragment_spreads(fragment, [])) if fragment
      end
      names
    end

    def collect_fragment_spreads(node, found)
      case node
      when GraphQL::Language::Nodes::FragmentSpread
        found << node.name
      when GraphQL::Language::Nodes::AbstractNode
        node.children.each { |child| collect_fragment_spreads(child, found) }
      when Array
        node.each { |child| collect_fragment_spreads(child, found) }
      end
      found
    end

    def collect_variables(node, found)
      case node
      when GraphQL::Language::Nodes::VariableIdentifier
        found << node.name
      when GraphQL::Language::Nodes::AbstractNode
        node.children.each { |child| collect_variables(child, found) }
      when Array
        node.each { |child| collect_variables(child, found) }
      end
      found
    end

    def collect_variables_from_fragments(fragment_names, fragments_by_name, found)
      fragment_names.each do |name|
        fragment = fragments_by_name[name]
        collect_variables(fragment, found) if fragment
      end
      found
    end
  end
end
