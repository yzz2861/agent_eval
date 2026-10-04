# frozen_string_literal: true

module GraphQL
  module Execution
    # Builds opt-in diagnostic information for non-null null propagation.
    # This class only inspects type and AST metadata; it never reads resolver values.
    class NullPropagation
      CONTEXT_KEY = :null_propagation_extensions
      EXTENSIONS_KEY = "nullPropagation"

      class << self
        def enabled?(context)
          context.key?(CONTEXT_KEY) && context[CONTEXT_KEY]
        end

        def append(query)
          return unless enabled?(query.context)

          traces = query.context.errors.filter_map do |error|
            origin_error = error.respond_to?(:null_propagation_origin) ? error.null_propagation_origin : nil
            build_trace(error, origin_error, query) if origin_error
          end

          return if traces.empty?

          extensions = query.context.response_extensions
          diagnostic = extensions[EXTENSIONS_KEY]
          if diagnostic.is_a?(Hash) && diagnostic["traces"].is_a?(Array)
            diagnostic["traces"].concat(traces)
          else
            extensions[EXTENSIONS_KEY] = { "traces" => traces }
          end
          nil
        end

        private

        def build_trace(error, origin_error, query)
          path = error.path || origin_error.path || query.path
          origin = trace_origin(path, origin_error, query)
          wrappers = origin.delete("wrappers")
          stop_path = origin.delete("stopPath")
          {
            "origin" => origin,
            "wrappers" => wrappers,
            "stopPath" => stop_path,
          }
        end

        def trace_origin(path, origin_error, query)
          relative_path = relative_path(path, query)
          current_type = query.root_type
          current_type = current_type.of_type if current_type.non_null?
          selections = query.selected_operation.selections
          wrappers = []
          stop_path = []
          path_offset = path.length - relative_path.length
          origin_kind = origin_error.is_from_array ? "LIST_ELEMENT" : "FIELD"
          origin_type = origin_error.field.type.to_type_signature

          relative_path.each_with_index do |path_key, index|
            result_path = path[0..(path_offset + index)]
            if path_key.is_a?(Integer)
              raise GraphQL::Error, "Expected a list type at #{result_path.inspect}" unless current_type.list?

              inner_type = current_type.of_type
              if inner_type.non_null?
                inner_type = inner_type.of_type
                type = current_type.of_type
                add_wrapper(wrappers, result_path, "LIST_ELEMENT", type)
                origin_kind = "LIST_ELEMENT"
                origin_type = type.to_type_signature
              else
                stop_path = result_path
              end
              current_type = inner_type
            else
              field_node, field_owner_type = find_field_node(selections, path_key, current_type, query)
              field_definition = query.types.field(field_owner_type, field_node.name)
              return_type = field_definition.type
              if return_type.non_null?
                inner_type = return_type.of_type
                kind = inner_type.list? ? "LIST" : "FIELD"
                add_wrapper(wrappers, result_path, kind, return_type)
                origin_kind = kind
                origin_type = return_type.to_type_signature
                current_type = inner_type
              else
                stop_path = result_path
                current_type = return_type
              end

              selections = field_node.selections
              current_type = current_type.unwrap unless current_type.list?
            end
          end

          {
            "path" => path.dup,
            "parentType" => origin_error.parent_type.graphql_name,
            "fieldName" => origin_error.field.graphql_name,
            "kind" => origin_kind,
            "type" => origin_type,
            "wrappers" => wrappers,
            "stopPath" => stop_path,
          }
        end

        def relative_path(path, query)
          base_path = query.path
          if !base_path.empty? && path[0, base_path.length] == base_path
            path[base_path.length..]
          else
            path
          end
        end

        def add_wrapper(wrappers, path, kind, type)
          wrappers << { "path" => path.dup, "kind" => kind, "type" => type.to_type_signature }
        end

        def find_field_node(selections, response_key, parent_type, query, visited = Set.new)
          selections.each do |selection|
            case selection
            when GraphQL::Language::Nodes::Field
              return [selection, parent_type] if (selection.alias || selection.name) == response_key
            when GraphQL::Language::Nodes::InlineFragment
              next unless type_condition_applies?(selection.type, parent_type, query)
              fragment_parent_type = selection.type ? query.types.type(selection.type.name) : parent_type
              fragment_parent_type = parent_type if fragment_parent_type.kind.abstract?
              found = find_field_node(selection.selections, response_key, fragment_parent_type, query, visited)
              return found if found
            when GraphQL::Language::Nodes::FragmentSpread
              next if visited.include?(selection.name)
              fragment = query.fragments[selection.name]
              next unless fragment && type_condition_applies?(fragment.type, parent_type, query)
              fragment_parent_type = query.types.type(fragment.type.name)
              fragment_parent_type = parent_type if fragment_parent_type.kind.abstract?

              next_visited = visited.dup
              next_visited << selection.name
              found = find_field_node(fragment.selections, response_key, fragment_parent_type, query, next_visited)
              return found if found
            end
          end
          nil
        end

        def type_condition_applies?(type_node, parent_type, query)
          return true if type_node.nil?

          condition_type = query.types.type(type_node.name)
          if condition_type.kind.object?
            condition_type == parent_type ||
              (!parent_type.kind.object? && query.types.possible_types(parent_type).include?(condition_type))
          elsif parent_type.kind.object?
            query.types.possible_types(condition_type).include?(parent_type)
          else
            query.types.possible_types(condition_type).intersect?(query.types.possible_types(parent_type))
          end
        end
      end
    end
  end
end
