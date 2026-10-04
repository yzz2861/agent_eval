# frozen_string_literal: true

module GraphQL
  module Execution
    class Interpreter
      # Records why an invalid `nil` propagated through the response.
      #
      # Only response metadata is ever recorded: response paths (using the
      # client-visible field alias, if any), field names, type signatures and
      # boundary kinds. Resolved field values are never collected.
      #
      # Enable per query with `context: { null_propagation_diagnostics: true }`;
      # the diagnostic is returned in the `nullPropagation` extension.
      #
      # @api private
      class NullPropagationTrace
        # Pass this as a query context key to enable the extension.
        CONTEXT_KEY = :null_propagation_diagnostics

        # Key under which the diagnostic is added to the response extensions.
        EXTENSION_KEY = "nullPropagation"

        # The field itself returned an invalid `nil`.
        ORIGIN_FIELD = "FIELD"
        # A list field itself returned an invalid `nil`.
        ORIGIN_LIST = "LIST"
        # An element of a non-null list was `nil`.
        ORIGIN_LIST_ELEMENT = "LIST_ELEMENT"

        # Propagation crossed a non-null field.
        BOUNDARY_FIELD = "FIELD"
        # Propagation crossed a non-null list.
        BOUNDARY_LIST = "LIST"
        # Propagation crossed a non-null list element.
        BOUNDARY_LIST_ELEMENT = "LIST_ELEMENT"

        # Propagation stopped at a nullable response position.
        STOP_NULLABLE = "NULLABLE"
        # Propagation reached the root, so the whole `data` entry became `null`.
        STOP_ROOT = "ROOT"

        def initialize
          @origin = nil
          @wrappers = []
          @stop = nil
        end

        # @param path [Array] client-visible path of the field that first returned an invalid `nil`
        # @param field [String] owner type and field name, e.g. `Expansion.name`
        # @param kind [String] {ORIGIN_FIELD}, {ORIGIN_LIST} or {ORIGIN_LIST_ELEMENT}
        # @param type [String, nil] type signature of the violated non-null position
        def record_origin(path:, field:, kind:, type:)
          @origin = {
            "path" => path,
            "field" => field,
            "kind" => kind,
            "type" => type,
          }
        end

        # Record a non-null wrapper the `nil` crossed while propagating.
        def record_wrapper(path:, kind:, type:)
          @wrappers << {
            "path" => path,
            "kind" => kind,
            "type" => type,
          }
        end

        # Record where propagation finally stopped.
        def record_stop(at:, path:)
          @stop = { "at" => at, "path" => path }
        end

        def to_h
          {
            "origin" => @origin,
            "wrappers" => @wrappers,
            "stop" => @stop,
          }
        end
      end
    end
  end
end
