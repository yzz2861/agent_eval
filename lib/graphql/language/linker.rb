# frozen_string_literal: true
module GraphQL
  module Language
    # An offline linker for GraphQL documents spread across multiple modules.
    #
    # Each module is a standalone GraphQL document string paired with an
    # explicit list of imports. Fragment names are bound in module scope, so
    # two modules may define fragments with the same name without one silently
    # overwriting the other. When imported fragments end up in the same output
    # document they are renamed deterministically, and every spread referring
    # to them is updated to the new name.
    #
    # Only the selected operation plus fragments actually reachable from it
    # (through any number of imports) end up in the linked document. The linker
    # verifies that:
    #
    # - every import names a module and a symbol that exists in that module;
    # - imported aliases don't collide with local fragments or each other;
    # - imports don't form a cycle;
    # - referenced fragments are always defined;
    # - every variable used by the operation or by a reachable fragment is
    #   declared by the operation.
    #
    # The linker never reads files; callers parse/read whatever they want and
    # pass document strings in.
    class Linker
      # Base class for every error raised while linking.
      class Error < GraphQL::Error; end

      # A module named in an import (or used as the entry) doesn't exist.
      class MissingModuleError < Error; end

      # An imported symbol isn't a fragment defined by the source module.
      class MissingSymbolError < Error; end

      # Two bindings in one module resolve to the same local name.
      class DuplicateBindingError < Error; end

      # A module declares the same fragment name more than once.
      class DuplicateFragmentError < Error; end

      # Imports form a cycle.
      class CircularImportError < Error; end

      # A fragment spread refers to a fragment that isn't in scope.
      class MissingFragmentError < Error; end

      # Reachable fragments depend on each other in a cycle.
      class CircularFragmentError < Error; end

      # The selected operation can't be found.
      class OperationNotFoundError < Error; end

      # A variable is used without being declared by the operation.
      class UndeclaredVariableError < Error; end

      class << self
        # @see Linker#link
        def link(documents, imports = nil, operation: nil, root: nil)
          new.link(documents, imports, operation: operation, root: root)
        end

        # @see Linker#link_to_query_string
        def link_to_query_string(documents, imports = nil, operation: nil, root: nil)
          new.link_to_query_string(documents, imports, operation: operation, root: root)
        end
      end

      # A single explicit import statement.
      # @api private
      class Import
        # @return [String, #to_s] module the symbol is imported from
        attr_reader :from
        # @return [String] fragment name in the source module
        attr_reader :name
        # @return [String] local name the fragment is bound as
        attr_reader :as

        def self.coerce(spec)
          case spec
          when Import
            spec
          when Hash
            from = spec[:from] || spec["from"]
            name = spec[:name] || spec["name"]
            as = spec[:as] || spec["as"] || name
            if from.nil?
              raise ArgumentError, "Import #{spec.inspect} is missing a required `:from` module"
            end
            if name.nil?
              raise ArgumentError, "Import #{spec.inspect} is missing a required `:name`"
            end
            new(from, name, as)
          when String, Symbol
            raise ArgumentError, "Import #{spec.inspect} must be a Hash with `:from`, `:name`, and optionally `:as`"
          else
            raise ArgumentError, "Unsupported import spec: #{spec.inspect}"
          end
        end

        def initialize(from, name, as = name)
          @from = from.to_s
          @name = name.to_s
          @as = as.to_s
        end
      end

      # One parsed module: its fragment/operation tables and its imports.
      # @api private
      class ModuleDocument
        # @return [String]
        attr_reader :name
        # @return [Array<Import>]
        attr_reader :imports
        # @return [Hash<String, Nodes::FragmentDefinition>]
        attr_reader :fragments
        # @return [Hash<String, Nodes::OperationDefinition>]
        attr_reader :operations

        def initialize(name, document, imports)
          @name = name.to_s
          @imports = imports
          @fragments = {}
          @operations = {}
          document.definitions.each do |definition|
            case definition
            when Nodes::FragmentDefinition
              if @fragments.key?(definition.name)
                raise DuplicateFragmentError, "Fragment `#{definition.name}` is defined more than once in module `#{@name}`"
              end
              @fragments[definition.name] = definition
            when Nodes::OperationDefinition
              operation_key = definition.name || ""
              if @operations.key?(operation_key)
                operation_label = definition.name || "<anonymous>"
                raise Error, "Operation `#{operation_label}` is defined more than once in module `#{@name}`"
              end
              @operations[operation_key] = definition
            end
          end
        end
      end

      # Link document modules into one executable document.
      #
      # @param documents [Hash{#to_s => String}] module names mapped to GraphQL
      #   document strings (file reading is the caller's responsibility)
      # @param imports [Hash{#to_s => Array<Hash>}] module names mapped to
      #   explicit import lists; each import is `{ from:, name:, as: }` with
      #   `as:` defaulting to `name`
      # @param operation [String, Symbol, nil] name of the operation to link;
      #   `nil` links the unique operation found anywhere
      # @param root [#to_s, nil] module containing the entry operation;
      #   required only when it would otherwise be ambiguous
      # @return [Nodes::Document]
      def link(documents, imports = nil, operation: nil, root: nil)
        if imports.nil? && documents.is_a?(Array)
          modules = build_modules_from_array(documents)
        else
          modules = build_modules(documents, imports || {})
        end
        verify_imports(modules)
        detect_import_cycles(modules)

        entry_module_name, entry_operation = resolve_operation(modules, operation, root)
        reachable = collect_reachable(modules, entry_module_name, entry_operation)
        final_names = assign_names(reachable)
        definitions = build_definitions(modules, entry_module_name, entry_operation, reachable, final_names)
        verify_variables(entry_operation, definitions)
        Nodes::Document.new(definitions: definitions)
      end

      # Same as {#link}, but returns the printed document string.
      # @return [String]
      def link_to_query_string(documents, imports = nil, operation: nil, root: nil)
        link(documents, imports, operation: operation, root: root).to_query_string
      end

      private

      def build_modules(documents, imports)
        documents.each_with_object({}) do |(module_name, document_string), modules|
          key = module_name.to_s
          module_imports = Array(imports[module_name] || imports[key]).map { |spec| Import.coerce(spec) }
          document = GraphQL.parse(document_string, filename: key)
          modules[key] = ModuleDocument.new(key, document, module_imports)
        end
      end

      def build_modules_from_array(entries)
        entries.each_with_object({}) do |entry, modules|
          key = (entry[:name] || entry["name"]).to_s
          document_string = entry[:document] || entry["document"]
          module_imports = Array(entry[:imports] || entry["imports"] || []).map { |spec| Import.coerce(spec) }
          modules[key] = ModuleDocument.new(key, GraphQL.parse(document_string, filename: key), module_imports)
        end
      end

      def verify_imports(modules)
        modules.each_value do |mod|
          mod.imports.each do |import_spec|
            source = modules[import_spec.from]
            if source.nil?
              raise MissingModuleError, "Module `#{mod.name}` imports `#{import_spec.name}` from unknown module `#{import_spec.from}`"
            end
            unless source.fragments.key?(import_spec.name) || source.imports.any? { |re_export| re_export.as == import_spec.name }
              raise MissingSymbolError, "Module `#{mod.name}` imports `#{import_spec.name}` from `#{import_spec.from}`, but no such fragment is defined there"
            end
          end

          bindings = {}
          mod.fragments.each_key { |fragment_name| bindings[fragment_name] = [:local, mod.name, fragment_name] }
          mod.imports.each do |import_spec|
            if bindings.key?(import_spec.as)
              kind, other_module, other_name = bindings[import_spec.as]
              if kind == :local
                raise DuplicateBindingError, "Import `#{import_spec.name}` as `#{import_spec.as}` in module `#{mod.name}` collides with a local fragment of that name"
              elsif other_name != import_spec.name || other_module != import_spec.from
                raise DuplicateBindingError, "Local name `#{import_spec.as}` in module `#{mod.name}` is bound to both `#{other_name}` from `#{other_module}` and `#{import_spec.name}` from `#{import_spec.from}`"
              end
            else
              bindings[import_spec.as] = [:import, import_spec.from, import_spec.name]
            end
          end
        end
      end

      def detect_import_cycles(modules)
        state = Hash.new(:unvisited)
        modules.each_key do |module_name|
          follow_imports(modules, module_name, [], state)
        end
      end

      def follow_imports(modules, module_name, path, state)
        case state[module_name]
        when :visiting
          cycle_start = path.index(module_name)
          cycle = path[cycle_start..-1] + [module_name]
          raise CircularImportError, "Import cycle detected: #{cycle.join(" -> ")}"
        when :visited
          return
        end

        state[module_name] = :visiting
        mod = modules[module_name]
        mod.imports.map(&:from).uniq.each do |from_name|
          follow_imports(modules, from_name, path + [module_name], state)
        end
        state[module_name] = :visited
      end

      def resolve_operation(modules, operation, root)
        if root
          entry_name = root.to_s
          mod = modules[entry_name]
          raise MissingModuleError, "Entry module `#{entry_name}` does not exist" if mod.nil?
          operation_key = operation.nil? ? "" : operation.to_s
          entry_operation =
            if operation.nil?
              raise OperationNotFoundError, "Module `#{entry_name}` contains no operation" if mod.operations.empty?
              if mod.operations.size > 1
                raise OperationNotFoundError, "Module `#{entry_name}` contains multiple operations; pass `operation:` to select one"
              end
              mod.operations.values.first
            else
              mod.operations[operation_key] || raise(OperationNotFoundError, "Operation `#{operation}` not found in module `#{entry_name}`")
            end
          return [entry_name, entry_operation]
        end

        candidates = []
        modules.each_value do |mod|
          mod.operations.each_value do |op|
            next unless operation.nil? || op.name == operation.to_s
            candidates << [mod.name, op]
          end
        end

        if candidates.empty?
          target = operation.nil? ? "an operation" : "operation `#{operation}`"
          raise OperationNotFoundError, "Could not find #{target} in any module"
        elsif candidates.size > 1
          raise OperationNotFoundError, "#{operation.nil? ? "Multiple operations" : "Multiple operations named `#{operation}`"} found; pass `root:` to select a module"
        end
        candidates.first
      end

      # Resolve a local fragment name used inside `mod` through the import
      # chain. Returns `[[definition_module, original_name], scope_module]`
      # where `scope_module` is the module whose bindings apply to spreads in
      # the fragment body (normally the definition module).
      def resolve_binding(modules, mod, local_name, seen = {})
        if mod.fragments.key?(local_name)
          [[mod.name, local_name], mod]
        elsif (import_spec = mod.imports.find { |candidate| candidate.as == local_name })
          source = modules[import_spec.from]
          key = [mod.name, local_name]
          return nil if seen.key?(key) # Defensive; import cycles are reported earlier.
          seen[key] = true
          resolve_binding(modules, source, import_spec.name, seen)
        end
      end

      # Walk spreads from the entry operation, following imports. Returns an
      # ordered map of `[module, fragment_name] => fragment node` for every
      # fragment actually reachable, in breadth-first order.
      def collect_reachable(modules, entry_module_name, entry_operation)
        entry_module = modules[entry_module_name]
        reachable = {}
        scopes = {}
        required_names = Hash.new { |hash, key| hash[key] = [] }
        edges = {}

        queue = []
        each_spread(entry_operation) do |spread_name|
          target, scope_mod = resolve_binding(modules, entry_module, spread_name) ||
            raise_missing_fragment(entry_module_name, spread_name, entry_operation.name)
          queue << [scope_mod, target, spread_name]
        end

        until queue.empty?
          scope_mod, item, local_name = queue.shift
          item_module_name, fragment_name = item
          unless required_names[item].include?(local_name)
            required_names[item] << local_name
          end
          next if reachable.key?(item)

          fragment = scope_mod.fragments[fragment_name]
          reachable[item] = fragment
          scopes[item] = scope_mod

          each_spread(fragment) do |spread_name|
            target, next_scope_mod = resolve_binding(modules, scope_mod, spread_name) ||
              raise_missing_fragment(item_module_name, spread_name, fragment_name)
            (edges[item] ||= []) << target
            queue << [next_scope_mod, target, spread_name]
          end
        end

        detect_fragment_cycles(edges)
        reachable.each_key do |item|
          reachable[item] = [reachable[item], required_names[item], scopes[item]]
        end
        reachable
      end

      def raise_missing_fragment(module_name, spread_name, parent_name)
        location = parent_name.nil? || parent_name.empty? ? "the operation" : "`#{parent_name}`"
        raise MissingFragmentError, "Fragment spread `#{spread_name}` used by #{location} in module `#{module_name}` doesn't resolve to any local or imported fragment"
      end

      def detect_fragment_cycles(edges)
        state = Hash.new(:unvisited)
        edges.each_key do |item|
          follow_fragment_edge(edges, item, [], state)
        end
      end

      def follow_fragment_edge(edges, item, path, state)
        case state[item]
        when :visiting
          cycle_start = path.index(item)
          cycle = path[cycle_start..-1] + [item]
          labels = cycle.map { |module_name, fragment_name| "#{fragment_name}@#{module_name}" }
          raise CircularFragmentError, "Fragment dependency cycle detected: #{labels.join(" -> ")}"
        when :visited
          return
        end

        state[item] = :visiting
        (edges[item] || []).uniq.each do |dependency|
          follow_fragment_edge(edges, dependency, path + [item], state)
        end
        state[item] = :visited
      end

      # Choose one globally-unique final name per reachable fragment.
      # Names the fragment was imported under win, in the order they were
      # encountered; a stable module-qualified fallback is used on collision.
      def assign_names(reachable)
        names = {}
        # Assign every name a fragment was imported/declared under to the first
        # fragment that needs it; this makes generated fallbacks safe from
        # shadowing a name still needed later.
        reserved_for = {}
        reachable.each_value do |(_fragment, preferred_names, _scope)|
          preferred_names.each do |candidate|
            reserved_for[candidate] ||= nil
          end
        end
        reachable.each do |item, (_fragment, preferred_names, _scope)|
          preferred_names.each do |candidate|
            reserved_for[candidate] = item if reserved_for[candidate].nil?
          end
          final_name = preferred_names.find { |candidate| reserved_for[candidate] == item }
          if final_name.nil?
            module_name, fragment_name = item
            base = "#{fragment_name}__#{stable_identifier(module_name)}"
            final_name = base
            counter = 2
            while reserved_for.key?(final_name)
              final_name = "#{base}_#{counter}"
              counter += 1
            end
          end
          reserved_for[final_name] = item
          names[item] = final_name
        end
        names
      end

      def stable_identifier(value)
        sanitized = value.to_s.gsub(/[^_a-zA-Z0-9]/, "_")
        sanitized = "_#{sanitized}" if sanitized.start_with?(/[0-9]/)
        sanitized
      end

      def build_definitions(modules, entry_module_name, entry_operation, reachable, final_names)
        entry_module = modules[entry_module_name]
        definitions = []

        operation_renames = spread_rename_map(modules, entry_module, entry_operation, final_names)
        definitions << rename_spreads(entry_operation, operation_renames)

        reachable.each do |item, (fragment, _preferred_names, fragment_scope)|
          item_module_name, fragment_name = item
          renamed_fragment = fragment.merge(name: final_names[item])
          renames = spread_rename_map(modules, fragment_scope, fragment, final_names)
          definitions << rename_spreads(renamed_fragment, renames)
        end
        definitions
      end

      def spread_rename_map(modules, mod, definition, final_names)
        renames = {}
        each_spread(definition) do |spread_name|
          target, _scope_mod = resolve_binding(modules, mod, spread_name)
          renames[spread_name] = final_names[target] if target
        end
        renames
      end

      def rename_spreads(definition, renames)
        return definition if renames.empty?
        SpreadRenamer.new(definition, renames).visit
      end

      def verify_variables(entry_operation, definitions)
        declared = entry_operation.variables.map(&:name)
        document = Nodes::Document.new(definitions: definitions)
        used = []
        VariableCollector.collect(document) { |variable_name| used << variable_name }
        undeclared = used.uniq.reject { |variable_name| declared.include?(variable_name) }
        unless undeclared.empty?
          operation_label = entry_operation.name || "<anonymous>"
          list = undeclared.map { |name| "$#{name}" }.join(", ")
          raise UndeclaredVariableError, "Operation #{operation_label} uses undeclared variable(s): #{list}"
        end
      end

      def each_spread(definition)
        SpreadCollector.collect(definition) { |spread_name| yield spread_name }
      end

      # Collects fragment spread names inside one definition.
      # @api private
      class SpreadCollector < StaticVisitor
        def self.collect(definition)
          collector = new(definition)
          collector.visit
          collector.spreads.each { |spread_name| yield spread_name }
        end

        attr_reader :spreads

        def initialize(definition)
          @spreads = []
          super(definition)
        end

        def on_fragment_spread(node, parent)
          @spreads << node.name
          super
        end
      end

      # Collects variable identifiers inside a document or definition.
      # @api private
      class VariableCollector < StaticVisitor
        def self.collect(definition, &block)
          collector = new(definition, block)
          collector.visit
        end

        def initialize(definition, callback)
          @callback = callback
          super(definition)
        end

        def on_variable_identifier(node, parent)
          @callback.call(node.name)
          super
        end
      end

      # Rewrites fragment spread names using a local-name => final-name map.
      # @api private
      class SpreadRenamer < Visitor
        def initialize(definition, renames)
          @renames = renames
          super(definition)
        end

        def on_fragment_spread(node, parent)
          new_name = @renames[node.name]
          if new_name && new_name != node.name
            super(node.merge(name: new_name), parent)
          else
            super
          end
        end
      end
    end
  end
end
