# frozen_string_literal: true
module GraphQL
  module Language
    # Links GraphQL documents that are split across several modules into one
    # complete, executable document for a selected operation.
    #
    # Each module is parsed in its own scope: fragments are bound to the module
    # that defines them, and cross-module references must be declared with an
    # explicit import manifest. Same-named fragments in different modules never
    # silently override one another -- when the linked document is printed,
    # fragments from other modules are renamed with a stable, module-derived
    # prefix and every reference to them is updated.
    #
    # The linker checks for import cycles, missing symbols, and variables used
    # but not declared by the selected operation. Only fragments that are
    # actually reachable from the operation are included in the output.
    #
    # The linker performs no file IO: callers read files themselves and pass
    # their contents as strings.
    #
    # @example Linking an operation that spans two modules
    #   linker = GraphQL::Language::DocumentLinker.new(
    #     modules: {
    #       "users" => "fragment UserFields on User { id name }",
    #       "posts" => "query GetPost($id: ID!) { post(id: $id) { author { ...UserFields } } }",
    #     },
    #     imports: {
    #       "posts" => [{ from: "users", symbols: ["UserFields"] }],
    #     },
    #   )
    #   linker.link("GetPost", from: "posts")
    class DocumentLinker
      # Base class for all errors raised while linking.
      class LinkError < GraphQL::Error; end

      # Raised when module imports form a cycle.
      class ImportCycleError < LinkError; end

      # Raised when an import manifest references a module that wasn't provided.
      class UnknownModuleError < LinkError; end

      # Raised when an imported symbol isn't a fragment exported by its module,
      # or when a fragment spread can't be resolved in its module's scope.
      class MissingSymbolError < LinkError; end

      # Raised when a module defines the same fragment or operation name twice.
      class DuplicateDefinitionError < LinkError; end

      # Raised when two names would collide in the linked document, either
      # because a module imports a symbol it also defines itself, or because
      # two fragments would be exported under the same name.
      class NameConflictError < LinkError; end

      # Raised when the selected operation can't be found or is ambiguous.
      class OperationNotFoundError < LinkError; end

      # Raised when a reachable fragment uses a variable that the selected
      # operation doesn't declare.
      class UndeclaredVariableError < LinkError; end

      # @param modules [Hash{String => String}] Module name => GraphQL source.
      #   Each source may contain operations and fragment definitions.
      # @param imports [Hash{String => Array<Hash>, Hash{String => String}}]
      #   Import manifest per module, either as a list of
      #   "{ from: "module", symbols: ["Name", ...] }" entries or as a flat
      #   "{ "Name" => "module" }" mapping.
      def initialize(modules:, imports: {})
        @modules = {}
        modules.each do |name, source|
          name = name.to_s
          @modules[name] = ModuleScope.new(name, source)
        end
        @imports = normalize_imports(imports)
      end

      # Link the document for the selected operation.
      #
      # @param operation_name [String, nil] Name of the operation to link.
      #   When nil, the home module must contain exactly one operation.
      # @param from [String, nil] Name of the module containing the operation.
      #   When nil, the operation name must be unique across all modules.
      # @return [String] A complete document, ready to execute.
      def link(operation_name = nil, from: nil)
        link_document(operation_name, from: from).to_query_string
      end

      # Like link, but returns the parsed document instead of a string.
      # @return [GraphQL::Language::Nodes::Document]
      def link_document(operation_name = nil, from: nil)
        home_name, operation = find_operation(operation_name, from&.to_s)
        resolve_module_graph(home_name)
        included = collect_fragments(home_name, operation)
        check_variables(operation, included)
        build_document(home_name, operation, included)
      end

      private

      # A parsed module: its own fragments and operations, bound to its scope.
      class ModuleScope
        attr_reader :name, :fragments, :operations

        def initialize(name, source)
          @name = name
          document = source.is_a?(GraphQL::Language::Nodes::Document) ? source : GraphQL.parse(source)
          @fragments = {}
          @operations = {}
          document.definitions.each do |defn|
            case defn
            when GraphQL::Language::Nodes::FragmentDefinition
              if @fragments.key?(defn.name)
                raise DuplicateDefinitionError, "Module \"#{name}\" defines fragment \"#{defn.name}\" more than once"
              end
              @fragments[defn.name] = defn
            when GraphQL::Language::Nodes::OperationDefinition
              if @operations.key?(defn.name)
                raise DuplicateDefinitionError, "Module \"#{name}\" defines operation \"#{defn.name || "(anonymous)"}\" more than once"
              end
              @operations[defn.name] = defn
            else
              raise LinkError, "Module \"#{name}\" contains a #{defn.class.name.split("::").last}; only operations and fragments can be linked"
            end
          end
        end
      end

      def normalize_imports(imports)
        normalized = {}
        imports.each do |mod_name, entries|
          mod_name = mod_name.to_s
          if !@modules.key?(mod_name)
            raise UnknownModuleError, "Import manifest references unknown module \"#{mod_name}\""
          end
          table = normalized[mod_name] ||= {}
          case entries
          when Hash
            entries.each do |symbol, source|
              add_import(table, mod_name, symbol.to_s, source.to_s)
            end
          when Array
            entries.each do |entry|
              from = entry[:from] || entry["from"]
              symbols = entry[:symbols] || entry["symbols"]
              if from.nil? || symbols.nil?
                raise ArgumentError, "Import entries for module \"#{mod_name}\" must have :from and :symbols keys, got: #{entry.inspect}"
              end
              symbols.each do |symbol|
                add_import(table, mod_name, symbol.to_s, from.to_s)
              end
            end
          else
            raise ArgumentError, "Imports for module \"#{mod_name}\" must be a Hash or an Array, got: #{entries.inspect}"
          end
        end
        normalized
      end

      def add_import(table, mod_name, symbol, source)
        if table.key?(symbol)
          raise NameConflictError, "Module \"#{mod_name}\" imports \"#{symbol}\" from both \"#{table[symbol]}\" and \"#{source}\""
        end
        table[symbol] = source
      end

      def imports_for(mod_name)
        @imports[mod_name] || GraphQL::EmptyObjects::EMPTY_HASH
      end

      def find_operation(operation_name, from)
        if from
          scope = @modules[from]
          if scope.nil?
            raise UnknownModuleError, "Unknown module \"#{from}\""
          end
          operation = select_operation(scope.operations, operation_name, "module \"#{from}\"")
          [from, operation]
        else
          matches = []
          @modules.each_value do |scope|
            scope.operations.each_value do |op|
              matches << [scope, op] if operation_name.nil? || op.name == operation_name
            end
          end
          if matches.empty?
            raise OperationNotFoundError, "Couldn't find operation \"#{operation_name}\" in any module"
          elsif matches.size > 1
            names = matches.map { |scope, _op| "\"#{scope.name}\"" }.join(", ")
            raise OperationNotFoundError, "Operation \"#{operation_name}\" is defined in more than one module (#{names}); pass from: to select one"
          end
          scope, operation = matches.first
          [scope.name, operation]
        end
      end

      def select_operation(operations, operation_name, location)
        if operation_name
          operation = operations[operation_name]
          if operation.nil?
            raise OperationNotFoundError, "Couldn't find operation \"#{operation_name}\" in #{location}"
          end
          operation
        else
          if operations.size != 1
            raise OperationNotFoundError, "#{location.capitalize} contains #{operations.size} operations; pass an operation name to select one"
          end
          operations.values.first
        end
      end

      # Walk the import graph of reachable modules, validating every declared
      # import and raising ImportCycleError on cycles.
      # @return [Array<String>] Reachable module names, in discovery order.
      def resolve_module_graph(home_name)
        states = {}
        reachable = []
        visit = nil
        visit = lambda do |mod_name, stack|
          case states[mod_name]
          when :done
            next
          when :visiting
            cycle = (stack[stack.index(mod_name)..] + [mod_name]).join(" -> ")
            raise ImportCycleError, "Import cycle detected: #{cycle}"
          end
          states[mod_name] = :visiting
          reachable << mod_name
          scope = @modules[mod_name]
          imports_for(mod_name).each do |symbol, source|
            source_scope = @modules[source]
            if source_scope.nil?
              raise UnknownModuleError, "Module \"#{mod_name}\" imports \"#{symbol}\" from unknown module \"#{source}\""
            end
            if scope.fragments.key?(symbol)
              raise NameConflictError, "Module \"#{mod_name}\" imports \"#{symbol}\" from \"#{source}\" but also defines it locally"
            end
            if !source_scope.fragments.key?(symbol)
              raise MissingSymbolError, "Module \"#{mod_name}\" imports \"#{symbol}\" from \"#{source}\", but \"#{source}\" doesn't define that fragment"
            end
            visit.call(source, stack + [mod_name])
          end
          states[mod_name] = :done
        end
        visit.call(home_name, [])
        reachable
      end

      # Depth-first collection of fragments reachable from the operation.
      # @return [Array<Array(String, GraphQL::Language::Nodes::FragmentDefinition)>]
      #   Pairs of module name and definition, in discovery order.
      def collect_fragments(home_name, operation)
        included = []
        included_keys = {}
        visit_spreads = nil
        visit_spreads = lambda do |mod_name, node|
          each_node(node) do |child|
            next unless child.is_a?(GraphQL::Language::Nodes::FragmentSpread)
            frag_mod, frag_def = resolve_fragment(mod_name, child.name)
            key = [frag_mod, frag_def.name]
            if !included_keys[key]
              included_keys[key] = true
              included << [frag_mod, frag_def]
              visit_spreads.call(frag_mod, frag_def)
            end
          end
        end
        visit_spreads.call(home_name, operation)
        included
      end

      # Resolve a fragment spread inside mod_name: the module's own scope
      # first, then its explicit imports.
      def resolve_fragment(mod_name, spread_name)
        scope = @modules[mod_name]
        if scope.fragments.key?(spread_name)
          [mod_name, scope.fragments[spread_name]]
        elsif (source = imports_for(mod_name)[spread_name])
          [source, @modules[source].fragments[spread_name]]
        else
          raise MissingSymbolError, "Module \"#{mod_name}\" spreads \"...#{spread_name}\", but it neither defines that fragment nor imports it"
        end
      end

      def check_variables(operation, included)
        declared = operation.variables.map(&:name)
        undeclared = []
        collect_variable_names(operation, undeclared)
        included.each do |_mod_name, frag_def|
          collect_variable_names(frag_def, undeclared)
        end
        undeclared.uniq!
        undeclared -= declared
        if !undeclared.empty?
          list = undeclared.map { |name| "$#{name}" }.join(", ")
          raise UndeclaredVariableError, "Operation \"#{operation.name || "(anonymous)"}\" uses variables that it doesn't declare: #{list}"
        end
      end

      def collect_variable_names(node, names)
        each_node(node) do |child|
          names << child.name if child.is_a?(GraphQL::Language::Nodes::VariableIdentifier)
        end
      end

      def build_document(home_name, operation, included)
        home_renames = rename_map_for(home_name, home_name)
        rewritten_operation = operation.merge(
          selections: rewrite_selections(operation.selections, home_renames)
        )
        definitions = [rewritten_operation]
        exported_names = {}
        included.each do |mod_name, frag_def|
          exported_name = exported_name_for(mod_name, frag_def.name, home_name)
          if (previous = exported_names[exported_name])
            raise NameConflictError, "Fragment \"#{frag_def.name}\" from \"#{mod_name}\" and fragment \"#{previous[1]}\" from \"#{previous[0]}\" would both be exported as \"#{exported_name}\""
          end
          exported_names[exported_name] = [mod_name, frag_def.name]
          renames = rename_map_for(mod_name, home_name)
          definitions << frag_def.merge(
            name: exported_name,
            selections: rewrite_selections(frag_def.selections, renames),
          )
        end
        GraphQL::Language::Nodes::Document.new(definitions: definitions)
      end

      # Map every fragment name visible inside mod_name to the name it will
      # have in the linked document.
      def rename_map_for(mod_name, home_name)
        renames = {}
        @modules[mod_name].fragments.each_key do |frag_name|
          renames[frag_name] = exported_name_for(mod_name, frag_name, home_name)
        end
        imports_for(mod_name).each do |symbol, source|
          renames[symbol] = exported_name_for(source, symbol, home_name)
        end
        renames
      end

      # Fragments from the operation's own module keep their names; fragments
      # from other modules get a stable prefix derived from the module name.
      def exported_name_for(mod_name, frag_name, home_name)
        mod_name == home_name ? frag_name : "#{name_prefix_for(mod_name)}_#{frag_name}"
      end

      # Turn an arbitrary module name into a stable, valid GraphQL name prefix,
      # eg "admin/user-fields" becomes "AdminUserFields".
      def name_prefix_for(mod_name)
        prefix = mod_name.split(/[^0-9A-Za-z]+/).reject(&:empty?).map do |part|
          part.sub(/\A./) { |char| char.upcase }
        end.join
        prefix = "Module" if prefix.empty?
        prefix = "_#{prefix}" if prefix.match?(/\A[0-9]/)
        prefix
      end

      # Copy selection trees, renaming fragment spreads according to renames.
      def rewrite_selections(selections, renames)
        selections.map do |selection|
          case selection
          when GraphQL::Language::Nodes::FragmentSpread
            new_name = renames[selection.name]
            new_name && new_name != selection.name ? selection.merge(name: new_name) : selection
          when GraphQL::Language::Nodes::Field, GraphQL::Language::Nodes::InlineFragment
            selection.merge(selections: rewrite_selections(selection.selections, renames))
          else
            selection
          end
        end
      end

      def each_node(node, &block)
        yield node
        node.children.each do |child|
          each_node(child, &block)
        end
      end
    end
  end
end
