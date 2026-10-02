# frozen-string-literal: true

module Sequel
  module Plugins
    # The identity_map plugin provides a query-scoped in-memory cache of model
    # objects.  While an identity map is active, loading the same model class,
    # database server, and primary key value returns the same object:
    #
    #   Album.plugin :identity_map
    #
    #   Album.with_identity_map do
    #     album = Album.select(:id, :name).first(id: 1)
    #     Album.select(:id, :copies_sold).first(id: 1).equal?(album)
    #     # => true
    #   end
    #
    # Later queries may add columns that were not loaded by an earlier query.
    # They never replace an attribute that is already present, so values loaded
    # from the database do not silently overwrite a modified attribute.  Models
    # without a primary key cannot be identity mapped.
    #
    # Explicit Model#refresh bypasses the identity map and replaces all values,
    # which also clears changed columns.  The identity map is removed when the
    # block exits, including when an exception is raised, so instances are not
    # retained beyond the scope.
    #
    # Selected aliases that refer to model columns and are not themselves model
    # column names are translated to the real column names while loading.  An
    # alias that is also a model column keeps the standard alias semantics.  If
    # a row contains conflicting values for a column and its non-column alias,
    # loading raises an Error.  Other aliases are left unchanged.  Rows from
    # different database servers remain separate.
    module IdentityMap
      THREAD_KEY = :sequel_identity_map_stack

      # Represents one active query scope.  Identity maps nest, with an inner
      # scope also using objects from outer scopes.  Objects loaded in the inner
      # scope are released when that scope exits.
      class Map
        def initialize(parent=nil)
          @records = {}
          @parent = parent
        end

        # Return the existing record for this model/server/primary key, searching
        # enclosing scopes first.  Otherwise, cache the given record in this scope.
        def record(model, server, pk, record)
          key = [model, server, pk]
          if existing = lookup(key)
            return existing
          end
          @records[key] = record
        end

        # Return whether this map or an enclosing map contains the given key.
        def lookup(key)
          @records[key] || (@parent && @parent.lookup(key))
        end
      end

      module ClassMethods
        # Run a block with a query-scoped identity map.  The block's return value
        # is returned, and the map is always removed when the block exits.
        def with_identity_map
          stack = Thread.current[THREAD_KEY] ||= []
          map = Map.new(stack.last)
          stack.push(map)
          begin
            yield map
          ensure
            stack.pop
            Thread.current[THREAD_KEY] = nil if stack.empty?
          end
        end

        # Return the currently active identity map, if any.
        def identity_map
          stack = Thread.current[THREAD_KEY]
          stack.last if stack
        end

        # Return whether an identity map is currently active for this thread.
        def identity_map?
          stack = Thread.current[THREAD_KEY]
          !stack.nil? && !stack.empty?
        end
      end

      module DatasetMethods
        def row_proc
          return super unless (rp = super) && model && model.primary_key && identity_map = model.identity_map

          old_rp = rp
          aliases = identity_map_column_aliases
          server = identity_map_server
          proc do |row|
            record = old_rp.call(identity_map_aliased_row(row, aliases))
            record.send(:identity_map_canonicalize, identity_map, server)
          end
        end

        private

        # Identify the physical database server that the query will use.  Nil,
        # :default, and a read-only query that falls back to the default server
        # all describe the same default identity.
        def identity_map_server
          server = opts[:server] || :default
          if db.sharded? && server == :read_only && db.pool.pick_server(server) == :default
            :default
          else
            server
          end
        end

        # Map real model columns to aliases selected by this dataset.  Primary
        # keys are always eligible even if column metadata is unavailable.
        def identity_map_column_aliases
          columns = ((model.columns || []) + Array(model.primary_key)).uniq
          return {} if columns.empty?

          map = {}
          (opts[:select] || []).each do |expression|
            next unless expression.is_a?(SQL::AliasedExpression)

            column = case expression.expression
            when Symbol
              expression.expression
            when SQL::QualifiedIdentifier
              expression.expression.column.to_sym
            when SQL::Identifier
              expression.expression.value.to_sym
            end

            aliased_column = expression.alias
            next unless column && columns.include?(column) && !columns.include?(aliased_column)
            if map.key?(column) || map.invert.key?(aliased_column)
              raise Error, "ambiguous identity map aliases in #{sql}: #{expression.inspect}"
            end
            map[column] = aliased_column
          end
          map
        end

        # Translate selected aliases to real model column names before model
        # initialization, retaining aliases that do not map to model columns.
        def identity_map_aliased_row(row, aliases)
          return row if aliases.empty?

          row = row.dup
          aliases.each do |column, aliased_column|
            next unless row.key?(aliased_column)

            if row.key?(column) && row[column] != row[aliased_column]
              raise Error, "conflicting values for #{model}.#{column} in identity map query #{sql}"
            end
            row[column] = row.delete(aliased_column)
          end
          row
        end
      end

      module InstanceMethods
        private

        # Merge a newly loaded row into the active identity map.  Existing
        # attributes are retained; only attributes missing from the existing
        # instance are copied, and no changed columns are added.
        def identity_map_canonicalize(map, server)
          return self unless (pk = identity_map_primary_key)

          if record = map.record(model, server, pk, self)
            record.send(:identity_map_merge_missing_values, self)
            record
          else
            self
          end
        end

        # Return a primary key if every part is present in the loaded row.
        def identity_map_primary_key
          key = model.primary_key
          return if key.nil? || key == []

          values = @values
          if key.is_a?(Array)
            pk = key.map{|column| values[column]}
            pk unless pk.any?(&:nil?)
          else
            values[key]
          end
        end

        # Fill only columns missing from the existing record.  Nil values loaded
        # from the database are still values and prevent a later query from
        # filling that column.
        def identity_map_merge_missing_values(candidate)
          candidate.values.each do |column, value|
            @values[column] = value unless @values.key?(column)
          end
        end
      end
    end
  end
end
