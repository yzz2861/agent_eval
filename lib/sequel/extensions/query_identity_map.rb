# frozen-string-literal: true
#
# The query_identity_map extension provides a block-scoped identity map for
# model objects loaded from the database. Within a block, repeated loads of
# the same model class, shard/server, and primary key return the same object,
# including objects encountered while eagerly loading associations.
#
#   Sequel.extension :query_identity_map
#   Sequel::Model.plugin :query_identity_map
#   # Or load the plugin only into specific model classes:
#   Artist.plugin :query_identity_map
#
#   Artist.identity_map do
#     a1 = Artist.select(:id).first
#     a2 = Artist.select(:id, :name).first
#     a1.equal?(a2) # => true
#     a1.name       # => "A"
#   end
#
# A later query only fills columns that were not present on the existing
# object. It never overwrites a column that is already present, including a
# column marked as changed. Refresh is explicit and retains its standard
# behavior: it overwrites all values from the database and clears dirty
# tracking.
#
# Identity maps are scoped to the current thread/fiber and to the
# server/shard used by the query. Nested blocks use separate maps. When a
# block exits, including when an exception is raised, all objects loaded in
# that scope are released by the identity map.
#
# Models without a primary key cannot be identity mapped, and a query in an
# identity map must select all primary key columns under their unaliased
# names. Such queries raise Sequel::Error instead of silently returning
# separate objects. Aliased non-primary-key columns are stored on the object
# using the alias name, as they are without the extension.
#
# Related module: Sequel::Plugins::QueryIdentityMap

module Sequel
  module Plugins
    module QueryIdentityMap
      class Scope
        def initialize
          @servers = Hash.new do |servers, server|
            servers[server] = Hash.new do |models, model|
              models[model] = {}
            end
          end
        end

        def call(model, values)
          primary_key = model.primary_key
          unless primary_key
            raise Error, "#{model} has no primary key and cannot be loaded inside an identity map"
          end

          columns = Array(primary_key)
          key = columns.map do |column|
            unless values.has_key?(column)
              raise Error, "primary key column #{column.inspect} was not selected under its unaliased name for #{model}"
            end
            values[column]
          end
          key = key.first if columns.length == 1

          records = @servers[QueryIdentityMap.current_server][model]
          if object = records[key]
            QueryIdentityMap.merge_values(object, values)
            object
          else
            QueryIdentityMap.without_identity_map do
              object = model.call(values)
              records[key] = object
            end
            object
          end
        end

        def release
          @servers.clear
        end
      end

      module ClassMethods
        def identity_map(&block)
          raise Error, "identity_map requires a block" unless block
          QueryIdentityMap.with_scope(&block)
        end
        alias with_identity_map identity_map

        def call(values)
          if !QueryIdentityMap.without_identity_map? && (scope = QueryIdentityMap.current_scope)
            scope.call(self, values)
          else
            super
          end
        end

        def primary_key_lookup(pk)
          QueryIdentityMap.with_model_query_server(dataset) do
            super
          end
        end
      end

      module DatasetMethods
        private

        def _all(block)
          QueryIdentityMap.with_model_query_server(self) do
            super
          end
        end

        def each(*args, &block)
          QueryIdentityMap.with_model_query_server(self) do
            super
          end
        end

        def with_sql_each(sql)
          QueryIdentityMap.with_model_query_server(self) do
            super
          end
        end

        public :each, :with_sql_each
      end

      class << self
        SCOPE_KEY = :sequel_query_identity_map_scopes
        SERVER_KEY = :sequel_query_identity_map_servers
        CONSTRUCTING_KEY = :sequel_query_identity_map_constructing
        private_constant :SCOPE_KEY, :SERVER_KEY, :CONSTRUCTING_KEY

        def current_scope
          Thread.current[SCOPE_KEY]&.last
        end

        def current_server
          Thread.current[SERVER_KEY]&.last || :default
        end

        def with_scope
          scopes = (Thread.current[SCOPE_KEY] ||= [])
          scope = Scope.new
          scopes.push(scope)
          begin
            yield
          ensure
            scope.release
            scopes.pop
            Thread.current[SCOPE_KEY] = nil if scopes.empty?
          end
        end

        def without_identity_map
          previous = Thread.current[CONSTRUCTING_KEY]
          Thread.current[CONSTRUCTING_KEY] = true
          begin
            yield
          ensure
            Thread.current[CONSTRUCTING_KEY] = previous
          end
        end

        def without_identity_map?
          Thread.current[CONSTRUCTING_KEY] == true
        end

        def with_model_query_server(dataset)
          servers = (Thread.current[SERVER_KEY] ||= [])
          servers.push(dataset.opts[:server] || :default)
          begin
            yield
          ensure
            servers.pop
            Thread.current[SERVER_KEY] = nil if servers.empty?
          end
        end

        def merge_values(object, values)
          existing_values = object.values
          values.each do |column, value|
            existing_values[column] = value unless existing_values.has_key?(column)
          end
          object
        end
      end
    end
  end
end
