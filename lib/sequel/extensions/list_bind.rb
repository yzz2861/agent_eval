# frozen-string-literal: true
#
# The list_bind extension adds explicit list bind parameters for
# prepared statements and bound variable queries.  A list bind parameter
# marks a value that is expected to be an array, and expands into the
# correct number of bind placeholders when the statement is called.  Plain
# arrays used in queries keep their usual meaning.
#
# Create list bind parameters with Sequel.list_bind:
#
#   ps = DB[:items].where(id: Sequel.list_bind(:ids)).prepare(:select, :by_ids)
#   ps.call(ids: [1, 2, 3])
#   # SELECT * FROM items WHERE (id IN (?, ?, ?)) -- args: [1, 2, 3]
#
#   ps.call(ids: [4, 5])
#   # SELECT * FROM items WHERE (id IN (?, ?)) -- args: [4, 5]
#
# Statements for different list lengths are cached with a bounded LRU
# cache (per named prepared statement).  Empty lists are well defined:
#
#   ps.call(ids: [])
#   # SELECT * FROM items WHERE (1 = 0)
#
# NOT IN (through Dataset#exclude) follows SQL three-valued logic, so a
# list containing NULL makes NOT IN match nothing:
#
#   ps = DB[:items].exclude(id: Sequel.list_bind(:ids)).prepare(:select, :x)
#   ps.call(ids: [1, nil])
#   # SELECT * FROM items WHERE (id NOT IN (?, ?)) -- args: [1, nil] (no rows)
#
# Lists of tuples are supported for composite keys:
#
#   ds = DB[:items].where([:a, :b] => Sequel.list_bind(:pairs))
#   ds.call(:select, pairs: [[1, 2], [3, 4]])
#   # SELECT * FROM items WHERE ((a, b) IN ((?, ?), (?, ?)))
#   # -- args: [1, 2, 3, 4]
#
# Defined behavior:
#
# * Empty list :: IN matches nothing, NOT IN matches everything.
# * Lists containing NULL :: elements stay bound; IN/NOT IN follow SQL
#   three-valued logic.
# * Same parameter used more than once :: every occurrence emits its own
#   placeholders, bound to the same value(s) in document order.
# * Missing parameter or non-array value :: raises Sequel::Error.
#
# All values are sent as bind parameters; they are never interpolated into
# the SQL string.
#
# Related module: Sequel::ListBind

module Sequel
  # Marker for a named list bind parameter.  Normally used as the value of
  # a condition pair (e.g. +where(id: Sequel.list_bind(:ids))+), which turns
  # it into an SQL::ListInExpression.
  class SQL::ListBind < SQL::Expression
    # The bind parameter name (hash key supplied when calling).
    attr_reader :name

    def initialize(name)
      unless name.respond_to?(:to_sym)
        raise Error, "list bind parameter name must be a symbol or respond to to_sym, got #{name.class}"
      end
      @name = name.to_sym
      freeze
    end

    # A bare marker outside an IN/NOT IN context has no SQL meaning.
    def sql_literal_append(ds, sql)
      raise Error, "#{inspect} used outside of an IN/NOT IN expression (use it as a condition value, e.g. where(id: Sequel.list_bind(:ids)))"
    end

    alias to_s_append sql_literal_append
  end

  # IN/NOT IN expression whose right-hand side is a named list bind
  # parameter.  Its SQL depends on the concrete list values available when
  # the statement is rendered for execution.
  class SQL::ListInExpression < SQL::Expression
    # Column expression, or an array of columns for composite keys.
    attr_reader :column
    # Bind parameter name.
    attr_reader :name
    # True when this is a NOT IN expression.
    attr_reader :negate

    def initialize(column, name, negate=false)
      @column = column
      @name = name.to_sym
      @negate = negate
      freeze
    end

    # Negate the expression (IN <-> NOT IN).
    def ~
      self.class.new(@column, @name, !@negate)
    end

    def to_s_append(ds, sql)
      ds.list_in_sql_append(sql, self)
    end
  end

  module ListBind
    # Default maximum number of length-specific statements cached per
    # named prepared statement.
    DEFAULT_MAX_LIST_BIND_STATEMENTS = 8

    # Bounded LRU cache for length-specific rendered statements.
    class SizedCache
      def initialize(max_size = DEFAULT_MAX_LIST_BIND_STATEMENTS)
        unless max_size.is_a?(Integer) && max_size >= 1
          raise Error, "invalid list bind statement cache size: #{max_size.inspect}"
        end
        @max_size = max_size
        @entries = {}
      end

      def [](key)
        return unless @entries.key?(key)
        value = @entries.delete(key)
        @entries[key] = value
      end

      def []=(key, value)
        @entries.delete(key)
        @entries[key] = value
        @entries.shift if @entries.length > @max_size
        value
      end

      def size
        @entries.length
      end

      def keys
        @entries.keys
      end
    end

    # Carries concrete bind values while rendering length-specific SQL and
    # tracks both referenced list names and every scalar placeholder value
    # in document order (so native bind arguments stay aligned).
    class Renderer
      attr_reader :bind_vars
      attr_reader :list_names
      attr_reader :placements

      def initialize(bind_vars)
        @bind_vars = bind_vars
        @list_names = []
        @placements = []
        # name => [element value...] in document order for named adapters
        @named = {}
        # counters for unique element placeholder names on named adapters
        @counters = Hash.new(0)
      end

      # Record one use of a list parameter and return its concrete array.
      def use_list(name)
        @list_names << name unless @list_names.include?(name)
        unless @bind_vars.key?(name)
          raise Error, "missing list bind parameter #{name.inspect}"
        end
        value = @bind_vars[name]
        unless value.is_a?(Array)
          raise Error, "list bind parameter #{name.inspect} must be an array, got #{value.class}"
        end
        value
      end

      # Record one scalar placeholder value in document order.
      def place_scalar(value)
        @placements << value
      end

      # Record one list element for a named-adapter placeholder and return
      # the unique bind name to use.
      def place_named(list_name, value)
        (@named[list_name] ||= []) << value
        index = @counters[list_name]
        @counters[list_name] += 1
        "#{list_name}_#{index}".to_sym
      end

      # Name -> value mapping for named adapters, covering scalar and list
      # parameters in the exact form used by the SQL placeholders.
      def named_arguments
        result = {}
        @bind_vars.each do |name, value|
          result[name] = value unless value.is_a?(Array) && @list_names.include?(name)
        end
        @named.each do |name, values|
          values.each_with_index do |value, index|
            result["#{name}_#{index}".to_sym] = value
          end
        end
        result
      end
    end

    # Turns list bind markers into IN expressions inside condition pairs.
    module BooleanExpressionMethods
      def from_value_pair(left, right)
        if right.is_a?(SQL::ListBind)
          SQL::ListInExpression.new(left, right.name, false)
        else
          super
        end
      end

      def invert(expression)
        if expression.is_a?(SQL::ListInExpression)
          ~expression
        else
          super
        end
      end
    end

    # Dataset SQL rendering plus prepared statement integration.
    module DatasetMethods
      public

      # One-shot bound variable call.  Emulated adapters literalize values
      # at run time; native adapters expand markers into placeholders and
      # pass bind arguments alongside.
      def call(type, bind_variables=Sequel::OPTS, *values, &block)
        bind_variables = bind_variables.frozen? ? bind_variables.dup : Hash[bind_variables]
        renderer = Renderer.new(bind_variables)

        mods = bound_variable_modules + [ConcreteDatasetMethods]
        concrete = to_prepared_statement(type, values, :extend=>mods)
        emulated = concrete.send(:emulate_prepared_statements?)
        concrete = concrete.clone(:bind_vars=>bind_variables.freeze,
          :list_bind_renderer=>renderer, :list_bind_emulated=>emulated)
        sql = concrete.prepared_sql
        return super(type, bind_variables, *values, &block) if renderer.list_names.empty?
        concrete.send(:list_bind_check_missing!, renderer)
        if emulated
          return concrete.send(:run, &block)
        end
        args = concrete.send(:list_bind_native_arguments, renderer)
        concrete.clone(:sql=>sql, :prepared_sql=>sql, :bind_arguments=>args,
          :prepared_statement_name=>nil).send(:run, &block)
      end

      # On native adapters, a statement referencing list bind parameters
      # cannot be server-prepared until list lengths are known, so build the
      # template without preparing it.  Length-specific statements are
      # created and cached when the statement is called.
      def prepare(type, name, *values)
        return super if emulate_prepared_statements?

        ps = to_prepared_statement(type, values,
          :name=>name,
          :extend=>prepared_statement_modules,
          :no_delayed_evaluations=>true,
        ).with_extend(NativeTemplateMethods).clone(:list_bind_names_collector=>[])

        sql = ps.prepared_sql.freeze
        ps.prepared_args.freeze
        result = ps.clone(:prepared_sql=>sql, :sql=>sql, :list_bind_names_collector=>nil)

        db.set_prepared_statement(name, result)
        result
      end

      # Build the IN/NOT IN clause for a list bind expression.
      def list_in_sql_append(sql, expr)
        renderer = @opts[:list_bind_renderer]
        values = renderer ? renderer.use_list(expr.name) : nil

        if values
          if values.empty?
            return literal_append(sql, {1 => expr.negate ? 1 : 0})
          end

          columns = Array(expr.column)
          arities = list_bind_tuple_arities(values)
          if arities
            if arities.length > 1
              raise Error, "list bind parameter #{expr.name.inspect} contains tuples of different sizes: #{arities.inspect}"
            end
            if arities.first != columns.length
              raise Error, "list bind parameter #{expr.name.inspect} has tuples of #{arities.first} value(s) but #{columns.length} column(s) given"
            end
          elsif values.any?{|v| v.is_a?(Array)}
            raise Error, "list bind parameter #{expr.name.inspect} mixes scalar and tuple values"
          elsif columns.length > 1
            raise Error, "list bind parameter #{expr.name.inspect} has scalar values but #{columns.length} columns given"
          end
        end

        sql << '('
        if expr.column.is_a?(Array)
          array_sql_append(sql, expr.column)
        else
          literal_append(sql, expr.column)
        end
        sql << (expr.negate ? ' NOT IN ' : ' IN ')
        list_bind_values_sql_append(sql, expr, values)
        sql << ')'
      end

      private

      # Render the value side: expanded placeholders for concrete values,
      # or a single placeholder while building the statement template.
      def list_bind_values_sql_append(sql, expr, values)
        if values
          sql << '('
          c = false
          values.each do |value|
            sql << ', ' if c
            list_bind_element_sql_append(sql, expr, value)
            c = true
          end
          sql << ')'
        else
          prepared_args << expr.name
          sql << prepared_arg_placeholder.to_s
        end
      end

      # Render one list element (scalar or tuple) as bind placeholders.
      def list_bind_element_sql_append(sql, expr, value)
        if value.is_a?(Array)
          sql << '('
          c = false
          value.each do |v|
            sql << ', ' if c
            list_bind_scalar_sql_append(sql, expr, v)
            c = true
          end
          sql << ')'
        else
          list_bind_scalar_sql_append(sql, expr, value)
        end
      end

      # Emit one scalar placeholder for a known value, recording its value
      # so the native argument array stays aligned with the placeholders.
      def list_bind_scalar_sql_append(sql, expr, value)
        renderer = @opts[:list_bind_renderer]
        if @opts[:list_bind_emulated]
          # Emulated adapters resolve placeholders to literalized values,
          # the same way ordinary scalar binds are handled.
          literal_append(sql, value)
        elsif list_bind_unnumbered_placeholder?
          renderer.place_scalar(value)
          prepared_args << expr.name
          sql << prepared_arg_placeholder.to_s
        else
          bind_name = renderer.place_named(expr.name, value)
          sql << "#{prepared_arg_placeholder}#{list_bind_named_key(bind_name)}"
        end
      end

      def list_bind_unnumbered_placeholder?
        prepared_arg_placeholder.to_s == '?'
      end

      # Convert a bind name to the adapter's placeholder key form (SQLite
      # replaces dots with double underscores, mirroring its mapper).
      def list_bind_named_key(name)
        name.to_s.gsub('.', '__')
      end

      # Distinct tuple sizes if every element is an Array, else nil.
      def list_bind_tuple_arities(values)
        return nil if values.empty?
        return nil unless values.all?{|v| v.is_a?(Array)}
        values.map(&:length).uniq
      end

      # Build the native bind argument container for a concrete rendering.
      # Unnumbered adapters use an ordered Array; named adapters (e.g.
      # SQLite) use the adapter's normal name -> value mapping.
      def list_bind_native_arguments(renderer)
        if list_bind_unnumbered_placeholder?
          renderer.placements
        else
          args = renderer.named_arguments
          result = {}
          args.each{|k, v| result[k.to_s.gsub('.', '__')] = v}
          result
        end
      end
    end

    # Mixed into a rendering dataset so ordinary +:$name+ scalar
    # placeholders also record their values in document order.
    module ConcreteDatasetMethods
      private

      def prepared_arg(name)
        if (renderer = @opts[:list_bind_renderer]) && @opts[:bind_vars].key?(name)
          value = @opts[:bind_vars][name]
          unless value.is_a?(Array)
            renderer.place_scalar(value)
          end
        end
        super
      end

      def list_bind_check_missing!(renderer)
        renderer.list_names.each do |name|
          unless renderer.bind_vars.key?(name)
            raise Error, "missing list bind parameter #{name.inspect}"
          end
        end
      end
    end

    # Renders a native-adapter template while recording the list bind
    # parameter names it references.
    module NativeTemplateMethods
      public
      def list_in_sql_append(sql, expr)
        names = @opts[:list_bind_names_collector]
        names << expr.name unless names.include?(expr.name)
        super
      end
    end

    # Shared logic for building concrete rendering datasets and caching.
    module StatementSupport
      private

      def list_bind_renderer(bind_vars)
        Renderer.new(bind_vars)
      end

      # Build a prepared-statement dataset that expands list markers with
      # concrete values while keeping scalar placeholders.
      def list_bind_concrete_dataset(renderer, bind_vars, values=nil, emulated=false)
        # with_extend includes modules in reverse order; ConcreteDataset
        # Methods must come first in the ancestor chain so its prepared_arg
        # override wraps the adapter mapper's.
        mods = [ConcreteDatasetMethods] + bound_variable_modules + [Dataset::PreparedStatementMethods]
        orig_dataset.to_prepared_statement(prepared_type, values || prepared_modify_values,
          :extend=>mods,
          :prepared_sql_type=>prepared_sql_type,
        ).clone(
          :bind_vars=>bind_vars.freeze,
          :list_bind_renderer=>renderer,
          :list_bind_emulated=>emulated,
        )
      end

      def list_bind_check_params!(bind_vars, list_names)
        list_names.each do |name|
          unless bind_vars.key?(name)
            raise Error, "missing list bind parameter #{name.inspect}"
          end
        end
      end

      def list_bind_cache_size
        db.opts[:max_list_bind_statements] || DEFAULT_MAX_LIST_BIND_STATEMENTS
      end

      def list_bind_cache(name)
        caches = db.instance_variable_get(:@list_bind_caches) ||
          db.instance_variable_set(:@list_bind_caches, {})
        caches[name] ||= SizedCache.new(list_bind_cache_size)
      end

      def list_bind_normalize_vars(bind_vars_arg)
        bind_vars_arg.frozen? ? bind_vars_arg.dup : Hash[bind_vars_arg]
      end
    end

    # Native adapters: named statement SQL is fixed at prepare time, so
    # rebuild the statement per list-length signature and cache it.
    module ArgumentMapperMethods
      include StatementSupport

      def call(bind_vars_arg=Sequel::OPTS, &block)
        bind_vars = list_bind_normalize_vars(bind_vars_arg)
        renderer = list_bind_renderer(bind_vars)
        concrete = list_bind_concrete_dataset(renderer, bind_vars, prepared_modify_values, emulate_prepared_statements?)
        sql = concrete.prepared_sql
        list_names = renderer.list_names
        list_bind_check_params!(bind_vars, list_names)
        args = concrete.send(:list_bind_native_arguments, renderer)

        if (ps_name = prepared_statement_name) && !list_names.empty?
          signature = list_names.map{|n| bind_vars[n].length}.freeze
          sql = list_bind_cache(ps_name)[signature] ||= sql.freeze
        end

        concrete.clone(:sql=>sql, :prepared_sql=>sql, :bind_arguments=>args,
          :prepared_statement_name=>nil).run(&block)
      end
    end

    # Emulated adapters (e.g. mock): render with concrete values; the
    # adapter literalizes scalar and list elements alike at run time.
    module EmulatedStatementMethods
      include StatementSupport

      def call(bind_vars_arg=Sequel::OPTS, &block)
        bind_vars = list_bind_normalize_vars(bind_vars_arg)
        renderer = list_bind_renderer(bind_vars)
        concrete = list_bind_concrete_dataset(renderer, bind_vars, prepared_modify_values, true)
        list_bind_check_params!(bind_vars, renderer.list_names)
        concrete.run(&block)
      end
    end

  end

  # Create a marker for a named list bind parameter.
  def self.list_bind(name)
    SQL::ListBind.new(name)
  end

  SQL::BooleanExpression.singleton_class.prepend(ListBind::BooleanExpressionMethods)

  Dataset.register_extension(:list_bind, ListBind::DatasetMethods)

  Dataset::EmulatePreparedStatementMethods.prepend(ListBind::EmulatedStatementMethods)
  Dataset::ArgumentMapper.prepend(ListBind::ArgumentMapperMethods)
end
