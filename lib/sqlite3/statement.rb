require "sqlite3/errors"
require "sqlite3/resultset"

class String
  def to_blob
    SQLite3::Blob.new(self)
  end
end

module SQLite3
  # A statement represents a prepared-but-unexecuted SQL query. It will rarely
  # (if ever) be instantiated directly by a client, and is most often obtained
  # via the Database#prepare method.
  class Statement
    include Enumerable

    class << self
      # Whether the loaded SQLite library supports column origin metadata (it
      # was built with +SQLITE_ENABLE_COLUMN_METADATA+). When this is false,
      # #column_metadata still reports the display name, but +database+,
      # +table+ and +column+ are always nil.
      def column_metadata_supported?
        return @column_metadata_supported unless @column_metadata_supported.nil?

        @column_metadata_supported = probe_column_metadata_support
      end

      private

      # The only reliable way to detect a library built without
      # SQLITE_ENABLE_COLUMN_METADATA is to ask for the origin of a known
      # table column: such a library always returns NULL, even though the
      # functions are present at link time.
      def probe_column_metadata_support
        SQLite3::Database.new(":memory:") do |db|
          db.execute("CREATE TABLE sqlite3_ruby_column_metadata_probe (id INTEGER PRIMARY KEY)")
          db.prepare("SELECT id FROM sqlite3_ruby_column_metadata_probe") do |stmt|
            stmt.respond_to?(:database_name) && !stmt.database_name(0).nil?
          end
        end
      rescue StandardError
        false
      end
    end

    # This is any text that followed the first valid SQL statement in the text
    # with which the statement was initialized. If there was no trailing text,
    # this will be the empty string.
    attr_reader :remainder

    # call-seq: SQLite3::Statement.new(db, sql)
    #
    # Create a new statement attached to the given Database instance, and which
    # encapsulates the given SQL text. If the text contains more than one
    # statement (i.e., separated by semicolons), then the #remainder property
    # will be set to the trailing text.
    def initialize(db, sql)
      raise ArgumentError, "prepare called on a closed database" if db.closed?

      sql = sql.encode(Encoding::UTF_8) if sql && sql.encoding != Encoding::UTF_8

      @connection = db
      @columns = nil
      @types = nil
      @column_metadata = nil
      @metadata_reprepare_count = nil
      @remainder = prepare db, sql
    end

    # Binds the given variables to the corresponding placeholders in the SQL
    # text.
    #
    # See Database#execute for a description of the valid placeholder
    # syntaxes.
    #
    # Type mapping from Ruby to SQLite3:
    # - +nil+                            → NULL
    # - Integer                          → INTEGER (or REAL when outside the signed int64 range)
    # - Float                            → REAL
    # - SQLite3::Blob                    → BLOB
    # - String with Encoding::ASCII_8BIT
    #   (a.k.a. BINARY)                  → BLOB
    # - String with Encoding::UTF_16LE
    #   or Encoding::UTF_16BE            → TEXT (bound as UTF-16)
    # - String (all other encodings)     → TEXT (re-encoded to UTF-8 if needed)
    # - Any other type                   → raises RuntimeError
    #
    # Note: a String with Encoding::ASCII_8BIT (BINARY) is always bound as a
    # BLOB, even when its bytes are all valid ASCII. If you want such a string
    # compared or stored as TEXT, re-encode it before binding:
    #
    #   stmt.bind_params(my_binary_str.encode(Encoding::UTF_8))
    #
    # Example:
    #
    #   stmt = db.prepare( "select * from table where a=? and b=?" )
    #   stmt.bind_params( 15, "hello" )
    #
    # See also #execute, #bind_param, Statement#bind_param, and
    # Statement#bind_params.
    def bind_params(*bind_vars)
      index = 1
      bind_vars.flatten.each do |var|
        if Hash === var
          var.each { |key, val| bind_param key, val }
        else
          bind_param index, var
          index += 1
        end
      end
    end

    # Execute the statement. This creates a new ResultSet object for the
    # statement's virtual machine. If a block was given, the new ResultSet will
    # be yielded to it; otherwise, the ResultSet will be returned.
    #
    # Any parameters will be bound to the statement using #bind_params.
    #
    # Example:
    #
    #   stmt = db.prepare( "select * from table" )
    #   stmt.execute do |result|
    #     ...
    #   end
    #
    # See also #bind_params, #execute!.
    def execute(*bind_vars)
      reset! if active? || done?

      bind_params(*bind_vars) unless bind_vars.empty?
      results = @connection.build_result_set self

      step if column_count == 0

      yield results if block_given?
      results
    end

    # Execute the statement. If no block was given, this returns an array of
    # rows returned by executing the statement. Otherwise, each row will be
    # yielded to the block.
    #
    # Any parameters will be bound to the statement using #bind_params.
    #
    # Example:
    #
    #   stmt = db.prepare( "select * from table" )
    #   stmt.execute! do |row|
    #     ...
    #   end
    #
    # See also #bind_params, #execute.
    def execute!(*bind_vars, &block)
      execute(*bind_vars)
      block ? each(&block) : to_a
    end

    # Returns true if the statement is currently active, meaning it has an
    # open result set.
    def active?
      !done?
    end

    # Return an array of the display column names for this statement, in
    # column order. This is the name used in the result set (the alias if one
    # was given). Note that this may execute the statement in order to obtain
    # the metadata; this makes it a (potentially) expensive operation.
    def columns
      get_metadata if metadata_stale?
      @columns
    end

    def each
      loop do
        val = step
        break self if done?
        yield val
      end
    end

    # Return an array of the data types for each column in this statement. Note
    # that this may execute the statement in order to obtain the metadata; this
    # makes it a (potentially) expensive operation.
    def types
      must_be_open!
      get_metadata if metadata_stale?
      @types
    end

    # Return column metadata for this statement as an array of hashes in
    # column order (one hash per result column). Each hash contains:
    #
    # - +name+: the display name of the result column (the alias, if given)
    # - +database+: the schema name of the originating database, or nil
    # - +table+: the name of the originating table, or nil
    # - +column+: the original (unaliased) column name, or nil
    #
    # The origin keys are nil for expressions, literals and other columns for
    # which SQLite cannot determine the source; they are never guessed. Views
    # resolve to the underlying table when SQLite is able to do so.
    #
    # If the loaded SQLite library was built without column metadata support,
    # use Statement.column_metadata_supported? to detect that case; the origin
    # keys are then always nil.
    #
    # Note that this may execute the statement in order to obtain the metadata;
    # this makes it a (potentially) expensive operation.
    def column_metadata
      must_be_open!
      get_metadata if metadata_stale?
      @column_metadata
    end

    # Performs a sanity check to ensure that the statement is not
    # closed. If it is, an exception is raised.
    def must_be_open! # :nodoc:
      if closed?
        raise SQLite3::Exception, "cannot use a closed statement"
      end
    end

    # Returns a Hash containing information about the statement.
    # The contents of the hash are implementation specific and may change in
    # the future without notice. The hash includes information about internal
    # statistics about the statement such as:
    #   - +fullscan_steps+: the number of times that SQLite has stepped forward
    # in a table as part of a full table scan
    #   - +sorts+: the number of sort operations that have occurred
    #   - +autoindexes+: the number of rows inserted into transient indices
    # that were created automatically in order to help joins run faster
    #   - +vm_steps+: the number of virtual machine operations executed by the
    # prepared statement
    #   - +reprepares+: the number of times that the prepare statement has been
    # automatically regenerated due to schema changes or changes to bound
    # parameters that might affect the query plan
    #   - +runs+: the number of times that the prepared statement has been run
    #   - +filter_misses+: the number of times that the Bloom filter returned
    # a find, and thus the join step had to be processed as normal
    #   - +filter_hits+: the number of times that a join step was bypassed
    # because a Bloom filter returned not-found
    def stat key = nil
      if key
        stat_for(key)
      else
        stats_as_hash
      end
    end

    private

    # Metadata is cached, but SQLite may transparently reprepare the
    # statement (for example after a schema change). The reprepare counter is
    # snapshotted when the metadata is gathered and used to invalidate the
    # cache.
    def metadata_stale?
      @columns.nil? || @metadata_reprepare_count != reprepare_count
    end

    # A convenience method for obtaining the metadata about the query. Note
    # that this will actually execute the SQL, which means it can be a
    # (potentially) expensive operation.
    def get_metadata
      count = column_count
      origins_supported = self.class.column_metadata_supported?
      @column_metadata = Array.new(count) do |column|
        metadata = {
          name: column_name(column),
          database: nil,
          table: nil,
          column: nil
        }
        if origins_supported
          metadata[:database] = database_name(column)
          metadata[:table] = table_name(column)
          metadata[:column] = origin_name(column)
        end
        metadata.freeze
      end
      @column_metadata.freeze
      @columns = @column_metadata.map { |metadata| metadata[:name] }
      @types = Array.new(count) do |column|
        column_decltype(column)&.downcase
      end
      @metadata_reprepare_count = reprepare_count
    end
  end
end
