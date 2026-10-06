require "sqlite3/errors"
require "sqlite3/column_metadata"
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

    # Whether the loaded SQLite library was compiled with
    # +SQLITE_ENABLE_COLUMN_METADATA+, which is required to determine the
    # database, table, and origin column of result columns. When this is
    # +false+, #columns_metadata still works but always reports +nil+ for the
    # three origin fields.
    unless const_defined?(:COLUMN_METADATA_ENABLED, false)
      COLUMN_METADATA_ENABLED = false
    end

    # call-seq: Statement.column_metadata? -> true or false
    #
    # Returns +true+ when the loaded SQLite library can report the database,
    # table, and origin column of result columns (i.e. it was built with
    # +SQLITE_ENABLE_COLUMN_METADATA+). When +false+, #columns_metadata
    # reports +nil+ for those origin fields instead of guessing.
    def self.column_metadata?
      COLUMN_METADATA_ENABLED
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
      @columns_metadata = nil
      @types = nil
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

    # Return an array of the column names for this statement. Note that this
    # may execute the statement in order to obtain the metadata; this makes it
    # a (potentially) expensive operation.
    def columns
      must_be_open!
      refresh_metadata if stale_metadata?
      @columns
    end

    # Return an array of ColumnMetadata, one per result column, ordered by
    # column position. Each entry carries the +display_name+ (the result-set
    # column name, honoring any +AS+ alias) plus the +database_name+,
    # +table_name+, and +origin_name+ when SQLite can determine the
    # originating table column; otherwise those fields are +nil+. The values
    # are never guessed.
    #
    # See ColumnMetadata for field semantics and
    # Statement.column_metadata? for the capability check. Note that this may
    # execute the statement in order to obtain the metadata; this makes it a
    # (potentially) expensive operation.
    def columns_metadata
      must_be_open!
      refresh_metadata if stale_metadata?
      @columns_metadata
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
      refresh_metadata if stale_metadata?
      @types
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

    # A convenience method for obtaining the metadata about the query. Note
    # that this will actually execute the SQL, which means it can be a
    # (potentially) expensive operation.
    #
    # SQLite transparently re-prepares a statement when the schema changed
    # since it was prepared; the reprepare counter is snapshotted when the
    # cache is built and compared on every read so stale metadata is rebuilt
    # instead of being served.
    def stale_metadata?
      @metadata_reprepare_count.nil? ||
        @metadata_reprepare_count != reprepare_count
    end

    def refresh_metadata
      count = column_count
      @columns = Array.new(count)
      @columns_metadata = Array.new(count)
      @types = Array.new(count)

      count.times do |column|
        display_name = column_name(column)
        @columns[column] = display_name
        @columns_metadata[column] = build_column_metadata(column, display_name)
        declared_type = column_decltype(column)
        @types[column] = declared_type&.downcase
      end

      @columns_metadata.freeze
      @metadata_reprepare_count = reprepare_count
    end

    # Collect the origin metadata for one column without guessing: only the
    # values SQLite reports are used, anything it cannot determine becomes
    # nil. On builds without SQLITE_ENABLE_COLUMN_METADATA the native methods
    # are absent, so all origin fields are nil.
    def build_column_metadata(column, display_name)
      if column_metadata_supported?
        database = database_name(column)
        table = table_name(column)
        origin = origin_name(column)
      else
        database = table = origin = nil
      end

      ColumnMetadata.new(
        display_name: display_name,
        database_name: database,
        table_name: table,
        origin_name: origin
      ).freeze
    end

    def column_metadata_supported?
      COLUMN_METADATA_ENABLED
    end
  end
end
