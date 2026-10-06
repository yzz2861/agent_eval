# frozen_string_literal: true

module SQLite3
  # Metadata describing a single result column of a prepared statement, in
  # column order.
  #
  # The +display_name+ is the name used for the column in the result set
  # (honoring any +AS+ alias), and is always available. The +database_name+,
  # +table_name+, and +origin_name+ describe the table column the result
  # column was copied from and are only available when SQLite can determine
  # the origin:
  #
  # - +database_name+: the schema the originating table belongs to (for
  #   example +"main"+ or an attached database name).
  # - +table_name+: the name of the originating table (not the alias used in
  #   the query).
  # - +origin_name+: the column's declared name in that table, before any
  #   +AS+ alias.
  #
  # For computed columns, expressions, or any column whose origin SQLite
  # cannot determine, +database_name+, +table_name+, and +origin_name+ are
  # +nil+. Origin metadata requires a SQLite build with
  # +SQLITE_ENABLE_COLUMN_METADATA+ (see
  # SQLite3::Statement.column_metadata?); when that support was not compiled
  # in, the three origin fields are always +nil+.
  #
  # Instances are immutable; the string attributes are frozen.
  class ColumnMetadata < Data.define(:display_name, :database_name, :table_name, :origin_name)
    # call-seq:
    #   metadata.missing_origin? -> true or false
    #
    # Returns true when SQLite could not determine a table column origin for
    # this result column (it is an expression or computed value), meaning
    # +database_name+, +table_name+, and +origin_name+ are all +nil+.
    def missing_origin?
      database_name.nil? && table_name.nil? && origin_name.nil?
    end
  end
end
