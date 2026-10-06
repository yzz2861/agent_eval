# frozen_string_literal: true

module SQLite3
  # An immutable snapshot of a single row change observed by
  # Database#preupdate_hook.
  #
  # All column values are copied out of sqlite's protected value handles
  # while the hook is running, so a PreupdateChange remains safe to read
  # after the callback returns, after later statements execute, and after
  # the connection is closed.
  #
  # Note that the hook fires *before* the change is durable: the statement
  # may still fail, and the surrounding transaction may still be rolled
  # back. Observing a change says nothing about whether it was committed.
  class PreupdateChange
    # The kind of operation: +:insert+, +:update+, or +:delete+.
    attr_reader :op

    # The name of the database containing the modified table, e.g. "main",
    # "temp", or an alias given to ATTACH.
    attr_reader :database

    # The name of the modified table.
    attr_reader :table

    # 0 if the change was made directly by a statement, 1 if it was made by
    # a top-level trigger, 2 by a trigger fired from a top-level trigger,
    # and so on.
    attr_reader :depth

    # The rowid of the row before the change, or nil for inserts and for
    # WITHOUT ROWID tables.
    attr_reader :old_rowid

    # The rowid of the row after the change, or nil for deletes and for
    # WITHOUT ROWID tables.
    attr_reader :new_rowid

    # A frozen array of the row's column values before the change, or nil
    # for inserts.
    attr_reader :old_values

    # A frozen array of the row's column values after the change, or nil
    # for deletes.
    attr_reader :new_values

    def initialize(op, database, table, depth, old_rowid, new_rowid, old_values, new_values)
      @op = op
      @database = database
      @table = table
      @depth = depth
      @old_rowid = old_rowid
      @new_rowid = new_rowid
      @old_values = old_values&.freeze
      @new_values = new_values&.freeze
      freeze
    end

    def insert?
      op == :insert
    end

    def update?
      op == :update
    end

    def delete?
      op == :delete
    end

    # True if the change was made by a trigger rather than directly by a
    # statement.
    def trigger?
      depth > 0
    end

    def ==(other)
      other.is_a?(PreupdateChange) &&
        op == other.op &&
        database == other.database &&
        table == other.table &&
        depth == other.depth &&
        old_rowid == other.old_rowid &&
        new_rowid == other.new_rowid &&
        old_values == other.old_values &&
        new_values == other.new_values
    end
    alias eql? ==

    def hash
      [op, database, table, depth, old_rowid, new_rowid, old_values, new_values].hash
    end
  end
end
