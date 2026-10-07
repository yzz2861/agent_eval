# frozen_string_literal: true

module SQLite3
  # A Snapshot records one historical version of a WAL-mode database. Capturing and opening a
  # snapshot both require an active transaction:
  #
  #   reader.transaction { snapshot = reader.snapshot }
  #   other.transaction do
  #     snapshot.open(other)
  #     other.execute("SELECT ...")
  #   end
  #   snapshot.release
  #
  # Opening an invalid snapshot raises instead of silently reading the latest version. A snapshot
  # can only be opened against the same on-disk database file from which it was captured. The
  # caller remains responsible for ending the target read transaction with #commit or #rollback.
  class Snapshot
    class << self
      # Captures the current WAL read view from +database+ and +schema+. The database must already
      # be in a read transaction. SQLite3::Snapshot.get and SQLite3::Snapshot.new are aliases.
      def capture(database, schema = "main")
        schema = schema.to_s
        require_supported!
        validate!(database, schema)
        require_read_transaction!(database, "capture a snapshot")
        ensure_wal_schema!(database, schema)

        allocate.tap do |snapshot|
          snapshot.send(:capture!, database, schema)
          filename = database.filename(schema)
          validate_capture_file!(filename)
          snapshot.instance_variable_set(:@filename, filename)
        end
      end

      alias_method :get, :capture
      alias_method :new, :capture

      # Returns +true+ when the loaded SQLite library exposes the snapshot API.
      def supported?
        SQLite3::SNAPSHOT_SUPPORTED
      end

      private

      def require_supported!
        return if SQLite3::SNAPSHOT_SUPPORTED

        message = "sqlite3_snapshot support requires SQLite compiled with SQLITE_ENABLE_SNAPSHOT"
        raise NotImplementedError, message
      end
    end

    # Starts a read transaction on +database+ using this snapshot. The database must already be in
    # a read transaction. Raises if the snapshot has been invalidated, released, or captured from
    # a different file. #restore is an alias.
    def open(database, schema = "main")
      schema = schema.to_s
      self.class.send(:require_supported!)
      self.class.send(:validate!, database, schema)
      raise SQLite3::Exception, "cannot use a released snapshot" if closed?

      self.class.send(:require_read_transaction!, database, "open a snapshot")
      self.class.send(:ensure_wal_schema!, database, schema)
      self.class.send(:verify_database!, @filename, database, schema)

      open!(database, schema)

      database
    end

    alias_method :restore, :open
    alias_method :free, :release

    private_class_method def self.validate!(database, schema)
      unless database.is_a?(SQLite3::Database)
        raise TypeError, "expected a SQLite3::Database, got #{database.class}"
      end
      raise SQLite3::Exception, "cannot use a closed database" if database.closed?

      raise ArgumentError, "schema cannot be empty" if schema.empty?
      if schema.include?("\0")
        raise ArgumentError, "invalid schema name"
      end
    end

    private_class_method def self.require_read_transaction!(database, action)
      return if database.transaction_active?

      raise SQLite3::Exception, "cannot #{action} outside a read transaction"
    end

    private_class_method def self.ensure_wal_schema!(database, schema)
      mode = database.get_first_value("PRAGMA #{quoted_schema(schema)}.journal_mode")
      return if mode&.downcase == "wal"

      message = "snapshots require WAL journal mode; #{schema.inspect} is using #{mode.inspect}"
      raise SQLite3::Exception, message
    end

    private_class_method def self.verify_database!(expected_filename, database, schema)
      actual_filename = database.filename(schema)
      validate_capture_file!(actual_filename)
      unless File.identical?(expected_filename, actual_filename)
        raise SQLite3::Exception, "snapshot was captured from a different database file"
      end
    end

    private_class_method def self.validate_capture_file!(filename)
      if filename.nil? || filename.empty? || !File.exist?(filename)
        raise SQLite3::Exception, "snapshots require a persistent WAL database file"
      end
    end

    private_class_method def self.quoted_schema(schema)
      "\"#{schema.to_s.gsub('"', '""')}\""
    end
  end
end
