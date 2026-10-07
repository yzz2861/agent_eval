# frozen_string_literal: true

require "helper"
require "tempfile"

module SQLite3
  class TestSnapshot < SQLite3::TestCase
    def setup
      super
      skip "SQLite snapshot support is unavailable" unless SQLite3::Snapshot.supported?

      @tempfile = Tempfile.new("sqlite3-snapshot")
      @path = @tempfile.path
      @writer = SQLite3::Database.new(@path)
      @writer.journal_mode = "wal"
      @writer.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)")
      @writer.execute("INSERT INTO items (version) VALUES (1)")
    end

    def teardown
      [@reader, @other, @writer].compact.each { |database| database.close unless database.closed? }
      @snapshot.release if @snapshot && !@snapshot.closed?
      delete_database_files(@path)
      @tempfile.close!
      super
    end

    def test_captures_and_reopens_the_same_version
      @snapshot = capture_snapshot

      @writer.execute("INSERT INTO items (version) VALUES (2)")

      @other = new_reader
      assert_equal [[1]], open_snapshot(@other)
      @other.rollback
      assert_equal [[2]], read_latest(@other)
    end

    def test_invalid_snapshot_does_not_fall_back_to_latest
      @snapshot = capture_snapshot

      @writer.execute("INSERT INTO items (version) VALUES (2)")
      result = @writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
      assert_equal 0, result.first.first.to_i

      @other = new_reader
      @other.transaction
      error = assert_raises(SQLite3::SQLException) { @snapshot.open(@other) }
      assert_equal SQLite3::Constants::ErrorCode::ERROR_SNAPSHOT, error.code
      assert_match(/snapshot is no longer valid/, error.message)
    ensure
      if @other&.transaction_active?
        @other.rollback
        @other.transaction
        assert_equal [[2]], @other.execute("SELECT version FROM items ORDER BY id DESC LIMIT 1")
        @other.rollback
      end
    end

    def test_snapshot_cannot_cross_databases
      other_file = Tempfile.new("sqlite3-snapshot-other")
      other_path = other_file.path
      other_writer = SQLite3::Database.new(other_path)
      other_writer.journal_mode = "wal"
      other_writer.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)")
      other_writer.execute("INSERT INTO items (version) VALUES (9)")

      @snapshot = capture_snapshot
      @other = new_reader(other_path)
      @other.transaction

      error = assert_raises(SQLite3::Exception) { @snapshot.open(@other) }
      assert_match(/different database file/, error.message)
    ensure
      @other&.rollback if @other&.transaction_active?
      other_writer&.close
      delete_database_files(other_path)
      other_file&.close!
    end

    def test_rollback_journal_mode_is_rejected
      @writer.journal_mode = "delete"
      @reader = new_reader
      @reader.transaction

      error = assert_raises(SQLite3::Exception) { SQLite3::Snapshot.capture(@reader) }
      assert_match(/snapshots require WAL journal mode/, error.message)
    ensure
      @reader&.rollback if @reader&.transaction_active?
    end

    def test_requires_a_transaction
      @reader = new_reader

      error = assert_raises(SQLite3::Exception) { SQLite3::Snapshot.capture(@reader) }
      assert_match(/outside a read transaction/, error.message)
    end

    def test_release_is_idempotent
      @snapshot = capture_snapshot

      refute_predicate @snapshot, :closed?
      @snapshot.release
      assert_predicate @snapshot, :closed?
      @snapshot.release

      @other = new_reader
      @other.transaction
      error = assert_raises(SQLite3::Exception) { @snapshot.open(@other) }
      assert_match(/released snapshot/, error.message)
    ensure
      @other&.rollback if @other&.transaction_active?
    end

    private

    def new_reader(path = @path)
      database = SQLite3::Database.new(path)
      database.execute("PRAGMA application_id")
      database
    end

    def delete_database_files(path)
      ["", "-wal", "-shm"].each do |suffix|
        database_path = path + suffix
        File.delete(database_path) if File.exist?(database_path)
      end
    end

    def capture_snapshot
      @reader = new_reader
      snapshot = nil
      @reader.transaction do
        snapshot = @reader.snapshot
      end
      @reader.close
      snapshot
    end

    def open_snapshot(database)
      database.transaction
      @snapshot.open(database)
      database.execute("SELECT version FROM items ORDER BY id")
    end

    def read_latest(database)
      database.transaction
      result = database.execute("SELECT version FROM items ORDER BY id DESC LIMIT 1")
      database.rollback
      result
    end
  end
end
