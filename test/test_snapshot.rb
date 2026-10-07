require "helper"
require "tempfile"

module SQLite3
  if defined?(SQLite3::Snapshot)
    class TestSnapshot < SQLite3::TestCase
      def setup
        super
        @file = Tempfile.new(["snapshot", ".db"])
        @path = @file.path
        @file.close

        @writer = SQLite3::Database.new(@path)
        @writer.journal_mode = "wal"
        @writer.execute("CREATE TABLE items (val TEXT)")
        @writer.execute("INSERT INTO items VALUES ('v1')")

        @readers = []
      end

      def teardown
        @readers.each { |reader| reader.close unless reader.closed? }
        @writer.close unless @writer.closed?
        @file.close!
        super
      end

      def open_reader
        SQLite3::Database.new(@path).tap { |reader| @readers << reader }
      end

      # Opens a read transaction on +reader+, captures a snapshot, then ends
      # the transaction, releasing the reader's hold on the WAL.
      def capture_snapshot(reader)
        reader.execute("BEGIN")
        reader.get_first_value("SELECT count(*) FROM items") # open the read transaction
        reader.snapshot
      ensure
        reader.execute("COMMIT") if reader.transaction_active?
      end

      def test_snapshot_handle_lifecycle
        reader = open_reader
        snapshot = capture_snapshot(reader)

        assert_instance_of(SQLite3::Snapshot, snapshot)
        refute_predicate(snapshot, :closed?)

        snapshot.free
        assert_predicate(snapshot, :closed?)
        assert_raises(SQLite3::Exception) { snapshot.free }
      end

      def test_snapshot_preserves_read_view_across_connections
        reader = open_reader
        snapshot = capture_snapshot(reader)
        reader.close # fully release the connection mid-analysis

        @writer.execute("INSERT INTO items VALUES ('v2')")

        later = open_reader
        later.execute("BEGIN")
        later.open_snapshot(snapshot)
        assert_equal(1, later.get_first_value("SELECT count(*) FROM items"))
        assert_equal("v1", later.get_first_value("SELECT val FROM items"))
        later.execute("COMMIT")

        # control: without the snapshot, the latest data is visible
        assert_equal(2, later.get_first_value("SELECT count(*) FROM items"))
      ensure
        later.execute("ROLLBACK") if later&.transaction_active?
      end

      def test_snapshot_invalidated_by_checkpoint_raises_instead_of_reading_latest
        reader = open_reader
        snapshot = capture_snapshot(reader)
        reader.close

        @writer.execute("INSERT INTO items VALUES ('v2')")
        # truncate the WAL, then write new frames so it is recycled
        assert_equal(0, @writer.get_first_value("PRAGMA wal_checkpoint(TRUNCATE)"))
        @writer.execute("INSERT INTO items VALUES ('v3')")

        later = open_reader
        later.execute("BEGIN")
        error = assert_raises(SQLite3::SQLException) { later.open_snapshot(snapshot) }
        assert_match(/no longer valid/, error.message)
        later.execute("ROLLBACK")

        # the failed open must not have silently fallen back to the latest
        # data; a plain read sees all three rows only in a fresh transaction
        assert_equal(3, later.get_first_value("SELECT count(*) FROM items"))
      ensure
        later.execute("ROLLBACK") if later&.transaction_active?
      end

      def test_snapshot_rejected_in_rollback_journal_mode
        rollback_file = Tempfile.new(["rollback", ".db"])
        rollback_db = SQLite3::Database.new(rollback_file.path)
        rollback_db.execute("CREATE TABLE t (x)")
        assert_equal("delete", rollback_db.journal_mode)

        rollback_db.execute("BEGIN")
        rollback_db.get_first_value("SELECT count(*) FROM t")
        error = assert_raises(SQLite3::Exception) { rollback_db.snapshot }
        assert_match(/WAL/, error.message)
        rollback_db.execute("ROLLBACK")
      ensure
        rollback_db&.close
        rollback_file&.close!
      end

      def test_open_snapshot_rejected_in_rollback_journal_mode
        reader = open_reader
        snapshot = capture_snapshot(reader)

        rollback_file = Tempfile.new(["rollback", ".db"])
        rollback_db = SQLite3::Database.new(rollback_file.path)
        rollback_db.execute("BEGIN")
        error = assert_raises(SQLite3::Exception) { rollback_db.open_snapshot(snapshot) }
        assert_match(/WAL/, error.message)
        rollback_db.execute("ROLLBACK")
      ensure
        rollback_db&.close
        rollback_file&.close!
      end

      def test_snapshot_requires_an_open_transaction
        reader = open_reader
        error = assert_raises(SQLite3::Exception) { reader.snapshot }
        assert_match(/transaction/, error.message)
      end

      def test_open_snapshot_requires_an_open_transaction
        reader = open_reader
        snapshot = capture_snapshot(reader)

        error = assert_raises(SQLite3::Exception) { reader.open_snapshot(snapshot) }
        assert_match(/transaction/, error.message)
      end

      def test_snapshot_cannot_be_opened_on_a_different_database
        other_file = Tempfile.new(["other", ".db"])
        other_db = SQLite3::Database.new(other_file.path)
        other_db.journal_mode = "wal"
        other_db.execute("CREATE TABLE other_table (x)")

        reader = open_reader
        snapshot = capture_snapshot(reader)

        other_db.execute("BEGIN")
        error = assert_raises(SQLite3::SQLException) { other_db.open_snapshot(snapshot) }
        assert_match(/no longer valid|belong to this database/, error.message)
        other_db.execute("ROLLBACK")
      ensure
        other_db&.close
        other_file&.close!
      end

      def test_freed_snapshot_cannot_be_opened
        reader = open_reader
        snapshot = capture_snapshot(reader)
        snapshot.free

        reader.execute("BEGIN")
        assert_raises(SQLite3::Exception) { reader.open_snapshot(snapshot) }
        reader.execute("ROLLBACK")
      end

      def test_open_snapshot_rejects_non_snapshot_objects
        reader = open_reader
        reader.execute("BEGIN")
        assert_raises(TypeError) { reader.open_snapshot("not a snapshot") }
        reader.execute("ROLLBACK")
      end
    end
  end
end
