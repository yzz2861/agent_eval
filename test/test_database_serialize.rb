# frozen_string_literal: true

require "helper"

module SQLite3
  class TestDatabaseSerialize < SQLite3::TestCase
    def setup
      super
      skip "sqlite3_serialize/sqlite3_deserialize not available" unless SQLite3::Database.method_defined?(:serialize)

      @source = SQLite3::Database.new(":memory:")
      @source.execute_batch <<~SQL
        CREATE TABLE authors (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE books (
          id INTEGER PRIMARY KEY,
          author_id INTEGER NOT NULL REFERENCES authors(id),
          title TEXT NOT NULL
        );
        CREATE INDEX idx_books_author ON books(author_id);
        INSERT INTO authors (name) VALUES ('Le Guin'), ('Gaiman');
        INSERT INTO books (author_id, title) VALUES (1, 'A Wizard of Earthsea'), (2, 'Coraline');
      SQL
    end

    def teardown
      @source.close unless @source.closed?
      super
    end

    def test_serialize_returns_binary_string
      image = @source.serialize

      assert_instance_of String, image
      assert_equal Encoding::BINARY, image.encoding
      assert_equal "SQLite format 3", image[0, 15]
    end

    def test_serialize_explicit_schema
      image = @source.serialize("main")

      assert_equal @source.serialize, image
    end

    def test_serialize_empty_schema
      empty = SQLite3::Database.new(":memory:")
      image = empty.serialize

      # sqlite may return nil (no pages) or a valid empty-database image,
      # depending on version; either must round-trip into an empty database
      db = SQLite3::Database.deserialize(image)
      assert_empty db.execute("SELECT name FROM sqlite_master")
    ensure
      empty.close
      db&.close
    end

    def test_deserialize_nil_is_an_empty_database
      db = SQLite3::Database.deserialize(nil)

      assert_empty db.execute("SELECT name FROM sqlite_master")
    ensure
      db.close
    end

    def test_serialize_closed_database_raises
      @source.close

      assert_raises(SQLite3::Exception) { @source.serialize }
    end

    def test_round_trip_preserves_tables_indexes_and_data
      db = SQLite3::Database.deserialize(@source.serialize)

      schema = db.execute("SELECT type, name, tbl_name FROM sqlite_master ORDER BY name")
      assert_includes schema, ["table", "authors", "authors"]
      assert_includes schema, ["table", "books", "books"]
      assert_includes schema, ["index", "idx_books_author", "books"]

      assert_equal [[1, "Le Guin"], [2, "Gaiman"]], db.execute("SELECT * FROM authors ORDER BY id")
      assert_equal [[1, 1, "A Wizard of Earthsea"], [2, 2, "Coraline"]],
        db.execute("SELECT * FROM books ORDER BY id")

      # the index is actually used by the query planner
      plan = db.execute("EXPLAIN QUERY PLAN SELECT * FROM books WHERE author_id = 1").join
      assert_match(/idx_books_author/, plan)
    ensure
      db.close
    end

    def test_instance_deserialize_round_trip
      db = SQLite3::Database.new(":memory:")
      db.deserialize(@source.serialize)

      assert_equal 2, db.get_first_value("SELECT count(*) FROM books")
    ensure
      db.close
    end

    def test_deserialize_read_only_rejects_writes
      db = SQLite3::Database.deserialize(@source.serialize, read_only: true)

      assert_predicate db, :readonly?
      assert_equal 2, db.get_first_value("SELECT count(*) FROM authors")

      assert_raises(SQLite3::ReadOnlyException) do
        db.execute("INSERT INTO authors (name) VALUES ('Butler')")
      end
      assert_raises(SQLite3::ReadOnlyException) do
        db.execute("CREATE TABLE extra (id INTEGER)")
      end
      assert_raises(SQLite3::ReadOnlyException) do
        db.execute("DROP TABLE authors")
      end

      # failed writes did not corrupt anything
      assert_equal 2, db.get_first_value("SELECT count(*) FROM authors")
    ensure
      db.close
    end

    def test_deserialize_writable_allows_writes
      db = SQLite3::Database.deserialize(@source.serialize)

      refute_predicate db, :readonly?
      db.execute("INSERT INTO authors (name) VALUES ('Butler')")

      assert_equal 3, db.get_first_value("SELECT count(*) FROM authors")
    ensure
      db.close
    end

    def test_writable_database_can_grow_beyond_original_image
      image = @source.serialize
      original_size = image.bytesize
      original_bytes = image.dup

      db = SQLite3::Database.deserialize(image)
      db.execute("INSERT INTO books (author_id, title) VALUES (1, randomblob(100000))")

      grown = db.serialize
      assert_operator grown.bytesize, :>, original_size
      assert_equal 3, db.get_first_value("SELECT count(*) FROM books")

      # growth happened in SQLite-owned memory; the caller's string is untouched
      assert_equal original_bytes, image
      assert_equal original_size, image.bytesize
    ensure
      db.close
    end

    def test_caller_string_is_not_shared_with_the_database
      image = @source.serialize

      db = SQLite3::Database.deserialize(image)

      # corrupting the caller's string afterwards must not affect the database
      image.replace("\x00" * image.bytesize)
      assert_equal 2, db.get_first_value("SELECT count(*) FROM authors")
      assert_equal "Le Guin", db.get_first_value("SELECT name FROM authors WHERE id = 1")
    ensure
      db.close
    end

    def test_deserialize_accepts_frozen_string
      db = SQLite3::Database.deserialize(@source.serialize.freeze)

      assert_equal 2, db.get_first_value("SELECT count(*) FROM authors")
    ensure
      db.close
    end

    def test_deserialize_survives_gc_compaction
      db = SQLite3::Database.deserialize(@source.serialize)

      GC.start
      GC.compact if GC.respond_to?(:compact)
      GC.start

      assert_equal 2, db.get_first_value("SELECT count(*) FROM authors")
      db.execute("INSERT INTO authors (name) VALUES ('Butler')")
      assert_equal 3, db.get_first_value("SELECT count(*) FROM authors")
    ensure
      db.close
    end

    def test_deserialize_with_open_statement
      db = SQLite3::Database.new(":memory:")
      db.execute("CREATE TABLE t (id INTEGER)")
      db.execute("INSERT INTO t VALUES (1)")
      stmt = db.prepare("SELECT * FROM t")
      result = stmt.execute
      result.next # keep the statement mid-iteration

      # deserializing swaps out the pager live statements point into,
      # so it is refused while any statement is open
      assert_raises(SQLite3::BusyException) { db.deserialize(@source.serialize) }

      stmt.close
      db.deserialize(@source.serialize)
      assert_equal 2, db.get_first_value("SELECT count(*) FROM authors")
    ensure
      db.close
    end

    def test_deserialize_closed_database_raises
      db = SQLite3::Database.new(":memory:")
      db.close

      assert_raises(SQLite3::Exception) { db.deserialize(@source.serialize) }
    end

    def test_deserialize_into_named_schema
      db = SQLite3::Database.new(":memory:")
      db.execute("ATTACH ':memory:' AS aux")
      db.deserialize(@source.serialize, "aux")

      assert_equal 2, db.get_first_value("SELECT count(*) FROM aux.authors")
      assert_empty db.execute("SELECT name FROM main.sqlite_master")
    ensure
      db.close
    end

    def test_deserialize_invalid_image_fails_on_use
      db = SQLite3::Database.new(":memory:")

      # like opening a corrupt file, sqlite reports the invalid image lazily
      db.deserialize("this is not a sqlite image")
      assert_raises(SQLite3::NotADatabaseException) do
        db.execute("SELECT count(*) FROM sqlite_master")
      end

      # closing the connection is still clean
      db.close
      assert_predicate db, :closed?
    ensure
      db.close unless db.closed?
    end

    def test_class_deserialize_passes_options_through
      db = SQLite3::Database.deserialize(@source.serialize, results_as_hash: true)

      assert_equal({"id" => 1, "name" => "Le Guin"}, db.execute("SELECT * FROM authors WHERE id = 1").first)
    ensure
      db.close
    end
  end
end
