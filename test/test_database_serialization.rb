require "helper"

module SQLite3
  class TestDatabaseSerialization < SQLite3::TestCase
    def setup
      @source = SQLite3::Database.new(":memory:")
      @source.execute("CREATE TABLE authors (id INTEGER PRIMARY KEY, name TEXT)")
      @source.execute("CREATE TABLE books (id INTEGER PRIMARY KEY, author_id INTEGER, title TEXT)")
      @source.execute("CREATE INDEX index_books_on_author_id ON books(author_id)")
      @source.execute("INSERT INTO authors VALUES (1, 'Sandi Metz')")
      @source.execute("INSERT INTO books VALUES (10, 1, 'Practical Object-Oriented Design')")
      @image = @source.serialize
    end

    def teardown
      @databases&.each { |database| database.close unless database.closed? }
      @source.close unless @source.closed?
    end

    def test_serialize_returns_binary_database_image
      assert_equal Encoding::ASCII_8BIT, @image.encoding
      assert_operator @image.bytesize, :>, 0
      assert_equal "SQLite format 3\0", @image[0, 16]
    end

    def test_round_trips_tables_data_and_index
      database = deserialize(@image)

      assert_equal [[1, "Sandi Metz"]], database.execute("SELECT * FROM authors ORDER BY id")
      assert_equal [[10, 1, "Practical Object-Oriented Design"]], database.execute("SELECT * FROM books ORDER BY id")
      assert_equal ["index_books_on_author_id"], indexes(database)
    end

    def test_serialize_is_a_snapshot
      database = deserialize(@image)
      @source.execute("INSERT INTO authors VALUES (2, 'Kent Beck')")

      assert_equal [[1]], database.execute("SELECT COUNT(*) FROM authors")
    end

    def test_round_trip_uses_an_in_memory_database
      database = deserialize(@image)

      assert_empty database.filename
      assert_equal [[0, "main", ""]], database.database_list
    end

    def test_deserialize_readonly_rejects_writes
      database = deserialize(@image, readonly: true)

      assert_predicate database, :readonly?
      assert_raise(SQLite3::ReadOnlyException) do
        database.execute("INSERT INTO authors VALUES (2, 'Kent Beck')")
      end
      assert_equal [[1]], database.execute("SELECT COUNT(*) FROM authors")
    end

    def test_readonly_import_can_close
      database = SQLite3::Database.deserialize(@image, readonly: true)

      database.close

      assert_predicate database, :closed?
    end

    def test_writable_deserialize_can_grow_beyond_source_image
      database = deserialize(@image)

      1000.times do |index|
        database.execute("INSERT INTO books VALUES (?, 1, ?)", [index + 11, "Book #{index} #{'x' * 200}"])
      end

      assert_equal [[1001]], database.execute("SELECT COUNT(*) FROM books")
      assert_operator database.serialize.bytesize, :>, @image.bytesize
    end

    def test_database_does_not_share_input_string_storage
      original = @image.dup
      mutable_image = @image.dup
      database = deserialize(mutable_image)

      mutable_image.setbyte(0, "x".ord)
      database.execute("INSERT INTO authors VALUES (2, 'Rebecca Parsons')")

      assert_equal original[0, original.bytesize], @source.serialize
      assert_equal [[1, "Sandi Metz"], [2, "Rebecca Parsons"]],
        database.execute("SELECT * FROM authors ORDER BY id")
    end

    def test_gc_compaction_after_import
      skip_unless_compaction_supported

      database = deserialize(@image)
      gc_verify_compaction_references

      database.execute("INSERT INTO authors VALUES (2, 'Mary Poppendieck')")
      assert_equal [[2, "Mary Poppendieck"]], database.execute("SELECT * FROM authors WHERE id = 2")
    end

    def test_active_statement_blocks_deserialization
      database = deserialize(@image)
      statement = database.prepare("SELECT * FROM authors")
      statement.step

      assert_raise(SQLite3::BusyException) do
        database.deserialize(@image)
      end
      assert_equal [[1, "Sandi Metz"]], database.execute("SELECT * FROM authors")
    ensure
      statement&.close
    end

    def test_idle_statement_blocks_deserialization
      database = deserialize(@image)
      statement = database.prepare("SELECT COUNT(*) FROM authors")

      assert_raise(SQLite3::BusyException) do
        database.deserialize(@image)
      end
      assert_equal [[1]], statement.to_a
    ensure
      statement&.close
    end

    def test_active_transaction_blocks_deserialization
      database = deserialize(@image)
      database.transaction do
        assert_predicate database, :transaction_active?
        assert_raise(SQLite3::BusyException) do
          database.deserialize(@image)
        end
      end

      assert_equal [[1]], database.execute("SELECT COUNT(*) FROM authors")
    end

    def test_invalid_image_failure_closes_database
      database = SQLite3::Database.new(":memory:")
      assert_raise(SQLite3::NotADatabaseException) do
        database.deserialize("not a database")
      end

      assert_predicate database, :closed?
    end

    def test_empty_image_is_rejected
      assert_raise(ArgumentError) do
        SQLite3::Database.deserialize("")
      end
    end

    def test_instance_deserialize
      database = SQLite3::Database.new(":memory:")
      result = database.deserialize(@image)

      assert_same database, result
      assert_equal [[1, "Sandi Metz"]], database.execute("SELECT * FROM authors")
    ensure
      database&.close
    end

    def test_deserialize_accepts_frozen_source
      database = SQLite3::Database.deserialize(@image.freeze, readonly: true)

      assert_equal [[1]], database.execute("SELECT COUNT(*) FROM authors")
    ensure
      database&.close
    end

    def test_schema_argument_accepts_symbols
      database = deserialize(@image, :main, readonly: true)

      assert_predicate database, :readonly?
    end

    private

    def deserialize(image, schema = "main", readonly: false)
      database = SQLite3::Database.deserialize(image, schema, readonly: readonly)
      @databases ||= []
      @databases << database
      database
    end

    def indexes(database)
      database.execute("SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name").flatten
    end
  end
end
