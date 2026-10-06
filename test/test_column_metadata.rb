# frozen_string_literal: true

require "helper"
require "tmpdir"

module SQLite3
  class TestColumnMetadata < SQLite3::TestCase
    def setup
      @db = SQLite3::Database.new(":memory:")
      @db.execute("CREATE TABLE artists (id INTEGER PRIMARY KEY, name TEXT)")
      @db.execute("CREATE TABLE albums (id INTEGER PRIMARY KEY, title TEXT, artist_id INTEGER)")
      @db.execute("CREATE TABLE artist_view AS SELECT id, name FROM artists")
      @db.execute("INSERT INTO artists (id, name) VALUES (1, 'the band')")
      @db.execute("INSERT INTO albums (id, title, artist_id) VALUES (10, 'the album', 1)")
    end

    def teardown
      @db.close
    end

    def test_capability_check
      assert_includes [true, false], SQLite3::Statement.column_metadata_supported?
      assert_equal(
        SQLite3::Statement.column_metadata_supported?,
        SQLite3::Statement.column_metadata_supported?
      )
    end

    def test_metadata_is_position_ordered_with_all_keys
      metadata = @db.prepare("SELECT id, name FROM artists").column_metadata

      assert_equal [{ name: "id", database: "main", table: "artists", column: "id" },
                    { name: "name", database: "main", table: "artists", column: "name" }],
                   metadata
      assert_predicate metadata, :frozen?
      metadata.each { |column| assert_predicate column, :frozen? }
    end

    def test_join_with_duplicate_ids_resolves_each_origin
      metadata = @db.prepare(<<~SQL).column_metadata
        SELECT artists.id, albums.id
        FROM artists
        JOIN albums ON albums.artist_id = artists.id
      SQL

      assert_equal ["id", "id"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal ["artists", "albums"], metadata.map { |column| column[:table] }
        assert_equal ["id", "id"], metadata.map { |column| column[:column] }
        assert_equal ["main", "main"], metadata.map { |column| column[:database] }
      else
        assert_equal [nil, nil], metadata.map { |column| column[:table] }
      end
    end

    def test_same_column_selected_twice
      metadata = @db.prepare("SELECT id, id FROM artists").column_metadata

      assert_equal ["id", "id"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal ["artists", "artists"], metadata.map { |column| column[:table] }
      end
    end

    def test_mixed_real_and_computed_columns
      metadata = @db.prepare(
        "SELECT id, id * 2 AS doubled, 42 AS constant, name || '!' FROM artists"
      ).column_metadata

      assert_equal ["id", "doubled", "constant", "name || '!'"],
                   metadata.map { |column| column[:name] }

      if SQLite3::Statement.column_metadata_supported?
        assert_equal "artists", metadata[0][:table]
        assert_equal "id", metadata[0][:column]
        metadata[1..].each do |column|
          assert_nil column[:database]
          assert_nil column[:table]
          assert_nil column[:column]
        end
      end
    end

    def test_alias_reports_display_and_original_name
      metadata = @db.prepare("SELECT id AS artist_id, name AS artist_name FROM artists").column_metadata

      assert_equal ["artist_id", "artist_name"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal ["id", "name"], metadata.map { |column| column[:column] }
        assert_equal ["artists", "artists"], metadata.map { |column| column[:table] }
      end
    end

    def test_view_resolves_to_underlying_table
      metadata = @db.prepare("SELECT id, name FROM artist_view").column_metadata

      assert_equal ["id", "name"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal ["artists", "artists"], metadata.map { |column| column[:table] }
        assert_equal ["id", "name"], metadata.map { |column| column[:column] }
      end
    end

    def test_flattened_subquery_resolves_origin
      metadata = @db.prepare("SELECT id FROM (SELECT id FROM artists)").column_metadata

      assert_equal ["id"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal "artists", metadata[0][:table]
        assert_equal "id", metadata[0][:column]
      end
    end

    def test_aliased_subquery_reports_original_column
      metadata = @db.prepare("SELECT renamed FROM (SELECT id AS renamed FROM artists)").column_metadata

      assert_equal ["renamed"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal "artists", metadata[0][:table]
        assert_equal "id", metadata[0][:column]
      end
    end

    def test_cte_resolves_origin
      metadata = @db.prepare(
        "WITH recent AS (SELECT id FROM artists) SELECT id FROM recent"
      ).column_metadata

      assert_equal ["id"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal "artists", metadata[0][:table]
        assert_equal "id", metadata[0][:column]
      end
    end

    def test_insert_returning
      metadata = nil
      @db.prepare("INSERT INTO artists (name) VALUES ('new artist') RETURNING id, name") do |stmt|
        metadata = stmt.column_metadata
        stmt.to_a
      end

      assert_equal ["id", "name"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal ["artists", "artists"], metadata.map { |column| column[:table] }
        assert_equal ["id", "name"], metadata.map { |column| column[:column] }
      end
    end

    def test_update_returning_with_alias
      metadata = nil
      @db.prepare("UPDATE artists SET name = 'renamed' WHERE id = 1 RETURNING id AS updated_id") do |stmt|
        metadata = stmt.column_metadata
        stmt.to_a
      end

      assert_equal ["updated_id"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal "artists", metadata[0][:table]
        assert_equal "id", metadata[0][:column]
      end
    end

    def test_delete_returning
      metadata = nil
      @db.prepare("DELETE FROM artists WHERE id = 1 RETURNING id") do |stmt|
        metadata = stmt.column_metadata
        stmt.to_a
      end

      assert_equal ["id"], metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal "artists", metadata[0][:table]
        assert_equal "id", metadata[0][:column]
      end
    end

    def test_result_set_exposes_metadata
      result_set = @db.prepare(
        "SELECT artists.id, albums.id FROM artists JOIN albums ON albums.artist_id = artists.id"
      ).execute

      assert_equal ["id", "id"], result_set.columns
      assert_equal ["id", "id"], result_set.column_metadata.map { |column| column[:name] }
      if SQLite3::Statement.column_metadata_supported?
        assert_equal ["artists", "albums"],
                     result_set.column_metadata.map { |column| column[:table] }
      end
      result_set.close
    end

    def test_metadata_does_not_crash_on_expression_column
      statement = @db.prepare("SELECT 1 + 1")
      if statement.respond_to?(:database_name)
        assert_nil statement.database_name(0)
        assert_nil statement.table_name(0)
        assert_nil statement.origin_name(0)
      end
      assert_nil statement.column_metadata[0][:table]
      statement.close
    end

    def test_metadata_is_refreshed_after_schema_change_reprepare
      Dir.mktmpdir do |dir|
        path = File.join(dir, "metadata_reprepare.db")
        db = SQLite3::Database.new(path)
        db.execute("CREATE TABLE songs (id INTEGER PRIMARY KEY, title TEXT)")
        db.execute("INSERT INTO songs (title) VALUES ('a song')")

        statement = db.prepare("SELECT * FROM songs")
        assert_equal ["id", "title"], statement.columns
        assert_equal ["id", "title"], statement.column_metadata.map { |column| column[:name] }
        statement.execute.to_a

        other = SQLite3::Database.new(path)
        other.execute("ALTER TABLE songs ADD COLUMN duration INTEGER")
        other.close

        statement.execute.to_a # triggers the automatic reprepare
        assert_operator statement.stat(:reprepares), :>=, 1
        assert_equal ["id", "title", "duration"], statement.columns
        assert_equal ["id", "title", "duration"],
                     statement.column_metadata.map { |column| column[:name] }
        if SQLite3::Statement.column_metadata_supported?
          assert_equal ["id", "title", "duration"],
                       statement.column_metadata.map { |column| column[:column] }
          assert_equal ["songs"] * 3,
                       statement.column_metadata.map { |column| column[:table] }
        end

        statement.close
        db.close
      end
    end
  end
end
