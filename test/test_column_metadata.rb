require "helper"

module SQLite3
  class TestColumnMetadata < SQLite3::TestCase
    def setup
      @db = SQLite3::Database.new(":memory:")
      @db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
      @db.execute("INSERT INTO users (name) VALUES ('alice'), ('bob')")
      @capable = SQLite3::Statement.column_metadata?
    end

    def teardown
      @db.close
    end

    def metadata_for(sql, *binds)
      stmt = @db.prepare(sql)
      stmt.bind_params(*binds) unless binds.empty?
      stmt.columns_metadata
    ensure
      stmt&.close
    end

    def test_capability_constant_and_predicate
      assert_includes([true, false], SQLite3::Statement::COLUMN_METADATA_ENABLED)
      assert_equal(SQLite3::Statement::COLUMN_METADATA_ENABLED,
        SQLite3::Statement.column_metadata?)
    end

    def test_metadata_is_column_ordered_and_has_display_names
      metadata = metadata_for("SELECT name, id FROM users")

      assert_equal(%w[name id], metadata.map(&:display_name))
      assert_equal(%w[name id], metadata_for("SELECT name, id FROM users").map(&:display_name))
    end

    def test_metadata_for_table_columns
      skip("SQLite was built without column metadata support") unless @capable

      metadata = metadata_for("SELECT id, name FROM users")

      assert_equal(
        ColumnMetadata.new(
          display_name: "id", database_name: "main",
          table_name: "users", origin_name: "id"
        ), metadata[0])
      assert_equal(
        ColumnMetadata.new(
          display_name: "name", database_name: "main",
          table_name: "users", origin_name: "name"
        ), metadata[1])
      refute_predicate(metadata[0], :missing_origin?)
    end

    def test_alias_does_not_change_origin_name
      skip("SQLite was built without column metadata support") unless @capable

      metadata = metadata_for("SELECT id AS user_id, name AS who FROM users")

      assert_equal(%w[user_id who], metadata.map(&:display_name))
      assert_equal(%w[id name], metadata.map(&:origin_name))
      assert_equal(["users", "users"], metadata.map(&:table_name))
    end

    def test_duplicate_column_names_are_distinguished_by_position
      skip("SQLite was built without column metadata support") unless @capable

      sql = <<~SQL
        SELECT a.id AS a_id, b.id AS b_id, a.name, b.name
        FROM users a JOIN users b ON a.id = b.id
        WHERE a.id = 1
      SQL
      metadata = metadata_for(sql)
      row = @db.execute(sql).first

      assert_equal(%w[a_id b_id name name], metadata.map(&:display_name))
      assert_equal(%w[id id name name], metadata.map(&:origin_name))
      metadata.each { |column| assert_equal "users", column.table_name }
      assert_equal([1, 1, "alice", "alice"], row)
    end

    def test_expressions_and_literals_have_explicit_nil_origin
      sql = <<~SQL
        SELECT id, id + 1 AS next_id, length(name) AS name_len,
               'literal' AS literal, NULL AS nul_value, ? AS bound
        FROM users WHERE id = 1
      SQL
      metadata = metadata_for(sql, 42)

      assert_equal(%w[id next_id name_len literal nul_value bound],
        metadata.map(&:display_name))

      real = metadata[0]
      computed = metadata[1..]

      if @capable
        assert_equal "id", real.origin_name
      end
      computed.each do |column|
        assert_nil column.database_name
        assert_nil column.table_name
        assert_nil column.origin_name
        assert_predicate column, :missing_origin?
      end
      refute_predicate real, :missing_origin?
    end

    def test_select_star_mixes_real_and_computed_columns
      skip("SQLite was built without column metadata support") unless @capable

      metadata = metadata_for("SELECT users.*, id * 2 AS doubled FROM users")

      assert_equal(%w[id name doubled], metadata.map(&:display_name))
      assert_equal(["id", "name", nil], metadata.map(&:origin_name))
      assert_nil metadata.last.origin_name
    end

    def test_view_columns_resolve_to_base_table
      skip("SQLite was built without column metadata support") unless @capable

      @db.execute("CREATE VIEW active_users AS SELECT id, name FROM users")
      metadata = metadata_for("SELECT id, name FROM active_users")

      assert_equal(%w[id name], metadata.map(&:display_name))
      metadata.each do |column|
        assert_equal "main", column.database_name
        assert_equal "users", column.table_name
      end
      assert_equal(%w[id name], metadata.map(&:origin_name))
    end

    def test_subquery_columns_track_origin
      skip("SQLite was built without column metadata support") unless @capable

      sql = <<~SQL
        SELECT inner_users.id AS outer_id,
               inner_users.name,
               inner_users.id + 1 AS computed
        FROM (SELECT id, name FROM users) AS inner_users
      SQL
      metadata = metadata_for(sql)

      assert_equal(%w[outer_id name computed], metadata.map(&:display_name))
      assert_equal("id", metadata[0].origin_name)
      assert_equal("users", metadata[0].table_name)
      assert_equal("name", metadata[1].origin_name)
      assert_nil metadata[2].origin_name
    end

    def test_star_subquery_keeps_origin
      skip("SQLite was built without column metadata support") unless @capable

      metadata = metadata_for("SELECT * FROM (SELECT id, name FROM users)")

      assert_equal(%w[id name], metadata.map(&:origin_name))
      assert_equal(["users", "users"], metadata.map(&:table_name))
    end

    def test_returning_reports_column_origins
      skip("SQLite was built without column metadata support") unless @capable

      metadata = nil
      stmt = @db.prepare(
        "INSERT INTO users (name) VALUES ('carol') RETURNING id, name, id + 1 AS next_id"
      )
      stmt.bind_params
      metadata = stmt.columns_metadata
      row = stmt.step

      assert_equal(%w[id name next_id], metadata.map(&:display_name))
      assert_equal "id", metadata[0].origin_name
      assert_equal "name", metadata[1].origin_name
      assert_nil metadata[2].origin_name
      assert_equal [3, "carol", 4], row
    ensure
      stmt&.close
    end

    def test_returning_star
      skip("SQLite was built without column metadata support") unless @capable

      stmt = @db.prepare("UPDATE users SET name = name WHERE id = 1 RETURNING *")
      metadata = stmt.columns_metadata
      stmt.step

      assert_equal(%w[id name], metadata.map(&:origin_name))
    ensure
      stmt&.close
    end

    def test_attached_database_name
      skip("SQLite was built without column metadata support") unless @capable

      @db.execute("ATTACH DATABASE ':memory:' AS aux")
      @db.execute("CREATE TABLE aux.things (id INTEGER PRIMARY KEY, label TEXT)")
      metadata = metadata_for("SELECT id, label FROM aux.things")

      assert_equal(%w[id label], metadata.map(&:display_name))
      metadata.each do |column|
        assert_equal "aux", column.database_name
        assert_equal "things", column.table_name
      end
    end

    def test_without_column_metadata_support_all_origins_are_nil
      metadata = metadata_for("SELECT id, id + 1 AS computed FROM users")

      if @capable
        assert_equal "id", metadata[0].origin_name
      else
        assert_equal %w[id computed], metadata.map(&:display_name)
        metadata.each do |column|
          assert_nil column.database_name
          assert_nil column.table_name
          assert_nil column.origin_name
        end
      end
    end

    def test_fallback_reporting_when_capability_is_absent
      # Simulate a build compiled without SQLITE_ENABLE_COLUMN_METADATA by
      # disabling the capability predicate. Display names must still be
      # reported, with explicit nil origins (never guessed).
      stmt = @db.prepare("SELECT id, name FROM users")
      stmt.define_singleton_method(:column_metadata_supported?) { false }

      metadata = stmt.columns_metadata

      assert_equal %w[id name], metadata.map(&:display_name)
      metadata.each do |column|
        assert_nil column.database_name
        assert_nil column.table_name
        assert_nil column.origin_name
        assert_predicate column, :missing_origin?
      end
    ensure
      stmt&.close
    end

    def test_metadata_objects_are_frozen_value_objects
      metadata = metadata_for("SELECT id FROM users")
      column = metadata.first

      assert_instance_of ColumnMetadata, column
      assert_predicate column, :frozen?
      assert_predicate column.display_name, :frozen?
      assert_equal({
        display_name: "id", database_name: (@capable ? "main" : nil),
        table_name: (@capable ? "users" : nil), origin_name: (@capable ? "id" : nil)
      }, column.to_h)
      assert_raises(FrozenError) { column.display_name.replace("x") }
    end

    def test_metadata_is_cached_and_aligned_with_columns
      stmt = @db.prepare("SELECT id, name FROM users")

      first = stmt.columns_metadata
      assert_same first, stmt.columns_metadata
      assert_equal stmt.columns, first.map(&:display_name)
      assert_equal ["integer", "text"], stmt.types
    ensure
      stmt&.close
    end

    def test_cache_refreshed_after_schema_change_reprepare
      stmt = @db.prepare("SELECT * FROM users")
      assert_equal %w[id name], stmt.columns_metadata.map(&:display_name)

      @db.execute("ALTER TABLE users ADD COLUMN age INTEGER")
      stmt.step
      stmt.reset!
      assert_operator stmt.send(:reprepare_count), :>=, 1

      metadata = stmt.columns_metadata
      assert_equal %w[id name age], metadata.map(&:display_name)
      assert_equal %w[id name age], metadata.map(&:origin_name) if @capable
      assert_equal %w[id name age], stmt.columns
      assert_equal ["integer", "text", "integer"], stmt.types
    ensure
      stmt&.close
    end

    def test_cache_stays_valid_without_schema_change
      stmt = @db.prepare("SELECT id, name FROM users")
      metadata = stmt.columns_metadata

      stmt.execute.to_a
      stmt.reset!
      stmt.execute.to_a

      assert_same metadata, stmt.columns_metadata
      assert_equal 0, stmt.send(:reprepare_count)
    ensure
      stmt&.close
    end

    def test_result_set_exposes_columns_metadata
      result = @db.prepare("SELECT id, id + 1 AS next_id FROM users WHERE id = 1").execute

      assert_respond_to result, :columns_metadata
      metadata = result.columns_metadata
      assert_equal %w[id next_id], metadata.map(&:display_name)
      if @capable
        assert_equal "id", metadata.first.origin_name
        assert_nil metadata.last.origin_name
      end

      assert_equal result.columns, metadata.map(&:display_name)
    ensure
      result&.close
    end

    def test_native_origin_methods_return_nil_instead_of_crashing
      skip("origin methods are not defined without column metadata support") unless @capable

      stmt = @db.prepare("SELECT 1 + 1 AS computed")

      assert_nil stmt.database_name(0)
      assert_nil stmt.table_name(0)
      assert_nil stmt.origin_name(0)
    ensure
      stmt&.close
    end

    def test_closed_statement_raises
      stmt = @db.prepare("SELECT id FROM users")
      stmt.close

      assert_raises(SQLite3::Exception) { stmt.columns_metadata }
    end

    def test_no_column_statement
      stmt = @db.prepare("INSERT INTO users (name) VALUES ('dave')")
      stmt.execute

      assert_equal [], stmt.columns_metadata
      assert_equal [], stmt.columns
    ensure
      stmt&.close
    end
  end
end
