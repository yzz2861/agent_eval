require "helper"

module SQLite3
  class TestScript < SQLite3::TestCase
    def setup
      @db = SQLite3::Database.new(":memory:")
      @db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
      super
    end

    def teardown
      @db.close unless @db.closed?
      super
    end

    def test_returns_result_sets_and_affected_row_counts
      script = @db.script(<<~SQL)
        INSERT INTO items (name) VALUES ("one");
        INSERT INTO items (name) VALUES ("two");
        SELECT name FROM items ORDER BY id;
        UPDATE items SET name = "updated";
        SELECT COUNT(*) FROM items;
      SQL

      assert_equal 1, script.next_result
      assert_equal 1, script.next_result
      assert_instance_of ResultSet, script.next_result
      assert_equal 2, script.next_result
      assert_equal [[2]], script.next_result.to_a
      assert_nil script.next_result
      assert_predicate script, :closed?
    end

    def test_sqlite_parser_determines_statement_boundaries
      @db.execute("CREATE TABLE audit (name TEXT)")
      script_sql = <<~SQL
        /* semicolon; in a comment */
        CREATE TRIGGER items_audit AFTER INSERT ON items
        BEGIN
          INSERT INTO audit (name) VALUES (new.name);
          UPDATE audit SET name = name WHERE ';' = ';';
        END;
        -- another; comment
        INSERT INTO items (name) VALUES ('semi;colon');
        SELECT name FROM items;
      SQL

      results = []
      @db.execute_script(script_sql) do |result|
        results << (result.is_a?(ResultSet) ? result.to_a : result)
      end

      assert_equal [0, 1, [["semi;colon"]]], results
      assert_equal [["semi;colon"]], @db.execute("SELECT name FROM audit")
    end

    def test_bind_parameters_are_independent_for_each_statement
      script = @db.script(<<~SQL)
        SELECT ?;
        SELECT :name;
        INSERT INTO items (name) VALUES (?);
        SELECT name FROM items;
      SQL

      assert_equal [[1]], script.next_result(1).to_a
      assert_equal [["two"]], script.next_result(name: "two").to_a
      assert_equal 1, script.next_result(["three"])
      assert_equal [["three"]], script.next_result.to_a
    end

    def test_missing_parameters_are_reported_before_the_statement_runs
      script = @db.script("INSERT INTO items (name) VALUES (:name)")

      error = assert_raises(ArgumentError) { script.next_result }
      assert_match(/name/, error.message)
      assert_predicate script, :closed?
      assert_equal 0, @db.get_first_value("SELECT COUNT(*) FROM items")
    end

    def test_wrong_positional_parameter_count_is_reported_before_execution
      script = @db.script(<<~SQL)
        INSERT INTO items (name) VALUES (?);
        INSERT INTO items (name) VALUES (?);
      SQL

      assert_equal 1, script.next_result("first")
      error = assert_raises(ArgumentError) { script.next_result("too", "many") }
      assert_match(/2 of 1 positional/, error.message)
      assert_predicate script, :closed?
      assert_equal [["first"]], @db.execute("SELECT name FROM items")
    end

    def test_advancing_closes_the_previous_open_statement
      script = @db.script("SELECT 1; SELECT 2;")
      first_result = script.next_result
      second_result = script.next_result

      assert_predicate first_result, :closed?
      assert_equal [[2]], second_result.to_a
    end

    def test_early_stop_closes_unfinished_statement
      script = @db.script("SELECT 1; SELECT 2;")
      result = script.next_result

      refute_predicate result, :closed?
      script.close

      assert_predicate result, :closed?
      assert_predicate script, :closed?
      assert_nil script.next_result
    end

    def test_block_form_closes_unconsumed_script
      result = nil
      @db.script("SELECT 1; SELECT 2;") do |script|
        result = script.next_result
      end

      assert_predicate result, :closed?
    end

    def test_failure_does_not_roll_back_already_committed_statements
      script = @db.script(<<~SQL)
        INSERT INTO items (name) VALUES ("valid");
        INSERT INTO items (name) VALUES (NULL);
      SQL

      assert_equal 1, script.next_result
      assert_raises(SQLite3::ConstraintException) { script.next_result }

      assert_predicate script, :closed?
      refute_predicate @db, :transaction_active?
      assert_equal [["valid"]], @db.execute("SELECT name FROM items")
    end

    def test_failure_preserves_callers_transaction
      @db.execute("BEGIN")
      script = @db.script(<<~SQL)
        INSERT INTO items (name) VALUES ("valid");
        INSERT INTO items (name) VALUES (NULL);
      SQL

      script.next_result
      assert_raises(SQLite3::ConstraintException) { script.next_result }
      assert_predicate script, :closed?
      assert_predicate @db, :transaction_active?
    ensure
      @db.rollback unless @db.closed? || !@db.transaction_active?
    end

    def test_comments_and_whitespace_have_no_results
      script = @db.script("-- only a comment;\n/* another; */\n")

      assert_nil script.next_result
      assert_predicate script, :closed?
    end

    def test_results_as_hash_is_respected
      @db.results_as_hash = true
      script = @db.script("SELECT 1 AS number")

      assert_equal [{"number" => 1}], script.next_result.to_a
    end
  end
end
