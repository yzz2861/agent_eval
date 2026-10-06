require "helper"

module SQLite3
  class TestPreupdateHook < SQLite3::TestCase
    def setup
      super
      skip("SQLite was compiled without preupdate hook support") unless
        PREUPDATE_HOOK_AVAILABLE
      @db = Database.new(":memory:")
      @events = []
      @transaction_states = []
      @db.preupdate_hook do |event|
        @events << event
        @transaction_states << @db.transaction_active?
      end
    rescue UnsupportedException
      skip("SQLite was compiled without preupdate hook support")
    end

    def teardown
      @db.close unless @db.closed?
      super
    end

    def test_triggered_insert_update_delete_snapshots_and_rollback
      @db.execute(<<~SQL)
        create table items (
          id integer primary key,
          label text,
          payload blob
        )
      SQL
      @db.execute("create table audit (id integer primary key, label text)")
      @db.execute(<<~SQL)
        create trigger items_audit after insert on items
        begin
          insert into audit (id, label) values (new.id, 'queued');
          update audit set label = 'processed' where id = new.id;
        end;
      SQL

      initial_payload = "\x00\xff\x10".b
      updated_payload = "binary\x00data".b

      @db.execute("begin")
      @db.execute(
        "insert into items values (?, ?, ?)",
        [1, nil, initial_payload]
      )
      @db.execute(
        "update items set label = ?, payload = ? where id = ?",
        ["updated", updated_payload, 1]
      )
      @db.execute("delete from items where id = ?", [1])
      @db.execute("rollback")

      counts = @db.execute(<<~SQL).first
        select (select count(*) from items),
               (select count(*) from audit)
      SQL
      assert_equal [0, 0], counts
      assert_equal [true] * 5, @transaction_states

      assert_events_match(
        [
          {
            operation: :insert,
            database: "main",
            table: "items",
            depth: 0,
            old_values: nil,
            new_values: [1, nil, initial_payload]
          },
          {
            operation: :insert,
            database: "main",
            table: "audit",
            depth: 1,
            old_values: nil,
            new_values: [1, "queued"]
          },
          {
            operation: :update,
            database: "main",
            table: "audit",
            depth: 1,
            old_values: [1, "queued"],
            new_values: [1, "processed"]
          },
          {
            operation: :update,
            database: "main",
            table: "items",
            depth: 0,
            old_values: [1, nil, initial_payload],
            new_values: [1, "updated", updated_payload]
          },
          {
            operation: :delete,
            database: "main",
            table: "items",
            depth: 0,
            old_values: [1, "updated", updated_payload],
            new_values: nil
          }
        ],
        @events
      )
    end

    def test_snapshots_are_frozen_and_preserve_binary_values
      @db.execute("create table items (id integer primary key, payload blob)")
      payload = "before\x00after".b

      @db.execute("insert into items values (?, ?)", [1, payload])
      @db.execute(
        "update items set payload = ? where id = ?",
        ["changed".b, 1]
      )

      inserted_blob = @events.fetch(0).fetch(:new_values).fetch(1)
      updated_blob = @events.fetch(1).fetch(:new_values).fetch(1)

      assert_equal(Encoding::ASCII_8BIT, inserted_blob.encoding)
      assert_instance_of(String, inserted_blob)
      assert_equal(payload.b, inserted_blob)
      assert_equal("changed".b, updated_blob)
      assert(@events.all?(&:frozen?))
      assert(@events.all? do |event|
        event[:database].frozen? && event[:table].frozen?
      end)
      values = @events.flat_map do |event|
        [event[:old_values], event[:new_values]]
      end
      assert(values.compact.all?(&:frozen?))
    end

    def test_callback_exception_propagates_and_connection_remains_usable
      @db.execute("create table items (id integer primary key)")
      @db.preupdate_hook { raise "callback failed" }

      error = assert_raises(RuntimeError) do
        @db.execute("insert into items values (1)")
      end
      assert_equal("callback failed", error.message)
      assert_equal([[2]], @db.execute("select 1 + 1"))
    end

    def test_same_connection_reentry_is_rejected
      @db.execute("create table items (id integer primary key)")
      @db.preupdate_hook { @db.execute("select 1") }

      error = assert_raises(SQLite3::Exception) do
        @db.execute("insert into items values (1)")
      end
      assert_match(
        /cannot use a database connection from its own preupdate callback/,
        error.message
      )
      assert_equal([[2]], @db.execute("select 1 + 1"))
    end

    def test_prepared_statement_reentry_is_rejected
      @db.execute("create table items (id integer primary key)")
      statement = @db.prepare("select 1")
      @db.preupdate_hook { statement.step }

      error = assert_raises(SQLite3::Exception) do
        @db.execute("insert into items values (1)")
      end
      assert_match(
        /cannot use a database connection from its own preupdate callback/,
        error.message
      )
    ensure
      statement&.close
    end

    def test_callback_exception_from_execute_batch_propagates
      @db.execute("create table items (id integer primary key)")
      @db.preupdate_hook { raise "batch failed" }

      error = assert_raises(RuntimeError) do
        @db.execute_batch2("insert into items values (1)")
      end
      assert_equal("batch failed", error.message)
      assert_equal([[2]], @db.execute("select 1 + 1"))
    end

    def test_observer_registration_during_callback_is_rejected
      @db.execute("create table items (id integer primary key)")
      @db.preupdate_hook { @db.preupdate_hook(nil) }

      assert_raises(SQLite3::Exception) do
        @db.execute("insert into items values (1)")
      end
    end

    private

    def assert_events_match(expected, actual)
      expected.each_with_index do |expected_event, index|
        event = actual.fetch(index)
        expected_event.each do |key, expected_value|
          if expected_value.nil?
            assert_nil(event.fetch(key), "event #{index} key #{key}")
          else
            message = "event #{index} key #{key}"
            assert_equal(expected_value, event.fetch(key), message)
          end
        end
        assert_equal(expected_event.keys, event.keys, "event #{index} keys")
      end
      assert_equal(expected.length, actual.length)
    end
  end
end
