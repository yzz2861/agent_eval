require "helper"

module SQLite3
  class TestPointer < SQLite3::TestCase
    Calculator = Struct.new(:value)

    def setup
      @db = Database.new(":memory:")
      skip("SQLite pointer passing is not supported") unless defined?(Pointer)
      skip("GC compaction is unsupported on this platform") unless GC.respond_to?(:verify_compaction_references)
      @alive = ObjectSpace::WeakMap.new
      define_functions
    end

    def teardown
      @db.close unless @db.closed?
    end

    def test_bound_pointer_identity_is_preserved_through_functions
      calculator = Calculator.new(42)

      result = @db.get_first_value(
        "SELECT read_calculator(echo_calculator(?))",
        [Pointer.new(:calculator, calculator)]
      )

      assert_equal(42, result)
    end

    def test_function_can_return_a_new_pointer
      result = @db.get_first_value(
        "SELECT read_calculator(make_calculator(?))",
        [7]
      )

      assert_equal(7, result)
    end

    def test_wrong_type_does_not_unwrap_another_object
      calculator = Calculator.new(1)

      result = @db.get_first_value(
        "SELECT other_value(read_other(echo_calculator(?)))",
        [Pointer.new(:calculator, calculator)]
      )

      assert_equal(404, result)
    end

    def test_get_returns_nil_without_a_pointer
      assert_nil(Pointer.get(42, :calculator))
    end

    def test_pointer_cannot_be_initialized_twice
      pointer = Pointer.new(:calculator, Calculator.new(1))

      assert_raise(RuntimeError) do
        pointer.send(:initialize, :other, Object.new)
      end
      assert_equal("calculator", pointer.type)
    end

    def test_pointer_does_not_expose_object_without_type_label
      pointer = Pointer.new(:calculator, Calculator.new(1))

      refute_respond_to(pointer, :get)
      refute_respond_to(pointer, :unwrap)
    end

    def test_pointer_is_null_to_ordinary_sql_operations
      calculator = Calculator.new(1)

      assert_nil(@db.get_first_value("SELECT ?", [Pointer.new(:calculator, calculator)]))
      assert_equal(1, @db.get_first_value("SELECT ? IS NULL", [Pointer.new(:calculator, calculator)]))
    end

    def test_pointer_is_persisted_as_null_without_object_contents
      @db.execute("CREATE TABLE pointers (value)")
      @db.execute("INSERT INTO pointers (value) VALUES (?)", [
        Pointer.new(:calculator, Calculator.new(42))
      ])

      assert_nil(@db.get_first_value("SELECT value FROM pointers"))
    end

    def test_reset_keeps_the_binding_available_for_another_step
      result = step_reset_pointer_twice(99)
      assert_equal([99, 99], result)
      force_gc
      assert_empty(@alive.keys)
    end

    def test_rebinding_releases_the_old_pointer
      statement = @db.prepare("SELECT read_calculator(?)")
      bind_weak_calculator(statement, 1)
      statement.bind_param(1, Pointer.new(:calculator, Calculator.new(2)))
      force_gc

      assert_empty(@alive.keys)
      assert_equal(2, statement.step.first)
      statement.close
    end

    def test_clear_bindings_releases_pointers
      statement = @db.prepare("SELECT read_calculator(?)")
      bind_weak_calculator(statement, 1)
      statement.clear_bindings!
      force_gc

      assert_empty(@alive.keys)
      statement.close
    end

    def test_statement_close_releases_pointers_repeatedly
      100.times do
        close_statement_with_bound_pointer(@db)
      end

      force_gc
      assert_empty(@alive.keys)
    end

    def test_connection_close_releases_pointers_repeatedly
      100.times do
        close_database_with_bound_pointer
      end

      force_gc
      assert_empty(@alive.keys)
    end

    def test_returned_pointer_is_released_after_query
      100.times do
        make_pointer_in_query(1)
      end

      force_gc
      assert_empty(@alive.keys)
    end

    private

    def force_gc
      GC.start(full_mark: true, immediate_sweep: true)
      GC.verify_compaction_references(expand_heap: true, toward: :empty)
      GC.start(full_mark: true, immediate_sweep: true)
    end

    def bind_weak_calculator(statement, value)
      calculator = Calculator.new(value)
      @alive[calculator] = calculator
      statement.bind_param(1, Pointer.new(:calculator, calculator))
    end

    def step_reset_pointer_twice(value)
      statement = @db.prepare("SELECT read_calculator(?)")
      bind_weak_calculator(statement, value)
      results = [statement.step.first]
      statement.reset!
      results << statement.step.first
      statement.close
      results
    end

    def close_statement_with_bound_pointer(db)
      statement = db.prepare("SELECT read_calculator(?)")
      bind_weak_calculator(statement, 1)
      statement.close
    end

    def close_database_with_bound_pointer
      db = Database.new(":memory:")
      statement = db.prepare("SELECT ?")
      bind_weak_calculator(statement, 1)
      db.close
    end

    def make_pointer_in_query(value)
      @db.get_first_value("SELECT read_calculator(make_calculator(?))", [value])
    end

    def define_functions
      @db.define_function("echo_calculator") { |value| value }
      @db.define_function("make_calculator") do |calculator|
        calculator = Calculator.new(calculator)
        @alive[calculator] = calculator
        Pointer.new(:calculator, calculator)
      end
      @db.define_function("read_calculator") do |pointer|
        Pointer.get(pointer, :calculator).value
      end
      @db.define_function("read_other") do |pointer|
        Pointer.get(pointer, :other)
      end
      @db.define_function("other_value") { |value| value || 404 }
    end
  end
end
