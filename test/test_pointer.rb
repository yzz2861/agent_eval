require "helper"
require "weakref"

module SQLite3
  class TestPointer < SQLite3::TestCase
    def setup
      @db = SQLite3::Database.new(":memory:")
    end

    def teardown
      @db.close unless @db.closed?
      super
    end

    def test_bind_pointer_preserves_identity
      obj = Object.new
      seen = nil
      @db.define_function("capture") { |arg| seen = arg; 1 }

      stmt = @db.prepare("SELECT capture(?)")
      ptr = SQLite3::Pointer.new(obj, "calc")
      stmt.bind_pointer(1, ptr)
      stmt.execute!

      assert_same ptr, seen
      assert_same obj, seen.fetch("calc")
    ensure
      stmt.close
    end

    def test_bind_pointer_with_object_and_type
      obj = Object.new
      seen = nil
      @db.define_function("capture") { |arg| seen = arg; 1 }

      stmt = @db.prepare("SELECT capture(?)")
      stmt.bind_pointer(1, obj, "calc")
      stmt.execute!

      assert_kind_of SQLite3::Pointer, seen
      assert_same obj, seen.fetch("calc")
      assert_equal "calc", seen.type
    ensure
      stmt.close
    end

    def test_bind_pointer_by_name
      obj = Object.new
      seen = nil
      @db.define_function("capture") { |arg| seen = arg; 1 }

      stmt = @db.prepare("SELECT capture(:p)")
      stmt.bind_pointer("p", obj, :calc)
      stmt.execute!

      assert_same obj, seen.fetch("calc")
    ensure
      stmt.close
    end

    def test_bind_pointer_rejects_unknown_parameter
      stmt = @db.prepare("SELECT ?")
      assert_raise(SQLite3::Exception) { stmt.bind_pointer(2, Object.new, "calc") }
      assert_raise(SQLite3::Exception) { stmt.bind_pointer("nope", Object.new, "calc") }
    ensure
      stmt.close
    end

    def test_bind_pointer_requires_pointer_without_type
      stmt = @db.prepare("SELECT ?")
      assert_raise(TypeError) { stmt.bind_pointer(1, Object.new) }
    ensure
      stmt.close
    end

    def test_pointer_is_invisible_to_plain_sql
      stmt = @db.prepare("SELECT ?, typeof(?), ? IS NULL, coalesce(?, 'fallback')")
      stmt.bind_pointer(1, Object.new, "calc")
      stmt.bind_pointer(2, Object.new, "calc")
      stmt.bind_pointer(3, Object.new, "calc")
      stmt.bind_pointer(4, Object.new, "calc")

      assert_equal [nil, "null", 1, "fallback"], stmt.execute!.to_a.first
    ensure
      stmt.close
    end

    def test_function_result_pointer_passed_to_another_function
      obj = Object.new
      @db.define_function("make_pointer") { SQLite3::Pointer.new(obj, "calc") }
      @db.define_function("same_object?") { |ptr| ptr.fetch("calc").equal?(obj) ? 1 : 0 }

      assert_equal 1, @db.get_first_value("SELECT [same_object?](make_pointer())")
    end

    def test_function_result_pointer_is_null_as_a_column
      @db.define_function("make_pointer") { SQLite3::Pointer.new(Object.new, "calc") }

      assert_nil @db.get_first_value("SELECT make_pointer()")
      assert_equal "null", @db.get_first_value("SELECT typeof(make_pointer())")
    end

    def test_type_mismatch_never_returns_an_object
      obj = Object.new
      ptr = SQLite3::Pointer.new(obj, "calc")

      assert_same obj, ptr.fetch("calc")
      assert_same obj, ptr.fetch(:calc)
      assert_nil ptr.fetch("other")
      assert_nil ptr.fetch(:other)

      @db.define_function("wrong_tag") { |arg| arg.fetch("other") }
      stmt = @db.prepare("SELECT wrong_tag(?)")
      stmt.bind_pointer(1, ptr)

      assert_nil stmt.execute!.to_a.first.first
    ensure
      stmt.close
    end

    def test_reset_keeps_pointer_binding
      obj = Object.new
      seen = []
      @db.define_function("capture") { |arg| seen << arg; 1 }

      stmt = @db.prepare("SELECT capture(?)")
      ptr = SQLite3::Pointer.new(obj, "calc")
      stmt.bind_pointer(1, ptr)

      stmt.execute!
      stmt.reset!
      refute ptr.released?
      stmt.execute!

      assert_equal 2, seen.length
      assert_same obj, seen.last.fetch("calc")
    ensure
      stmt.close
    end

    def test_rebinding_releases_previous_pointer
      stmt = @db.prepare("SELECT ?")
      old_ptr = SQLite3::Pointer.new(Object.new, "calc")
      new_ptr = SQLite3::Pointer.new(Object.new, "calc")

      stmt.bind_pointer(1, old_ptr)
      refute old_ptr.released?

      stmt.bind_pointer(1, new_ptr)
      assert old_ptr.released?
      refute new_ptr.released?

      stmt.bind_param(1, nil)
      assert new_ptr.released?
    ensure
      stmt.close
    end

    def test_clear_bindings_releases_pointer
      stmt = @db.prepare("SELECT ?")
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt.bind_pointer(1, ptr)

      stmt.clear_bindings!

      assert ptr.released?
    ensure
      stmt.close
    end

    def test_statement_close_releases_pointer
      stmt = @db.prepare("SELECT ?")
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt.bind_pointer(1, ptr)

      stmt.close

      assert ptr.released?
    end

    def test_pointer_shared_between_statements_releases_last
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt1 = @db.prepare("SELECT ?")
      stmt2 = @db.prepare("SELECT ?")
      stmt1.bind_pointer(1, ptr)
      stmt2.bind_pointer(1, ptr)

      stmt1.close
      refute ptr.released?

      stmt2.close
      assert ptr.released?
    end

    def test_rebinding_same_wrapper_keeps_it_alive
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt = @db.prepare("SELECT ?")
      stmt.bind_pointer(1, ptr)
      stmt.bind_pointer(1, ptr) # releases the first binding, holds the second

      refute ptr.released?

      stmt.close
      assert ptr.released?
    end

    def test_database_close_then_statement_close_releases_pointer
      db = SQLite3::Database.new(":memory:")
      stmt = db.prepare("SELECT ?")
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt.bind_pointer(1, ptr)

      db.close
      refute ptr.released?
      stmt.close
      assert ptr.released?
    end

    def test_statement_gc_releases_pointer
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      bind_and_drop(ptr)
      GC.start

      assert ptr.released?
    end

    def test_result_pointer_released_after_statement_reset
      holder = []
      @db.define_function("make_pointer") do
        SQLite3::Pointer.new(Object.new, "calc").tap { |ptr| holder << ptr }
      end

      stmt = @db.prepare("SELECT make_pointer()")
      stmt.step
      refute holder[0].released?

      stmt.reset!
      assert holder[0].released?
    ensure
      stmt.close
    end

    def test_released_bound_pointer_is_collectable
      weak_ptr = nil
      weak_obj = nil

      stmt = @db.prepare("SELECT ?")
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      weak_ptr = WeakRef.new(ptr)
      weak_obj = WeakRef.new(ptr.fetch("calc"))
      stmt.bind_pointer(1, ptr)
      stmt.close
      ptr = nil

      assert_equal 1, SQLite3::Pointer.prune_released!
      GC.start

      refute weak_ptr.weakref_alive?
      refute weak_obj.weakref_alive?
    end

    def test_released_result_pointer_is_collectable
      weak_obj = nil
      @db.define_function("make_pointer") do
        obj = Object.new
        weak_obj = WeakRef.new(obj)
        SQLite3::Pointer.new(obj, "calc")
      end

      stmt = @db.prepare("SELECT make_pointer()")
      stmt.execute!
      stmt.close
      SQLite3::Pointer.prune_released!
      GC.start

      refute weak_obj.weakref_alive?
    end

    def test_unreleased_pointer_keeps_object_alive
      weak_obj = nil
      ptr = nil
      stmt = @db.prepare("SELECT ?")
      obj = Object.new
      weak_obj = WeakRef.new(obj)
      ptr = SQLite3::Pointer.new(obj, "calc")
      stmt.bind_pointer(1, ptr)
      obj = nil
      GC.start

      assert weak_obj.weakref_alive?
      assert_same weak_obj.__getobj__, ptr.fetch("calc")
    ensure
      stmt.close
    end

    def test_prune_is_idempotent
      stmt = @db.prepare("SELECT ?")
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt.bind_pointer(1, ptr)
      stmt.close

      assert_equal 1, SQLite3::Pointer.prune_released!
      assert_equal 0, SQLite3::Pointer.prune_released!
      assert ptr.released?
      GC.start
      assert_equal 0, SQLite3::Pointer.prune_released!
    end

    def test_pointer_retain_prunes_earlier_releases
      stmt = @db.prepare("SELECT ?")
      ptr = SQLite3::Pointer.new(Object.new, "calc")
      stmt.bind_pointer(1, ptr)
      stmt.close

      # binding a new pointer prunes the released one as a side effect
      stmt2 = @db.prepare("SELECT ?")
      stmt2.bind_pointer(1, Object.new, "calc")
      assert_equal 0, SQLite3::Pointer.prune_released!
    ensure
      stmt2.close
    end

    private

    def bind_and_drop(ptr)
      stmt = @db.prepare("SELECT ?")
      stmt.bind_pointer(1, ptr)
      stmt = nil
    end
  end
end
