# frozen_string_literal: true
require_relative "spec_helper"

# Shared specs run against both the sharded single-threaded pool and the
# sharded multi-threaded pool.  Both must route the same way; only the
# concurrency-context storage differs.
read_after_write_specs = Module.new do
  extend Minitest::Spec::DSL

  it "should use the read_only server for reads outside the scope" do
    @db[:t].all
    @db.sqls.must_equal ["SELECT * FROM t -- read_only"]
  end

  it "should use read_only for reads before the first write, then primary" do
    @db.with_read_after_write do
      @db[:t].all
      @db[:t].insert
      @db[:t].all
      @db[:t].update(:a => 1)
      @db[:t].all
      @db[:t].delete
      @db[:t].all
    end
    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "UPDATE t SET a = 1",
      "SELECT * FROM t",
      "DELETE FROM t",
      "SELECT * FROM t",
    ]
  end

  it "should restore automatic read routing after leaving the scope" do
    @db.with_read_after_write do
      @db[:t].insert
      @db[:t].all
    end
    @db[:t].all
    @db.sqls.must_equal ["INSERT INTO t DEFAULT VALUES", "SELECT * FROM t", "SELECT * FROM t -- read_only"]
  end

  it "should not override a server explicitly chosen on the dataset" do
    @db.with_read_after_write do
      @db[:t].insert
      @db[:t].server(:read_only).all
      @db[:t].server(:b).all
      @db[:t].server(:default).all
      @db[:t].all
    end
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- b",
      "SELECT * FROM t",
      "SELECT * FROM t",
    ]
  end

  it "should keep reads on read_only when the scope never writes" do
    @db.with_read_after_write do
      @db[:t].all
    end
    @db[:t].all
    @db.sqls.must_equal ["SELECT * FROM t -- read_only", "SELECT * FROM t -- read_only"]
  end

  it "should record the failed write statement but not pin later reads" do
    @db.with_read_after_write do
      @db[:t].all
      begin
        @db[:t].with_numrows(StandardError).update(:a => 1)
      rescue Sequel::DatabaseError
      end
      @db[:t].all
    end
    @db.sqls.must_equal ["SELECT * FROM t -- read_only", "UPDATE t SET a = 1", "SELECT * FROM t -- read_only"]
  end

  it "should pin later reads after a successful write following a failed write" do
    @db.with_read_after_write do
      begin
        @db[:t].with_numrows(StandardError).delete
      rescue Sequel::DatabaseError
      end
      @db[:t].all
      @db[:t].insert
      @db[:t].all
    end
    @db.sqls.must_equal [
      "DELETE FROM t",
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
    ]
  end

  it "should restore routing even when the block raises" do
    proc do
      @db.with_read_after_write do
        @db[:t].insert
        @db[:t].all
        raise "boom"
      end
    end.must_raise(RuntimeError)
    @db[:t].all
    @db.sqls.must_equal ["INSERT INTO t DEFAULT VALUES", "SELECT * FROM t", "SELECT * FROM t -- read_only"]
  end

  it "should route a read in a nested transaction to the primary after a write" do
    @db.with_read_after_write do
      @db.transaction do
        @db[:t].insert
        @db.transaction(:savepoint => true) do
          @db[:t].update(:a => 2)
          @db[:t].all
        end
        @db[:t].all
      end
    end
    @db.sqls.must_equal [
      "BEGIN",
      "INSERT INTO t DEFAULT VALUES",
      "SAVEPOINT autopoint_1",
      "UPDATE t SET a = 2",
      "SELECT * FROM t",
      "RELEASE SAVEPOINT autopoint_1",
      "SELECT * FROM t",
      "COMMIT",
    ]
  end

  it "should keep reads pinned when an inner savepoint is rolled back" do
    @db.with_read_after_write do
      @db.transaction do
        @db[:t].insert
        @db.transaction(:savepoint => true) do
          @db[:t].update(:a => 2)
          raise Sequel::Rollback
        end rescue nil
        @db[:t].all
      end
      @db[:t].all
    end
    @db.sqls.must_equal [
      "BEGIN",
      "INSERT INTO t DEFAULT VALUES",
      "SAVEPOINT autopoint_1",
      "UPDATE t SET a = 2",
      "ROLLBACK TO SAVEPOINT autopoint_1",
      "SELECT * FROM t",
      "COMMIT",
      "SELECT * FROM t",
    ]
  end

  it "should keep reads pinned to primary after an entire transaction rolls back" do
    @db.with_read_after_write do
      begin
        @db.transaction do
          @db[:t].insert
          @db[:t].all
          raise Sequel::Rollback
        end
      rescue Sequel::Rollback
      end
      @db[:t].all
    end
    @db[:t].all
    @db.sqls.must_equal [
      "BEGIN",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "ROLLBACK",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should work with server_block regardless of extension load order" do
    @db = Sequel.mock(:servers => {:read_only => {}, :a => {}, :a_ro => {}})
    @db.extension :read_after_write
    @db.extension :server_block

    @db.with_read_after_write do
      @db.with_server(:a, :a_ro) do
        @db[:t].insert
        @db[:t].all
      end
    end
    @db.sqls.must_equal ["INSERT INTO t DEFAULT VALUES -- a", "SELECT * FROM t -- a"]
  end

  it "should not pin reads when a write fails and the whole transaction rolls back" do
    @db.with_read_after_write do
      begin
        @db.transaction do
          @db[:t].all
          @db[:t].with_numrows(StandardError).update(:a => 1)
        end
      rescue Sequel::DatabaseError
      end
      @db[:t].all
    end
    @db.sqls.must_equal [
      "BEGIN",
      "SELECT * FROM t -- read_only",
      "UPDATE t SET a = 1",
      "ROLLBACK",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should inherit the written state through nested scopes and restore at the outermost" do
    @db.with_read_after_write do
      @db[:t].all
      @db.with_read_after_write do
        @db[:t].all
        @db[:t].insert
        @db[:t].all
      end
      @db[:t].all
    end
    @db[:t].all
    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should not leak an inner scope's routing when it did not write" do
    @db.with_read_after_write do
      @db.with_read_after_write do
        @db[:t].all
      end
      @db[:t].all
      @db[:t].insert
      @db.with_read_after_write do
        @db[:t].all
      end
    end
    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
    ]
  end

  it "should treat DDL and run as writes" do
    @db.with_read_after_write do
      @db.run("CREATE TABLE x (id integer)")
      @db[:t].all
      @db.run("CREATE TABLE y (id integer)")
      @db[:t].all
    end
    @db.sqls.must_equal [
      "CREATE TABLE x (id integer)",
      "SELECT * FROM t",
      "CREATE TABLE y (id integer)",
      "SELECT * FROM t",
    ]
  end
end

describe "read_after_write extension with sharded single-threaded pool" do
  before do
    @db = Sequel.mock(:single_threaded => true, :servers => {:read_only => {}, :b => {}})
    @db.extension :read_after_write
  end

  include read_after_write_specs
end

describe "read_after_write extension with sharded threaded pool" do
  before do
    @db = Sequel.mock(:servers => {:read_only => {}, :b => {}})
    @db.extension :read_after_write
  end

  include read_after_write_specs

  it "should route post-write reads to the write shard inside a with_server block" do
    @db = Sequel.mock(:servers => {:read_only => {}, :a => {}, :a_ro => {}, :b => {}})
    @db.extension :server_block
    @db.extension :read_after_write

    @db.with_read_after_write do
      @db.with_server(:a, :a_ro) do
        @db[:t].all
        @db[:t].insert
        @db[:t].all
        @db[:t].server(:a_ro).all
        @db[:t].server(:b).all
      end
    end
    @db[:t].all
    @db.sqls.must_equal [
      "SELECT * FROM t -- a_ro",
      "INSERT INTO t DEFAULT VALUES -- a",
      "SELECT * FROM t -- a",
      "SELECT * FROM t -- a_ro",
      "SELECT * FROM t -- b",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should isolate written state between threads" do
    q, q1 = Queue.new, Queue.new
    t = nil

    @db[:t].all
    @db.with_read_after_write do
      @db[:t].insert
      @db[:t].all

      t = Thread.new do
        @db[:t].all
        @db.with_read_after_write do
          @db[:t].all
          @db[:t].insert
          @db[:t].all
          q.push(nil)
          q1.pop
          @db[:t].all
        end
        @db[:t].all
      end

      q.pop
      @db[:t].all
    end
    q1.push(nil)
    @db[:t].all
    t.join

    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end
end

describe "read_after_write extension with fiber concurrency" do
  before do
    @original_current = Sequel.method(:current)
    Sequel.extension :fiber_concurrency
    @db = Sequel.mock(:servers => {:read_only => {}, :b => {}})
    @db.extension :read_after_write
  end

  after do
    Sequel.define_singleton_method(:current, @original_current)
  end

  it "should isolate written state between fibers" do
    f = Fiber.new do
      Fiber.yield
      @db[:t].all
      @db.with_read_after_write do
        @db[:t].insert
        @db[:t].all
        Fiber.yield
        @db[:t].all
      end
      @db[:t].all
    end

    # f suspends before issuing any query.
    f.resume
    # Main fiber: no scope yet, reads go to the replica.
    @db[:t].all
    # Main fiber writes in its own scope, pinning only the main fiber.
    @db.with_read_after_write do
      @db[:t].insert
      @db[:t].all
      # f has no scope, so its read goes to the replica, then it writes
      # inside its own scope and suspends.
      f.resume
      # Main fiber is still pinned.
      @db[:t].all
    end
    # Outside the main scope, resume f: the read in f's scope uses the
    # primary, since only f's scope has written.
    f.resume

    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end
end

describe "read_after_write extension with a non-sharded database" do
  before do
    @db = Sequel.mock
    @db.extension :read_after_write
  end

  it "should be a no-op and keep all queries on the default server" do
    @db.with_read_after_write do
      @db[:t].all
      @db[:t].insert
      @db[:t].all
    end
    @db[:t].all
    @db.sqls.must_equal [
      "SELECT * FROM t",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t",
    ]
  end
end
