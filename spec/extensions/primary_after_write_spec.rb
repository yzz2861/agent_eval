# frozen_string_literal: true
require_relative "spec_helper"

with_primary_after_write = Module.new do
  extend Minitest::Spec::DSL

  def run_queries
    @db[:t].all
    @db[:t].insert
    @db[:t].all
    @db[:t].update(:a=>1)
    @db[:t].delete
    @db[:t].all
    @db.sqls
  end

  def select_sqls(sqls)
    sqls.grep(/\ASELECT/)
  end

  it "should route reads to the replica before the first write and the primary after it" do
    @db.with_primary_on_write do
      run_queries.must_equal [
        "SELECT * FROM t -- read_only",
        "INSERT INTO t DEFAULT VALUES",
        "SELECT * FROM t",
        "UPDATE t SET a = 1",
        "DELETE FROM t",
        "SELECT * FROM t",
      ]
    end
  end

  it "should restore replica routing when leaving the scope" do
    @db.with_primary_on_write do
      @db[:t].insert
      @db[:t].all
    end
    @db[:t].all
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should keep reads on the replica when no write is performed in the scope" do
    @db.with_primary_on_write do
      @db[:t].all
      @db[:t].all
    end
    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should restore the outer state when a write-free inner scope exits" do
    @db.with_primary_on_write do
      @db[:t].all
      @db.with_primary_on_write do
        @db[:t].all
      end
      @db[:t].all
    end
    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should inherit a written state into a newly entered scope" do
    @db.with_primary_on_write do
      @db[:t].insert
      @db.with_primary_on_write do
        @db[:t].all
      end
    end
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
    ]
  end

  it "should keep enclosing scopes on the primary after an inner write" do
    @db.with_primary_on_write do
      @db[:t].all
      @db.with_primary_on_write do
        @db[:t].all
        @db[:t].insert
        @db[:t].all
      end
      @db[:t].all
      @db.with_primary_on_write do
        @db[:t].all
      end
    end
    @db[:t].all
    @db.sqls.must_equal [
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should not pin reads when a write raises" do
    @db.autoid = proc{|sql| raise Sequel::DatabaseError, "boom"}
    proc do
      @db.with_primary_on_write do
        begin
          @db[:t].insert
        rescue Sequel::DatabaseError
        end
        @db[:t].all
      end
    end.must_be_silent
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should restore routing when a scope unwinds due to an exception" do
    raised = false
    begin
      @db.with_primary_on_write do
        @db[:t].insert
        @db[:t].all
        raise ArgumentError, "boom"
      end
    rescue ArgumentError
      raised = true
    end
    raised.must_equal true
    @db[:t].all
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should keep reads on the primary after a rolled back savepoint" do
    @db.with_primary_on_write do
      @db.transaction do
        @db[:t].insert
        begin
          @db.transaction(:savepoint=>true) do
            @db[:t].update(:a=>1)
            raise Sequel::Rollback
          end
        rescue Sequel::Rollback
        end
        @db[:t].all
      end
      @db[:t].all
    end
    selects = select_sqls(@db.sqls)
    selects.wont_include "SELECT * FROM t -- read_only"
    selects.must_equal ["SELECT * FROM t", "SELECT * FROM t"]
  end

  it "should keep reads on the primary after a committed savepoint in a nested transaction" do
    @db.with_primary_on_write do
      @db.transaction do
        @db[:t].insert
        @db.transaction(:savepoint=>true) do
          @db[:t].update(:a=>1)
        end
        @db[:t].all
      end
      @db[:t].all
    end
    selects = select_sqls(@db.sqls)
    selects.wont_include "SELECT * FROM t -- read_only"
    selects.must_equal ["SELECT * FROM t", "SELECT * FROM t"]
  end

  it "should keep reads on the primary after a committed nested transaction without a savepoint" do
    @db.with_primary_on_write do
      @db.transaction do
        @db[:t].insert
        @db.transaction do
          @db[:t].update(:a=>1)
        end
        @db[:t].all
      end
      @db[:t].all
    end
    selects = select_sqls(@db.sqls)
    selects.wont_include "SELECT * FROM t -- read_only"
    selects.must_equal ["SELECT * FROM t", "SELECT * FROM t"]
  end

  it "should keep reads on the primary after a full transaction rollback" do
    @db.with_primary_on_write do
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
    selects = select_sqls(@db.sqls)
    selects.wont_include "SELECT * FROM t -- read_only"
    selects.must_equal ["SELECT * FROM t", "SELECT * FROM t"]
  end

  it "should not pin reads when a write raises inside a transaction" do
    @db.autoid = proc{|sql| raise Sequel::DatabaseError, "boom"}
    @db.with_primary_on_write do
      begin
        @db.transaction do
          @db[:t].insert
        end
      rescue Sequel::DatabaseError
      end
      @db[:t].all
    end
    select_sqls(@db.sqls).must_equal ["SELECT * FROM t -- read_only"]
  end

  it "should not override an explicitly specified read server" do
    @db.with_primary_on_write do
      @db[:t].insert
      @db[:t].server(:b).all
      @db[:t].server(:b).all
    end
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t -- b",
      "SELECT * FROM t -- b",
    ]
  end

  it "should respect an explicit read_only server after a write" do
    @db.with_primary_on_write do
      @db[:t].insert
      @db[:t].server(:read_only).all
      @db[:t].all
    end
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t",
    ]
  end

  it "should not pin on a write sent to an explicitly specified server" do
    @db.with_primary_on_write do
      @db[:t].server(:b).insert
      @db[:t].all
    end
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES -- b",
      "SELECT * FROM t -- read_only",
    ]
  end

  it "should pin subsequent reads to the primary after a raw write" do
    @db.with_primary_on_write do
      @db.run("UPDATE t SET a = 1")
      @db[:t].all
    end
    @db.sqls.must_equal [
      "UPDATE t SET a = 1",
      "SELECT * FROM t",
    ]
  end
end

describe "Database#with_primary_on_write single threaded" do
  before do
    @db = Sequel.mock(:single_threaded=>true, :servers=>{:read_only=>{}, :b=>{}})
    @db.extension :primary_after_write
  end

  include with_primary_after_write
end

describe "Database#with_primary_on_write multi threaded" do
  before do
    @db = Sequel.mock(:servers=>{:read_only=>{}, :b=>{}})
    @db.extension :primary_after_write
  end

  include with_primary_after_write

  it "should isolate scope state between threads" do
    q, q1 = Queue.new, Queue.new
    t = nil
    @db.with_primary_on_write do
      @db[:t].insert
      @db[:t].all
      t = Thread.new do
        @db[:t].all
        @db.with_primary_on_write do
          @db[:t].all
          @db[:t].insert
          @db[:t].all
          q.push nil
          q1.pop
          @db[:t].all
        end
        @db[:t].all
      end
      q.pop
      @db[:t].all
    end
    @db[:t].all
    q1.push nil
    t.join
    @db.sqls.must_equal [
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
  end unless RUBY_ENGINE == "jruby" && Fiber.new{Thread.current}.resume == Thread.current
end

describe "Database#with_primary_on_write fiber isolation" do
  before do
    @original_sequel_current = Sequel.method(:current)
    Sequel.extension :fiber_concurrency
    @db = Sequel.mock(:servers=>{:read_only=>{}})
    @db.extension :primary_after_write
  end

  after do
    orig = @original_sequel_current
    Sequel.define_singleton_method(:current){orig.call}
  end

  it "should isolate scope state between fibers in the same thread" do
    f = nil
    @db.with_primary_on_write do
      @db[:t].insert
      @db[:t].all
      f = Fiber.new do
        @db[:t].all
        @db.with_primary_on_write do
          @db[:t].all
          Fiber.yield
          @db[:t].insert
          @db[:t].all
        end
        @db[:t].all
      end
      f.resume
      @db[:t].all
      f.resume
    end
    @db[:t].all
    @db.sqls.must_equal [
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t",
      "INSERT INTO t DEFAULT VALUES",
      "SELECT * FROM t",
      "SELECT * FROM t -- read_only",
      "SELECT * FROM t -- read_only",
    ]
  end unless RUBY_ENGINE == "jruby" && Fiber.new{Thread.current}.resume == Thread.current
end

describe "Database#with_primary_on_write with server_block" do
  before do
    @db = Sequel.mock(:servers=>{:default=>{}, :read_only=>{}, :a=>{}, :a_read_only=>{}})
    @db.extension :server_block, :primary_after_write
  end

  it "should pin reads to the current shard's primary after a write" do
    @db.with_server(:a) do
      @db[:t].all
      @db.with_primary_on_write do
        @db[:t].all
        @db[:t].insert
        @db[:t].all
      end
      @db[:t].all
    end
    @db.sqls.must_equal [
      "SELECT * FROM t -- a",
      "SELECT * FROM t -- a",
      "INSERT INTO t DEFAULT VALUES -- a",
      "SELECT * FROM t -- a",
      "SELECT * FROM t -- a",
    ]
  end
end
