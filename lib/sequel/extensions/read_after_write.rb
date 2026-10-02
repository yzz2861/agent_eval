# frozen-string-literal: true
#
# The read_after_write extension adds an explicit scope inside which, after
# the first successful write, all subsequent reads are routed to the primary
# (:default) server instead of a read-only replica.  This provides read-your
# -writes consistency for a single business operation without having to pin
# every query to the primary explicitly:
#
#   DB = Sequel.connect('postgres://primary/db',
#     servers: {read_only: {host: 'replica'}})
#   DB.extension :read_after_write
#
#   DB.with_read_after_write do
#     DB[:accounts].where(id: 1).update(balance: 100) # primary
#     DB[:accounts].where(id: 1).get(:balance)        # primary
#   end
#   DB[:accounts].where(id: 1).get(:balance)          # replica again
#
# Only reads whose server is chosen automatically are affected.  A server
# explicitly requested by the caller always wins:
#
#   DB.with_read_after_write do
#     DB[:accounts].insert # primary
#     DB[:accounts].all                     # primary (automatic read)
#     DB[:accounts].server(:read_only).all  # replica (explicit)
#     DB[:accounts].server(:other).all      # :other (explicit)
#   end
#
# A write marks the scope as having written only if it succeeds.  A write
# that raises an exception does not pin later reads, and the flag remains
# pinned for the rest of the scope after a successful write.  This keeps the
# following cases independent:
#
# * A nested transaction (a transaction joined via savepoint or reusing the
#   connection) does not reset the flag, so reads after a write anywhere in
#   the surrounding business operation use the primary.
# * Rolling back an inner savepoint does not clear the flag set by a write
#   before the savepoint, and a successful write outside a rolled back
#   savepoint still pins later reads.  The uncommitted write inside the
#   savepoint is gone, but reading from the primary remains safe.
# * Rolling back an entire transaction also does not clear the flag.  A
#   later read still goes to the primary, where the application can observe
#   the committed state (possibly the state from before the transaction).
# * A write that raises before it succeeds never sets the flag, so later
#   reads continue to use the read-only replica.
#
# Scopes nest.  An inner scope inherits the written state of the scopes
# enclosing it, and a successful write in an inner scope propagates to all
# enclosing scopes, so reads stay on the primary until the outermost scope
# exits, at which point automatic read routing is restored:
#
#   DB.with_read_after_write do
#     DB[:t].all # replica
#     DB.with_read_after_write do
#       DB[:t].insert # primary
#       DB[:t].all    # primary
#     end
#     DB[:t].all # primary (inherited from the inner successful write)
#   end
#   DB[:t].all # replica
#
# The written state is stored per concurrency context (using Sequel.current,
# which is Thread.current by default and Fiber.current with the
# fiber_concurrency extension), so threads and fibers do not affect each
# other.
#
# This extension works with the sharded single, threaded, and timed_queue
# connection pools.  On a non-sharded database it has no effect (all queries
# already use the single default server).
#
# Related modules: Sequel::ReadAfterWrite, Sequel::UnthreadedReadAfterWrite,
# Sequel::ThreadedReadAfterWrite

module Sequel
  module ReadAfterWrite
    # Extend the connection pool with read-after-write scope support, using
    # the threaded or unthreaded implementation depending on the pool type,
    # and make all datasets honor the scope when choosing the read server.
    def self.extended(db)
      pool = db.pool
      if pool.respond_to?(:pick_server, true)
        case pool.pool_type
        when :sharded_threaded, :sharded_timed_queue
          pool.extend(ThreadedReadAfterWrite)
          pool.instance_variable_set(:@read_after_write_scopes, {})
        when :sharded_single
          pool.extend(UnthreadedReadAfterWrite)
          pool.instance_variable_set(:@read_after_write_scopes, [])
        end
      end

      db.extend_datasets(DatasetMethods)
    end

    # Run the block inside a read-after-write scope.  After the first
    # successful write inside the block, automatic reads use the primary
    # (:default) server until the block returns.  Explicit server choices
    # are respected regardless of the scope.
    def with_read_after_write(&block)
      if sharded?
        pool.with_read_after_write_scope(&block)
      else
        yield
      end
    end

    # After a successful write during an active scope on this database,
    # record that the current concurrency context has written, so that
    # subsequent automatic reads route to the primary.  Write failures
    # (raised exceptions) do not call this.
    def execute_dui(sql, opts=OPTS, &block)
      ret = super
      pool.mark_read_after_write if sharded?
      ret
    end

    # DDL statements are writes, so mark the scope on success.
    def execute_ddl(sql, opts=OPTS, &block)
      ret = super
      pool.mark_read_after_write if sharded?
      ret
    end

    # INSERT statements are writes, so mark the scope on success.
    def execute_insert(sql, opts=OPTS, &block)
      ret = super
      pool.mark_read_after_write if sharded?
      ret
    end

    module DatasetMethods
      # For SELECTs (which use the :read_only server by default), request
      # the primary when the dataset does not specify an explicit server and
      # the current scope has already written.  An internal sentinel is used
      # instead of :default so that server_block (which intentionally
      # overrides :default) can route the read to the block's write shard.
      # Datasets with an explicit server (including .server(:read_only)) are
      # left untouched, so explicit caller choices always take precedence.
      def execute(sql, opts=OPTS, &block)
        if db.sharded? && !opts.has_key?(:server) && !@opts[:server] &&
           db.pool.read_after_write?
          opts = Hash[opts]
          opts[:server] = READ_AFTER_WRITE_PRIMARY
        end
        super
      end
    end
  end

  # Read-after-write scope support for the sharded single connection pool.
  # The scope stack is plain instance state, which is safe because the pool
  # is only used by a single thread.
  module UnthreadedReadAfterWrite
    # Enter a new scope, inheriting whether an enclosing scope has written.
    def with_read_after_write_scope
      scopes = @read_after_write_scopes
      scopes << (scopes.empty? ? false : scopes[-1])
      yield
    ensure
      # The written state propagates outward after a successful inner write,
      # so update the new outer frame before discarding the popped one.
      written = scopes.pop
      scopes[-1] = true if written && !scopes.empty?
    end

    # Whether the current scope (or an enclosing scope) has already written.
    def read_after_write?
      !@read_after_write_scopes.empty? && @read_after_write_scopes[-1] == true
    end

    # Mark the current scope and all enclosing scopes as having written.
    def mark_read_after_write
      @read_after_write_scopes.length.times { |i| @read_after_write_scopes[i] = true }
      nil
    end
  end

  # Read-after-write scope support for the sharded threaded and timed_queue
  # connection pools.  The scope stacks are stored per concurrency context
  # (Sequel.current), keeping threads (and fibers with fiber_concurrency)
  # isolated from each other.
  module ThreadedReadAfterWrite
    # Enter a new scope for the current concurrency context, inheriting
    # whether an enclosing scope in the same context has written.
    def with_read_after_write_scope
      stack = sync { (@read_after_write_scopes[Sequel.current] ||= []) }
      stack << (stack.empty? ? false : stack[-1])
      yield
    ensure
      written = stack.pop
      if stack.empty?
        sync { @read_after_write_scopes.delete(Sequel.current) }
      elsif written
        stack[-1] = true
      end
    end

    # Whether the current concurrency context's scope (or an enclosing one)
    # has already written.
    def read_after_write?
      stack = sync { @read_after_write_scopes[Sequel.current] }
      !stack.nil? && !stack.empty? && stack[-1] == true
    end

    # Mark the current concurrency context's scope and all of its enclosing
    # scopes as having written.  Other contexts are unaffected.
    def mark_read_after_write
      stack = sync { @read_after_write_scopes[Sequel.current] }
      stack.length.times { |i| stack[i] = true } if stack
      nil
    end
  end

  Database.register_extension(:read_after_write, ReadAfterWrite)
end
