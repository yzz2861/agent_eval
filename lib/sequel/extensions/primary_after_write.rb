# frozen-string-literal: true
#
# The primary_after_write extension adds Database#with_primary_on_write.
# Inside the passed block, automatically routed reads issued after the
# first successful write use the primary (+:default+ server) instead of
# a replica (+:read_only+ server):
#
#   DB.extension :primary_after_write
#
#   DB.with_primary_on_write do
#     DB[:items].all               # Uses the :read_only server
#     DB[:items].insert(name: 'A')   # Uses the :default server and pins the scope
#     DB[:items].where(id: 1).all    # Uses the :default server
#   end
#   DB[:items].all                 # Uses the :read_only server again
#
# Only the completion of a successful write pins the scope.  If a
# write raises, the scope is not pinned, so reads performed while
# handling the exception continue to use the replica.
#
# Blocks can be nested.  A new scope inherits the state of the
# enclosing scope: if a write has already happened, reads in the new
# scope use the primary before it performs a write of its own.  A
# successful write in an inner scope also pins all enclosing scopes,
# so reads remain on the primary after the inner block exits:
#
#   DB.with_primary_on_write do
#     DB.with_primary_on_write do
#       DB[:items].insert(name: 'A')
#       DB[:items].all  # Uses the :default server
#     end
#     DB[:items].all    # Uses the :default server
#   end
#
# A write followed by a rollback was still issued to the primary, so
# the scope stays pinned.  Ordinary transactions, savepoint rollbacks
# in nested transactions, and a rollback of the whole transaction are
# treated the same; transaction and savepoint state is not inspected.
# A write that raises is different and does not pin the scope.
#
# An explicitly specified server always takes precedence, whether it
# names a concrete shard/replica or one of +:default+ and +:read_only+:
#
#   DB.with_primary_on_write do
#     DB[:items].insert(name: 'A')
#     DB[:items].server(:other).all   # Uses :other
#     DB[:items].server(:read_only).all # Uses :read_only
#   end
#
# With the server_block extension, a write in a shard block pins
# subsequent automatic reads to that shard's primary.
#
# Scope state is isolated per thread, and per fiber when the
# fiber_concurrency extension is enabled before the pool is created.
#
# This extension requires a sharded connection pool.
#
# Related modules: Sequel::PrimaryAfterWrite,
# Sequel::PrimaryAfterWriteDatasetMethods,
# Sequel::UnthreadedPrimaryAfterWrite,
# Sequel::ThreadedPrimaryAfterWrite

module Sequel
  module PrimaryAfterWrite
    # Extend the pool with the behavior appropriate for its pool type,
    # and make all of the database's datasets aware of the scope.
    def self.extended(db)
      pool = db.pool
      case pool.pool_type
      when :sharded_threaded, :sharded_timed_queue
        pool.extend(ThreadedPrimaryAfterWrite)
        pool.send(:initialize_primary_after_write_state)
      else
        pool.extend(UnthreadedPrimaryAfterWrite)
        pool.send(:initialize_primary_after_write_state)
      end
      db.extend_datasets(PrimaryAfterWriteDatasetMethods)
    end

    # Run the block with read-after-write routing: after the first
    # successful write inside the block, automatically routed reads use
    # the primary for the remainder of the block.
    def with_primary_on_write(&block)
      pool.with_primary_on_write(&block)
    end

    # DDL and raw queries issued through Database#run are writes too.
    def execute_ddl(sql, opts=OPTS, &block)
      _primary_after_write(sql, opts){super}
    end

    # UPDATE/DELETE are writes.
    def execute_dui(sql, opts=OPTS, &block)
      _primary_after_write(sql, opts){super}
    end

    # INSERT is a write.
    def execute_insert(sql, opts=OPTS, &block)
      _primary_after_write(sql, opts){super}
    end

    private

    # Datasets fill in +:default+ for implicitly routed writes on a
    # sharded database, while writes issued another way leave +:server+
    # unset.  A concrete explicit server is the caller's choice and
    # does not pin automatic reads.
    def _primary_after_write_auto_routed?(server)
      server.nil? || server == :default
    end

    # Run the write, and mark the scope as written only after it
    # completes without raising.  Resolve the server through the pool
    # so routing extensions such as server_block can map the write to
    # the actual shard primary used.
    def _primary_after_write(sql, opts)
      result = yield
      server = opts[:server]
      if _primary_after_write_auto_routed?(server)
        pool.primary_after_write!(server || :default)
      end
      result
    end
  end

  # Redirects automatically routed reads once the active scope has
  # seen a successful write.  Explicit Dataset#server calls leave
  # +:server+ in the options, so they are left unchanged.
  module PrimaryAfterWriteDatasetMethods
    private

    # Reads fill in +:read_only+ here when no server is set.  Replace
    # it with +:default+ when the current scope is pinned, then let the
    # pool (and extensions such as server_block) resolve it.
    def execute(sql, opts=OPTS, &block)
      if db.sharded? && !opts.has_key?(:server) && !@opts[:server] &&
         @db.pool.primary_after_write_active_server
        opts = Hash[opts]
        opts[:server] = :default
      end
      super(sql, opts, &block)
    end
  end

  # Scope state for the sharded single connection pool.
  module UnthreadedPrimaryAfterWrite
    # Enter a scope.  Each entry is the primary server implicit reads
    # must use after a successful write, or nil before such a write.
    def with_primary_on_write
      @primary_after_write_scopes << @primary_after_write_scopes[-1]
      yield
    ensure
      @primary_after_write_scopes.pop
    end

    # Record a successful write that selected +server+, and pin the
    # active and all enclosing scopes to the resolved primary.
    def primary_after_write!(server)
      # Resolve through the pool so server_block can map a write's
      # +:default+ placeholder to the shard primary.  Writes never
      # use +:read_only+, so the dataset redirection is not involved.
      server = pick_server(server)
      @primary_after_write_scopes.each_index do |i|
        @primary_after_write_scopes[i] = server
      end
    end

    # The primary server automatic reads in the active scope must use,
    # or nil when no successful write has occurred.
    def primary_after_write_active_server
      @primary_after_write_scopes[-1]
    end

    private

    def initialize_primary_after_write_state
      @primary_after_write_scopes = []
    end
  end

  # Scope state for the sharded threaded and timed queue connection
  # pools, keyed by the current concurrency primitive (Thread or
  # Fiber).
  module ThreadedPrimaryAfterWrite
    # Enter a scope for the current thread or fiber.
    def with_primary_on_write
      scopes = nil
      sync do
        scopes = (@primary_after_write_scopes[Sequel.current] ||= [])
        scopes << scopes[-1]
      end
      yield
    ensure
      sync do
        if scopes
          scopes.pop
          @primary_after_write_scopes.delete(Sequel.current) if scopes.empty?
        end
      end
    end

    # Record a successful write that selected +server+, and pin the
    # active and all enclosing scopes for this thread or fiber to the
    # resolved primary.
    def primary_after_write!(server)
      # Writes never use +:read_only+, so this does not recurse into
      # read redirection.  The pool's pick_server is safe to call here;
      # doing it before the mutex avoids holding it during another pool
      # sync, and allows extensions such as server_block to map the
      # write's shard.
      server = pick_server(server)
      sync do
        scopes = @primary_after_write_scopes[Sequel.current]
        scopes&.each_index{|i| scopes[i] = server}
      end
    end

    # The primary server automatic reads in the active scope must use,
    # or nil when no successful write has occurred.
    def primary_after_write_active_server
      sync do
        scopes = @primary_after_write_scopes[Sequel.current]
        scopes && scopes[-1]
      end
    end

    private

    def initialize_primary_after_write_state
      @primary_after_write_scopes = {}
    end
  end

  Database.register_extension(:primary_after_write, PrimaryAfterWrite)
end
