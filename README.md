connection\_pool
=================
[![Build Status](https://github.com/mperham/connection_pool/actions/workflows/ci.yml/badge.svg)](https://github.com/mperham/connection_pool/actions/workflows/ci.yml)

Generic connection pooling for Ruby.

MongoDB has its own connection pool.
ActiveRecord has its own connection pool.
This is a generic connection pool that can be used with anything, e.g. Redis, Dalli and other Ruby network clients.

Usage
-----

Create a pool of objects to share amongst the fibers or threads in your Ruby application:

``` ruby
$memcached = ConnectionPool.new(size: 5, timeout: 5) { Dalli::Client.new }
```

Then use the pool in your application:

``` ruby
$memcached.with do |conn|
  conn.get('some-count')
end
```

If all the objects in the connection pool are in use, `with` will block
until one becomes available.
If no object is available within `:timeout` seconds,
`with` will raise a `ConnectionPool::TimeoutError` (a subclass of `Timeout::Error`).

You can also use `ConnectionPool#then` to support _both_ a
connection pool and a raw client.

```ruby
# Compatible with a raw Redis::Client, and ConnectionPool Redis
$redis.then { |r| r.set 'foo' 'bar' }
```

Optionally, you can specify a timeout override:

``` ruby
$memcached.with(timeout: 2.0) do |conn|
  conn.get('some-count')
end
```

This will only modify the timeout for this particular invocation.
This is useful if you want to fail-fast on certain non-critical
sections when a resource is not available, or conversely if you are comfortable blocking longer on a particular resource.

## Migrating to a Connection Pool

You can use `ConnectionPool::Wrapper` to wrap a single global connection, making it easier to migrate existing connection code over time:

``` ruby
$redis = ConnectionPool::Wrapper.new(size: 5, timeout: 3) { Redis.new }
$redis.sadd('foo', 1)
$redis.smembers('foo')
```

The wrapper uses `method_missing` to checkout a connection, run the requested method and then immediately check the connection back into the pool.
It's **not** high-performance so you'll want to port your performance sensitive code to use `with` as soon as possible.

``` ruby
$redis.with do |conn|
  conn.sadd('foo', 1)
  conn.smembers('foo')
end
```

Once you've ported your entire system to use `with`, you can remove `::Wrapper` and use `ConnectionPool` directly.


## Shutdown

You can shut down a ConnectionPool instance once it should no longer be used.
Further checkout attempts will immediately raise an error but existing checkouts will work.

```ruby
cp = ConnectionPool.new { Redis.new }
cp.shutdown { |c| c.close }
```

Shutting down a connection pool will block until all connections are checked in and closed.
**Note that shutting down is completely optional**; Ruby's garbage collector will reclaim unreferenced pools under normal circumstances.

## Reload

You can reload a ConnectionPool instance if it is necessary to close all existing connections and continue to use the pool.
ConnectionPool will automatically reload if the process is forked.
Use `auto_reload_after_fork: false` if you don't want this behavior.

```ruby
cp = ConnectionPool.new(auto_reload_after_fork: false) { Redis.new }
cp.reload { |conn| conn.quit } # reload manually
cp.with { |conn| conn.get('some-count') }
```

Like `shutdown`, `reload` will block until all connections are checked in and closed.

## Reap

You can call `reap` periodically on the ConnectionPool instance to close connections that were created but have not been used for a certain amount of time. This can be useful in environments where connections are expensive.

You can specify how many seconds the connections have to be idle for them to be reaped, defaulting to 60 seconds.

```ruby
cp = ConnectionPool.new { Redis.new }

# Start a reaper thread to reap connections that have been
# idle more than 300 seconds (5 minutes)
Thread.new do
  loop do
    cp.reap(idle_seconds: 300, &:close)
    sleep 30
  end
end
```

## Discarding Connections

## Transferring Ownership with a Lease

Sometimes background code needs to hand a borrowed resource to another thread
for processing. Rather than passing the raw connection and agreeing informally
on who returns it, you can transfer ownership explicitly with a **lease**.

The current owner calls `pool.lease` inside its `with` block. This detaches the
connection from the owner immediately: that thread can no longer use or return
it through the pool. It then passes the returned `ConnectionPool::Lease` object
to the new owner, which receives the connection with `pool.accept`.

```ruby
queue = Thread::Queue.new

worker = Thread.new do
  lease = queue.pop
  pool.accept(lease) do |conn|
    conn.do_work
  end
end

pool.with do |conn|
  queue << pool.lease
end
```

The handoff is a rendezvous: when the owner's `with` block finishes, its checkin
blocks until another thread accepts the lease. Ownership then moves to that
thread and the connection is **not** returned to the pool; it is returned later,
exactly once, when the new owner finishes its `accept` block.

The outcomes are explicit:

- If no thread accepts the lease before `timeout` (defaults to the pool's
  `timeout`), the offer expires and the owner's checkin returns the connection
  to the pool as usual. A late `accept` raises `ConnectionPool::TimeoutError`.
- If the owning thread raises or is killed before the handoff completes, the
  offer is cancelled, the connection is returned to the pool, and a waiting
  `accept` raises `ConnectionPool::Error`.
- A lease can only be received once; a second (or losing) `accept` raises
  `ConnectionPool::LeaseError`.
- A lease must be accepted by a different thread than the one that created it.
- Transfers are not allowed inside nested checkouts, because the resource would
  have more than one possible owner. Offer the connection from a single
  `with`/`checkout` level instead.

`accept` also works without a block: it returns the connection and you must
return it yourself with `pool.checkin`.

You can discard connections in the ConnectionPool instance to remove connections that are broken and can't be repaired. 
It can only be done inside the block passed to `with`.
Takes an optional block that will be executed with the connection.

```ruby
pool.with do |conn|
  begin
    conn.execute("SELECT 1")
  rescue SomeConnectionError
    pool.discard_current_connection(&:close)  # remove the connection from the pool
    raise
  end
end
```

## Current State

There are several methods that return information about a pool.

```ruby
cp = ConnectionPool.new(size: 10) { Redis.new }
cp.size # => 10
cp.available # => 10
cp.idle # => 0

cp.with do |conn|
  cp.size # => 10
  cp.available # => 9
  cp.idle # => 0
end

cp.idle # => 1
```

## Upgrading from ConnectionPool 2

* Support for Ruby <3.2 has been removed.
* ConnectionPool's APIs now consistently use keyword arguments everywhere.
Positional arguments must be converted to keywords:
```ruby
pool = ConnectionPool.new(size: 5, timeout: 5)
pool.checkout(1) # 2.x
pool.reap(30)    # 2.x
pool.checkout(timeout: 1) # 3.x
pool.reap(idle_seconds: 30) # 3.x
```

## Notes

- Connections are lazily created as needed.
- **WARNING**: Avoid `Timeout.timeout` in your Ruby code or you can see
  occasional silent corruption and mysterious errors. The Timeout API is unsafe
  and dangerous to use. Use proper socket timeout options as exposed by
  Net::HTTP, Redis, Dalli, etc.


## Author

Mike Perham, [@getajobmike](https://ruby.social/@getajobmike), <https://www.mikeperham.com>
