# Test Adapter

The built-in Faraday Test adapter lets you define stubbed HTTP requests. This can
be used to mock out network services in an application's unit tests.

The easiest way to do this is to create the stubbed requests when initializing
a `Faraday::Connection`. Stubbing a request by path yields a block with a
`Faraday::Env` object. The stub block expects an Array return value with three
values: an Integer HTTP status code, a Hash of key/value headers, and a
response body.

```ruby
conn = Faraday.new do |builder|
  builder.adapter :test do |stub|
    # block returns an array with 3 items:
    # - Integer response status
    # - Hash HTTP headers
    # - String response body
    stub.get('/ebi') do |env|
      [
        200,
        { 'Content-Type': 'text/plain', },
        'shrimp'
      ]
    end

    # test exceptions too
    stub.get('/boom') do
      raise Faraday::ConnectionFailed
    end
  end
end
```

You can define the stubbed requests outside of the test adapter block:

```ruby
stubs = Faraday::Adapter::Test::Stubs.new do |stub|
  stub.get('/tamago') { |env| [200, {}, 'egg'] }
end
```

This Stubs instance can be passed to a new Connection:

```ruby
conn = Faraday.new do |builder|
  builder.adapter :test, stubs do |stub|
    stub.get('/ebi') { |env| [ 200, {}, 'shrimp' ]}
  end
end
```

It's also possible to stub additional requests after the connection has been
initialized. This is useful for testing.

```ruby
stubs.get('/uni') { |env| [ 200, {}, 'urchin' ]}
```

You can also stub the request body with a string or a proc.
It would be useful to pass a proc if it's OK only to check the parts of the request body are passed.

```ruby
stubs.post('/kohada', 'where=sea&temperature=24') { |env| [ 200, {}, 'spotted gizzard shad' ]}
stubs.post('/anago', -> (request_body) { JSON.parse(request_body).slice('name') == { 'name' => 'Wakamoto' } }) { |env| [200, {}, 'conger eel'] }
```

If you want to stub requests that exactly match a path, parameters, and headers,
`strict_mode` would be useful.

```ruby
stubs = Faraday::Adapter::Test::Stubs.new(strict_mode: true) do |stub|
  stub.get('/ikura?nori=true', 'X-Soy-Sauce' => '5ml' ) { |env| [200, {}, 'ikura gunkan maki'] }
end
```

This stub expects the connection will be called like this:

```ruby
conn.get('/ikura', { nori: 'true' }, { 'X-Soy-Sauce' => '5ml' } )
```

If there are other parameters or headers included, the Faraday Test adapter
will raise `Faraday::Test::Stubs::NotFound`. It also raises the error
if the specified parameters (`nori`) or headers (`X-Soy-Sauce`) are omitted.

You can also enable `strict_mode` after initializing the connection.
In this case, all requests, including ones that have been already stubbed,
will be handled in a strict way.

```ruby
stubs.strict_mode = true
```

## Stateful workflows

Some APIs are inherently sequential: you must create a draft, submit it and
only then can you read the result, and the same URL may return a different
response depending on the stage. Use `state_machine` to organize stubs by
named states and one-time transitions instead of matching each URL in
isolation:

```ruby
stubs = Faraday::Adapter::Test::Stubs.new do |stub|
  stub.state_machine(initial: :drafting) do |fsm|
    fsm.state :drafting do |state|
      state.post('/drafts') do |env, session|
        # Transitions and handlers receive the request env and a shared
        # session hash, so a request can generate values for later stages.
        session[:draft_id] = JSON.parse(env[:body]).fetch('id')
        [201, { 'X-Draft-Id' => session[:draft_id] }, 'draft created']
      end

      # This transition can only be taken once and moves the machine to
      # :ready. The optional guard can read the request and veto the move.
      state.transition(:post, '/submit', :ready,
                       guard: ->(env) { env.request_headers['X-Draft-Id'] }) do |_env, session|
        [202, {}, "submitted draft #{session[:draft_id]}"]
      end

      # The same path returns different responses in different states.
      state.get('/result') { [409, {}, 'not submitted yet'] }
    end

    fsm.state :ready do |state|
      state.transition(:get, '/result', :done) { [200, {}, 'processing'] }
    end

    fsm.state :done do |state|
      state.get('/result') { [200, {}, 'done'] }
    end
  end
end
```

Requests are matched in the current state only. Following a stage out of
order raises `Faraday::Adapter::Test::Stubs::SequenceError` with a message
that names the current state and the missing step, while a route unknown to
every stub still raises `Stubs::NotFound` as before. Transitions are consumed
atomically, so when concurrent requests race for the same one-time transition
exactly one succeeds and the others receive a `SequenceError`. Plain, state
independent stubs defined with `stub.get`/`stub.post`/... keep working exactly
as before and can be freely mixed with state machines.

`verify_stubbed_calls` also reports transitions that were never taken, and a
machine can be returned to its initial state with `reset`.

Finally, you can treat your stubs as mocks by verifying that all of the stubbed
calls were made. NOTE: this feature is still fairly experimental. It will not
verify the order or count of any stub.

```ruby
stubs.verify_stubbed_calls
```

After the test case is completed (possibly in an `after` hook), you should reset
the stubs so each test starts with its own set. When you hold a reference to the
`Stubs` instance, call `clear` to remove every stub, including consumed ones.

```ruby
stubs.clear
```

Alternatively, if you rely on the default connection, you can clear it to prevent
it from being cached between different tests.

```ruby
Faraday.default_connection = nil
```

## Examples

Working [RSpec] and [test/unit] examples for a fictional JSON API client are
available.

[RSpec]: https://github.com/lostisland/faraday/blob/main/examples/client_spec.rb
[test/unit]: https://github.com/lostisland/faraday/blob/main/examples/client_test.rb
