HTTPX is careful to enforce timeouts everywhere by default.

The default behavior is to raise a `TimeoutException` after 5 seconds of
network inactivity.

## Setting and disabling timeouts

You can set timeouts for an individual request:

```python
# Using the top-level API:
httpx.get('http://example.com/api/v1/example', timeout=10.0)

# Using a client instance:
with httpx.Client() as client:
    client.get("http://example.com/api/v1/example", timeout=10.0)
```

Or disable timeouts for an individual request:

```python
# Using the top-level API:
httpx.get('http://example.com/api/v1/example', timeout=None)

# Using a client instance:
with httpx.Client() as client:
    client.get("http://example.com/api/v1/example", timeout=None)
```

## Setting a default timeout on a client

You can set a timeout on a client instance, which results in the given
`timeout` being used as the default for requests made with this client:

```python
client = httpx.Client()              # Use a default 5s timeout everywhere.
client = httpx.Client(timeout=10.0)  # Use a default 10s timeout everywhere.
client = httpx.Client(timeout=None)  # Disable all timeouts by default.
```

## Fine tuning the configuration

HTTPX also allows you to specify the timeout behavior in more fine grained detail.

There are four different types of timeouts that may occur. These are **connect**,
**read**, **write**, and **pool** timeouts.

* The **connect** timeout specifies the maximum amount of time to wait until
a socket connection to the requested host is established. If HTTPX is unable to connect
within this time frame, a `ConnectTimeout` exception is raised.
* The **read** timeout specifies the maximum duration to wait for a chunk of
data to be received (for example, a chunk of the response body). If HTTPX is
unable to receive data within this time frame, a `ReadTimeout` exception is raised.
* The **write** timeout specifies the maximum duration to wait for a chunk of
data to be sent (for example, a chunk of the request body). If HTTPX is unable
to send data within this time frame, a `WriteTimeout` exception is raised.
* The **pool** timeout specifies the maximum duration to wait for acquiring
a connection from the connection pool. If HTTPX is unable to acquire a connection
within this time frame, a `PoolTimeout` exception is raised. A related
configuration here is the maximum number of allowable connections in the
connection pool, which is configured by the `limits` argument.

You can configure the timeout behavior for any of these values...

```python
# A client with a 60s timeout for connecting, and a 10s timeout elsewhere.
timeout = httpx.Timeout(10.0, connect=60.0)
client = httpx.Client(timeout=timeout)

response = client.get('http://example.com/')
```

## Bounding the total request duration

The connect, read, write, and pool timeouts each apply to a single network
operation. A request that involves redirects, authentication retries, or a
response that keeps trickling in small chunks of data can therefore keep
going indefinitely without ever triggering one of those timeouts.

The optional `total` budget bounds the duration of the entire request, from
the moment it is sent until the response is closed. Queueing, connecting,
authentication retries, redirects, and streaming the response body all share
the same remaining budget, measured against a monotonic clock...

```python
# Each operation may take up to 10s, but the entire request,
# including any redirects and reading the response body,
# must complete within 30s.
timeout = httpx.Timeout(10.0, total=30.0)
client = httpx.Client(timeout=timeout)

response = client.get('http://example.com/')
```

If the budget is exhausted a `TotalTimeout` exception is raised, which is
distinct from `ReadTimeout` and the other per-operation timeouts, and the
underlying connection is released. The budget also applies when streaming
responses, so a response that keeps sending small chunks of data cannot
extend it...

```python
timeout = httpx.Timeout(10.0, total=30.0)
with httpx.Client(timeout=timeout) as client:
    with client.stream("GET", "http://example.com/") as response:
        for chunk in response.iter_bytes():
            ...  # A `TotalTimeout` is raised here if the budget runs out.
```

The `total` budget defaults to `None`, which disables it and leaves the
existing timeout behavior unchanged.
