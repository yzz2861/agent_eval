# Adapter Capabilities

Different adapters support different features. For example, response streaming
through `on_data` is only implemented by some adapters, and certain TLS options
can silently have no effect with others.

Capabilities make this explicit:

- **Adapters declare** the capabilities they support with
  `Faraday::Adapter.supports_capabilities`.
- **Connections and requests declare** the capabilities they require.

Faraday checks fixed connection requirements when the connection is built and
per-request requirements before the request reaches the adapter. A missing
declaration is treated as *unknown* (and therefore not supported) rather than
assumed to work. Requests that do not require any capability are never
affected, so existing adapters and applications keep working unchanged.

## Standard capabilities

The following capabilities are defined as constants on `Faraday::Adapter`:

| Constant | Meaning |
|----------|---------|
| `STREAMING_RESPONSES` | Streaming response bodies via the `on_data` request option. |
| `PARALLEL` | Running multiple requests concurrently. |
| `TLS_VERIFY` | Certificate verification options (`verify`, `verify_mode`, `cert_store`, `ca_file`, `ca_path`). |
| `TLS_MIN_VERSION` | The `min_version` SSL option. |
| `TLS_MAX_VERSION` | The `max_version` SSL option (and the legacy `version` option). |
| `TLS_CIPHERS` | The `ciphers` SSL option. |
| `TLS_CLIENT_CERT` | Client certificate options (`client_cert`, `client_key`, `certificate`, `private_key`). |
| `TLS_VERIFY_DEPTH` | The `verify_depth` SSL option. |

Adapter gems may also declare their own symbols for non-standard features.

## Requiring capabilities on a connection

Fixed requirements that apply to every request are checked while the
connection is being built, as soon as the adapter is known:

```ruby
conn = Faraday.new(
  'https://example.com',
  ssl: { min_version: :TLS1_2 },
  required_capabilities: [Faraday::Adapter::TLS_MIN_VERSION]
) do |f|
  f.adapter :net_http
end
```

You can also declare them inside the configuration block:

```ruby
conn = Faraday.new do |f|
  f.require_capabilities Faraday::Adapter::TLS_MIN_VERSION
  f.adapter :net_http
end
```

If the configured adapter does not declare the capability, a
`Faraday::MissingCapabilitiesError` is raised and the message names the adapter
and the missing capabilities.

## Requiring capabilities for a single request

Request-scoped requirements are checked immediately before the adapter is
called:

```ruby
conn.get('/events') do |req|
  req.options.on_data = proc { |chunk, size, env| puts chunk }
  req.options.require_capabilities Faraday::Adapter::STREAMING_RESPONSES
end
```

## Declaring capabilities on an adapter

Adapter authors declare capabilities in the adapter class. Declarations are
inherited and can be extended by subclasses:

```ruby
class Faraday::Adapter::MyAdapter < Faraday::Adapter
  supports_capabilities Faraday::Adapter::STREAMING_RESPONSES,
                         Faraday::Adapter::TLS_MIN_VERSION
end
```

You can inspect what an adapter supports:

```ruby
Faraday::Adapter::MyAdapter.declared_capabilities
# => [:streaming_responses, :tls_min_version]
Faraday::Adapter::MyAdapter.supports_capabilities?(:streaming_responses)
# => true
Faraday::Adapter::MyAdapter.missing_capabilities(:parallel)
# => [:parallel]
```

## Compatibility

Adapters that do not declare anything, and code that does not require
capabilities, continue to work exactly as before. Capability checks only run
when at least one capability is explicitly required.
