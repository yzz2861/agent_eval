# Configuration Guide

This guide covers the parts of `secure` you are most likely to customize after the quick start. Keep `Secure` as the public entry point and pass it the builders you need.

## Default configuration

`Secure.with_default_headers()` uses `Preset.BALANCED`, which provides a modern baseline while keeping the header set lean:

- **Cross-Origin-Opener-Policy:** `same-origin`
- **Cross-Origin-Resource-Policy:** `same-origin`
- **Content-Security-Policy:** `default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests`
- **Strict-Transport-Security:** `max-age=31536000; includeSubDomains`
- **Permissions-Policy:** `geolocation=(), microphone=(), camera=()`
- **Referrer-Policy:** `strict-origin-when-cross-origin`
- **Server:** empty string
- **X-Content-Type-Options:** `nosniff`
- **X-Frame-Options:** `SAMEORIGIN`

Balanced intentionally skips `Cache-Control` and the compatibility headers (`X-Permitted-Cross-Domain-Policies`, `X-DNS-Prefetch-Control`, `Origin-Agent-Cluster`, `X-Download-Options`, `X-XSS-Protection`). Add them explicitly when your deployment still depends on them.

`Preset.BALANCED` is the recommended default. `Preset.BASIC` is the compatibility-oriented option that most closely matches Helmet-style defaults. `Preset.STRICT` is available when you want tighter CSP and stronger isolation. It is not the default.

The balanced CSP includes `'unsafe-inline'` in `style-src` for compatibility. It does not allow inline scripts by default. If your app needs a looser CSP, treat that as an app-specific adjustment and test it against real behavior.

## Customizing individual builders

All public header builders are re-exported from `secure`, so most applications can stay on the package-level API.

### `X-Frame-Options`

If you want to allow framing only from the same origin, use:

```python
from secure import Secure, XFrameOptions

secure_headers = Secure(xfo=XFrameOptions().sameorigin())
```

This protects against clickjacking while still allowing same-origin embedding.

### `Strict-Transport-Security`

To enforce HTTPS for all subdomains and opt into preload when you are ready, configure HSTS explicitly:

```python
from secure import Secure, StrictTransportSecurity

secure_headers = Secure(
    hsts=StrictTransportSecurity().max_age(63072000).include_subdomains().preload()
)
```

This enforces HTTPS for two years, applies the rule to subdomains, and opts into the preload list.

## Adding custom headers

Use `CustomHeader` for application-specific response headers that do not have a dedicated builder:

```python
from secure import CustomHeader, Secure

custom_header = CustomHeader("X-Custom-Header", "CustomValue")
secure_headers = Secure(custom=[custom_header])
```

## Starting from a preset

Every `Secure` instance exposes its configured builders through `headers_list`, so you can replace or extend a preset after construction:

```python
from secure import Preset, Secure, StrictTransportSecurity

secure_headers = Secure.from_preset(Preset.BALANCED)

secure_headers.headers_list = [
    header
    for header in secure_headers.headers_list
    if header.header_name != "Strict-Transport-Security"
]
secure_headers.headers_list.append(
    StrictTransportSecurity().max_age(63072000).include_subdomains()
)
```

This replaces the preset HSTS builder while leaving the rest of the preset untouched.
If you need the compatibility profile instead, start from `Preset.BASIC`.

## Layered policy resolution

When headers come from several sources (default policy, tenant policy, per-route overrides), loading them into one list and relying on call order is unsafe: duplicate names silently resolve to whichever value was appended last. `PolicyResolver` models each source as an explicit layer with its own identifier and priority, then merges them once into an immutable snapshot.

```python
from secure import PolicyLayer, PolicyResolver, Secure, StrictTransportSecurity

resolver = PolicyResolver()
secure = Secure.from_layers(
    [
        PolicyLayer.from_headers('default', 10, [StrictTransportSecurity().max_age(31536000)]),
        PolicyLayer.from_headers('tenant', 20, [('Strict-Transport-Security', 'max-age=60')]),
        PolicyLayer.from_headers('route', 30, [('Strict-Transport-Security', 'max-age=63072000')]),
    ],
    resolver=resolver,
)
```

Resolution rules:

- **Single-valued headers:** the highest-priority value wins. Layer order never matters, so a shorter `max-age` cannot overwrite a stronger one just because it was loaded second.
- **Explicit deny:** `PolicyEntry.deny('Server')` suppresses every lower-priority allow. A higher-priority allow still overrides the deny.
- **Multi-valued headers:** names in `multi_ok` (default: `Content-Security-Policy`) keep one output line per distinct value; names in `comma_join_ok` (default: `Cache-Control`) are joined with `', '`.
- **Conflicts:** two different single values at the same priority raise `PolicyConflictError` with a readable message and per-source origins. Pass `on_conflict='collect'` to omit the conflicted header and keep a `PolicyDiagnostic` on the snapshot instead.
- **Provenance:** `ResolvedPolicy.origins` records the source, priority, effect, and value behind every emitted header line.

The returned `ResolvedPolicy` is an immutable snapshot: mutating the original header builders or layers after resolution cannot change it. `set_headers()` and `set_headers_async()` emit exactly that snapshot.

### Hot reload

For configuration updates, call `reload_layers()` (an alias of `apply_layers()`). The new layers are fully resolved before the snapshot reference is swapped, so concurrent requests observe either the complete old snapshot or the complete new one, never a mixture:

```python
secure.reload_layers(
    [PolicyLayer.from_headers('default', 10, new_headers)],
    resolver=resolver,
)
```

In-flight requests keep using the snapshot they started with. Directly mutating `headers_list` remains supported and falls back to the classic single-layer pipeline, discarding any installed layered snapshot.

Validation runs while the snapshot is built. The resolver defaults to `strict=True` and `on_invalid='raise'`, so CR/LF injection, illegal header names, and empty values fail resolution instead of being smuggled through the merge. Use `on_invalid='drop'`/`'warn'` or `strict=False` to mirror the normalization helper's softer policies.

## Middleware behavior

The ASGI and WSGI middleware classes use the same `Secure` instance you would use in hooks or handlers:

- Existing header values are overwritten by default for configured header names.
- Pass `multi_ok` when a header name should be preserved and appended instead.
- `SecureASGIMiddleware` only changes HTTP responses. WebSocket scopes pass through unchanged.

## Validation and normalization

If you need stronger guarantees before emission, `Secure` also exposes optional pipeline helpers:

- `allowlist_headers(...)` filters or rejects unexpected header names in the current `headers_list`.
- `deduplicate_headers(...)` resolves duplicate header names in `headers_list` before you build a single-valued mapping.
- `validate_and_normalize_headers(...)` validates and normalizes the current `header_items()`, then caches the single-valued mapping used by `.headers`, `set_headers()`, and `set_headers_async()`.

If you intentionally emit duplicate headers such as multiple `Content-Security-Policy` values, use `header_items()` instead of `.headers`.

For per-header builder details, see the docs under [headers](./headers).
