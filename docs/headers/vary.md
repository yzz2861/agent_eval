# Vary

## What it does

`Vary` tells caches which request headers participated in selecting a response. It is part of cache-key correctness, not a substitute for `Cache-Control` privacy directives.

For personalized pages, combine `Cache-Control: private` / `no-store` with a `Vary` that includes the selecting headers. Never use `Vary` alone to make a personalized response safe for a shared cache.

## Minimal example

```python
from secure import Secure, Vary

secure_headers = Secure(
    vary=Vary().accept_encoding().authorization().cookie()
)
```

## Resulting header

```http
Vary: Accept-Encoding, Authorization, Cookie
```

## Default behavior

If you create `Vary()` and do not add fields, it returns the library default:

- **Default header value:** `Accept-Encoding`

## Merging existing values

`Vary` is often already set by the framework, CDN, or application. Use `merge()` to preserve those fields:

```python
vary = Vary().merge("Accept-Encoding").cookie()
print(vary.header_value)  # Accept-Encoding, Cookie
```

The middleware uses the same merge behavior, so an application's existing `Vary: Accept-Encoding` is never replaced by a configured `Vary: Cookie`.

## Builder API

- `.add("Accept-Encoding", "Cookie")`
- `.field(...)`, `.custom(...)` aliases for `.add(...)`
- `.accept()`, `.accept_encoding()`, `.accept_language()`
- `.authorization()`, `.cookie()`, `.origin()`, `.user_agent()`
- `.any()` emits `*`
- `.merge(value)` merges fields from an existing header value
- `.value(value)` / `.set(value)` replace the whole value
- `.clear()` returns to the default

Duplicate field names are removed case-insensitively. `*` dominates any other field.

## Attribution

- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary) (licensed under [CC-BY-SA 2.5](https://creativecommons.org/licenses/by-sa/2.5/))
