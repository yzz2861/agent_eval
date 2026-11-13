# Set-Cookie Builder

## What it does

`SetCookie` builds a single, validated `Set-Cookie` response header. Browsers silently drop cookies whose prefix and attribute combinations violate [RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis); the builder refuses those combinations at construction time instead of emitting a header that will never be stored.

It lives alongside the response-header builders and middleware without changing them: `Secure`, the header classes, and the ASGI/WSGI middleware keep working exactly as before.

## Minimal example

```python
from secure import SameSite, SetCookie

cookie = SetCookie(
    "__Host-session",
    "session-token",
    path="/",
    secure=True,
    http_only=True,
    same_site=SameSite.STRICT,
)

response.set_header(cookie.header_name, cookie.header_value)
```

## Resulting header

```http
Set-Cookie: __Host-session=session-token; Path=/; Secure; HttpOnly; SameSite=Strict
```

## Prefix rules

The `__Host-` and `__Secure-` name prefixes carry hard requirements that the builder enforces automatically:

- `__Host-` cookies must set `Path=/`, must not set `Domain`, and must set `Secure`.
- `__Secure-` cookies must set `Secure`; `Domain` and `Path` remain available.
- Unprefixed cookies have no prefix-driven requirements.

```python
SetCookie("__Host-session", value, path="/", secure=True)          # valid
SetCookie("__Host-session", value, path="/", domain="example.com") # ValueError
SetCookie("__Secure-id", value, secure=True)                       # valid
SetCookie("__Secure-id", value)                                    # ValueError
```

## Attribute rules

- `SameSite.None` requires `Secure`. `SameSite.Strict` and `SameSite.Lax` do not.
- `Partitioned` requires `Secure` (partitioned cookies are only sent over secure channels).
- `max_age` and `expires` are mutually exclusive; choose one lifetime mechanism.
- `expires` must be a timezone-aware `datetime.datetime` and is serialized as an RFC 7231 HTTP-date.
- `max_age` must be a non-negative integer number of seconds.

```python
from datetime import datetime, timedelta, timezone

expires = datetime.now(timezone.utc) + timedelta(days=14)

SetCookie("sid", value, max_age=1209600, secure=True, same_site=SameSite.LAX)
SetCookie("sid", value, expires=expires, secure=True)
```

## Name, value, and length validation

- Cookie names must be RFC 7230 tokens (visible ASCII without separators or control characters).
- Values reject control characters and the structural characters that break cookie parsing: whitespace, double quotes, commas, semicolons, and backslashes.
- Non-ASCII values such as Chinese text are preserved as UTF-8.
- The combined `name=value` payload must not exceed 4096 bytes when encoded as UTF-8.

```python
SetCookie("lang", "中文偏好", path="/", secure=True)
# Set-Cookie: lang=中文偏好; Path=/; Secure

SetCookie("bad name", value)  # ValueError
SetCookie("sid", "a;b")       # ValueError
```

## Sensitive values

Cookie values frequently carry session material. The value is therefore never included in validation errors or in the debug representation:

```python
cookie = SetCookie("session", "supersecret", secure=True)
repr(cookie)
# SetCookie(name='session', value=<redacted>, path=None, ...)
```

## Emitting on a response

`set_on()` and the async `set_on_async()` support the same response interfaces as `Secure.set_headers()` (`set_header`, or a `headers` container/mapping). Repeated calls append separate `Set-Cookie` fields when the container allows it.

```python
cookie.set_on(response)            # sync
await cookie.set_on_async(response)  # async
```

For ASGI/WSGI middleware stacks, build the cookie independently and append `cookie.header_items()` next to the headers produced by `Secure`; neither the middleware nor the default header set is modified.

## Resources

- [MDN Web Docs: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [RFC 6265bis: HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
