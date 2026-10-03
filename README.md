<!--- this file is synced from dry-rb/template-gem project -->
[gem]: https://rubygems.org/gems/dry-container
[actions]: https://github.com/dry-rb/dry-container/actions

# dry-container [![Gem Version](https://badge.fury.io/rb/dry-container.svg)][gem] [![CI Status](https://github.com/dry-rb/dry-container/workflows/ci/badge.svg)][actions]

## Links

* [User documentation](https://dry-rb.org/gems/dry-container)
* [API documentation](http://rubydoc.info/gems/dry-container)
* [Forum](https://discourse.dry-rb.org)

## Supported Ruby versions

This library officially supports the following Ruby versions:

* MRI `>= 3.0.0`
* jruby `>= 9.4` (not tested on CI)

## License

See `LICENSE` file.

## Restricted read-only views

Use a view when handing a container to third-party code that should resolve only
explicitly approved keys. The allowlist is supplied when the view is created:

```ruby
container.register("billing.gateway", gateway)
container.register("database.admin_url", admin_url)
container.register("signing.key", signing_key)

billing_view = container.read_only_view(namespaces: "billing")
one_key_view = container.read_only_view(keys: "billing.gateway")
```

`resolve`, `key?`, `keys`, and `each` apply the same visibility rules. The `[]`
alias delegates to `resolve`, so it cannot bypass the view. Namespaces are scoped
with the container separator: a `"billing"` namespace exposes `"billing.gateway"`
but not `"billing_admin_url"`.

Unauthorized requests raise a normal `KeyError` with the same behavior for keys
that do and do not exist in the source container. Error messages therefore do not
reveal whether a hidden key is registered, and suggestions are limited to keys the
view is allowed to expose.

The view is read-only, but it is not an arbitrary-Ruby sandbox. Resolving an item
runs that item's registered factory. If an accessible factory closes over the
original container, mutates shared state, or returns a broader capability, the
view cannot contain that code. Keep such factories out of the accessible keys and
namespaces, and freeze or fully construct source containers before sharing views.
