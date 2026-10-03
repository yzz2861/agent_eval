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

## Read-only views

Give third-party code a restricted facade instead of the complete container:

```ruby
view = container.read_only_view(
  keys: "billing.invoice_generator",
  namespaces: "public_api"
)
```

`resolve`, `[]`, `key?`, `keys`, and `each` only see the explicitly granted
keys or namespaces. Unauthorized keys are reported like missing keys, so their
existence is not disclosed. The view is not a Ruby sandbox: if a permitted
factory captured the original container, code executed by that factory remains
outside the view's control.
