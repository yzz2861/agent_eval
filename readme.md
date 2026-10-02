# Rack::Session

Session management implementation for Rack.

[![Development Status](https://github.com/rack/rack-session/workflows/Test/badge.svg)](https://github.com/rack/rack-session/actions?workflow=Test)

## Usage

In your `config.ru`:

``` ruby
# config.ru

require 'rack/session'
use Rack::Session::Cookie,
  :domain => 'mywebsite.com',
  :path => '/',
  :expire_after => 3600*24,
  :secret => '**unique secret key**'
```

Usage follows the standard outlined by `rack.session`, i.e.:

``` ruby
class MyApp
  def call(env)
    session = env['rack.session']

    # Set some state:
    session[:key] = "value"
  end
end
```

### Manual Commit Mode

By default (`commit_mode: :auto`), the session is written back to the store when the response is generated. If you have endpoints that should never persist session changes, you can opt into explicit commits:

``` ruby
use Rack::Session::Pool, commit_mode: :manual
```

In manual commit mode, the request works on a private, editable copy of the session:

- Changes are only persisted when the application calls `env['rack.session'].commit!`. If the request finishes or raises without committing, the stored session and the client cookie are left untouched.
- The isolation boundary includes nested hashes and arrays: the copy is deep-duplicated when loaded, and a deep copy of the current data is written when committed, so neither uncommitted edits nor modifications made after a commit can leak into the store. To persist further changes, call `commit!` again.
- `commit!` writes synchronously and returns `true`/`false`, so storage failures are reported to the application before the response is committed.
- `session.destroy` stages the deletion, which is only applied on `commit!`. The `:renew` and `:drop` options likewise take effect at `commit!` time.

The mode can also be toggled per request via `env['rack.session.options'][:commit_mode] = :manual`.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
