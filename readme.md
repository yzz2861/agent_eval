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

### Session Timeouts

Both `Rack::Session::Cookie` and `Rack::Session::Pool` support two
independent, server-enforced session lifetimes:

``` ruby
use Rack::Session::Cookie,
  :secret => '**unique secret key**',
  :idle_timeout => 20 * 60,        # expire after 20 minutes of inactivity
  :absolute_timeout => 8 * 60 * 60 # force re-authentication 8 hours after login
```

- `:idle_timeout` expires the session after this many seconds without a
  request. Renewal writes are throttled by `:touch_throttle` (default 60
  seconds); throttling only ever makes the check stricter, never wider.
- `:absolute_timeout` expires the session this many seconds after it was
  created, no matter how active it is. Renewing the session (e.g. via
  `env['rack.session.options'][:renew] = true` after authentication)
  starts a fresh absolute window.

Timestamps are generated and validated by the server; malformed or
suspiciously future-dated timestamps are rejected and the session is
discarded. An expired session is never exposed to the application — it
sees a fresh, empty session instead.

Requests that only poll for status can read the session without extending
the idle timeout:

``` ruby
env['rack.session.options'][:skip_touch] = true
```

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
