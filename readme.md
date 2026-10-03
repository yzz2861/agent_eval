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

### Session lifetimes

Both `Rack::Session::Cookie` and `Rack::Session::Pool` support independent
server-enforced limits:

``` ruby
use Rack::Session::Cookie,
  idle_timeout: 20 * 60,
  absolute_timeout: 8 * 60 * 60,
  renew_cookie_after: 60
```

`idle_timeout` expires a session after enough inactive seconds. Ordinary
activity slides that deadline. Set `env['rack.session.skip_idle_renewal']` to
true for read-only polling requests so they can load the session without sliding
the idle deadline. `absolute_timeout` expires a session at a fixed age even when
it remains active. Timestamps are maintained by the server and validated on each
request; client-supplied timestamps are not trusted as the current clock. With
Cookie storage, `renew_cookie_after` can throttle Set-Cookie rewrites without
making expiry more permissive.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
