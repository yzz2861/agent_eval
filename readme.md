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

### Subject revocation

Optional per-subject session generations can revoke all sessions for one user
without rotating the cookie encryption key and affecting every user:

``` ruby
revocation_store = Rack::Session::Revocation::MemoryStore.new

use Rack::Session::Cookie,
  secret: '**unique secret key**',
  revocation_store: revocation_store,
  revocation_subject: 'user_id'

# After a password change, in the same process using the store:
revocation_store.bump_generation!(current_user.id)
```

The session record stores its subject's generation when an authenticated
session is issued. A request whose subject has a newer generation is rejected
and starts as an anonymous session. Anonymous sessions do not query the store.

New logins and subject changes rotate the session ID and stamp the current
generation. Ordinary renewal keeps the existing generation, so an old session
cannot gain access by renewing its ID. Storage failures while validating or
issuing an authenticated session fail closed. Use a custom store with atomic
`generation(subject)` and `bump_generation!(subject)` methods for multi-process
deployments; `MemoryStore` is intended for tests and single-process use.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
