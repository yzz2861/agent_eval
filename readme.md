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

### Explicit commit mode

By default sessions are saved automatically at the end of a request, so even
read-only code paths can mutate the session by accident. Pass
`explicit_commit: true` to `Rack::Session::Pool` or `Rack::Session::Cookie`
to opt in to explicit persistence instead:

``` ruby
use Rack::Session::Pool, explicit_commit: true

run lambda do |env|
  session = env['rack.session']

  # The application gets its own editable copy of the session...
  session[:key] = "value"

  # ...and nothing reaches the store until commit! is called:
  session.commit!

  [200, {}, ["ok"]]
end
```

Rules of explicit commit mode:

- Without `commit!`, the stored session is never modified, even if the request
  raises. Nested hashes and arrays are deep copied, so in-place mutations
  (`session[:a] << 1`) cannot reach the store either.
- Each `commit!` persists an independent snapshot of the current session. Edits
  made after a commit do not affect what was stored; call `commit!` again to
  persist later edits. A commit made before an exception is still persisted.
- `:drop`, `:renew` and `session.destroy` are also deferred until the next
  `commit!`; they have no effect on the store if the request never commits.
- An empty session can be committed and results in a stored (empty) session
  with a session cookie. A request that never commits leaves no session behind
  at all.
- If the store rejects a write, `commit!` returns `false`, a warning is written
  to `rack.errors`, no cookie is set and the previous session stays intact.
- Cookie stores enforce the same boundary: the cookie only reflects the last
  committed snapshot, so a second request reads exactly what was committed.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
