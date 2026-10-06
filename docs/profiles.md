# Named profiles

`dry-configurable` supports named configuration profiles for overlapping
environment-specific setups (development, staging, production, ...). A
profile bundles a set of configuration changes under a name and may inherit
from one or more other profiles. Selecting a profile builds a fresh,
independent config object; the class-level config is never touched.

```ruby
class App
  extend Dry::Configurable

  setting :dsn, default: "sqlite:memory"
  setting :pool, default: 5

  profile :base do |config|
    config.pool = 10
  end

  profile :production, inherits: %i[base] do |config|
    config.dsn = ENV.fetch("DATABASE_URL")
  end
end

config = App.config_for(:production)
config.pool # => 10 (inherited from :base)
config.dsn  # => "postgres://..."
App.config.pool # => 5 (untouched)
```

Every call to `config_for` starts from a pristine config, so nested configs
and mutable defaults (arrays, hashes, sets) are never shared between
profiles: mutating one profile's config cannot leak into another's.

## Unset vs. explicit nil vs. restored default

Inside a profile block the three kinds of "no value" stay distinct:

- a setting the block never touches keeps the value inherited from the
  ancestor profiles (or the setting's own default);
- `config.key = nil` assigns an explicit `nil` (`configured?` is true);
- `config.restore_default(:key)` discards any inherited value and restores
  the setting's declared default (`configured?` is false again).

```ruby
class App
  extend Dry::Configurable

  setting :pool, default: 5

  profile(:base)        { |config| config.pool = 10 }
  profile(:nil_pool,    inherits: %i[base]) { |config| config.pool = nil }
  profile(:default_pool, inherits: %i[base]) { |config| config.restore_default(:pool) }
end

App.config_for(:base).pool         # => 10
App.config_for(:nil_pool).pool     # => nil
App.config_for(:default_pool).pool # => 5
```

## Multiple inheritance and linearization

A profile may inherit from several parents. The inheritance chain is
resolved with C3 linearization — the same algorithm Ruby uses for its own
method resolution order — which guarantees:

- a profile always precedes its parents (more specific wins);
- the declared order of parents is preserved (earlier parents win over
  later ones);
- every profile appears exactly once, so a shared ancestor in a diamond is
  never applied twice;
- contradictory constraints raise
  `Dry::Configurable::ProfileLinearizationError` instead of silently
  picking an arbitrary order.

The resolved order is exposed via `.profile_order`, from highest to lowest
precedence. `config_for` applies it in reverse (ancestors first).

### Diamond example

```ruby
class App
  extend Dry::Configurable

  setting :dsn, default: "sqlite:memory"
  setting :pool, default: 5
  setting :log, default: []

  profile :base do |config|
    config.pool = 10
    config.log << "base"
  end

  profile :development, inherits: %i[base] do |config|
    config.dsn = "sqlite:dev"
    config.log << "development"
  end

  profile :test, inherits: %i[base] do |config|
    config.pool = 2
    config.log << "test"
  end

  profile :ci, inherits: %i[development test] do |config|
    config.log << "ci"
  end
end

App.profile_order(:ci) # => [:ci, :development, :test, :base]

config = App.config_for(:ci)
config.dsn # => "sqlite:dev"            (from :development)
config.pool # => 2                      (from :test, overriding :base)
config.log # => ["base", "test", "development", "ci"]
#           ^^^^ :base applied exactly once, despite the diamond
```

### Unlinearizable example

When two branches demand contradictory orders, no consistent linearization
exists and an error is raised:

```ruby
class App
  extend Dry::Configurable

  setting :mode, default: nil

  profile(:x) { |config| config.mode = :x }
  profile(:y) { |config| config.mode = :y }

  profile(:a, inherits: %i[x y]) { |config| } # x before y
  profile(:b, inherits: %i[y x]) { |config| } # y before x
  profile(:c, inherits: %i[a b]) { |config| } # contradiction
end

App.config_for(:c)
# raises Dry::Configurable::ProfileLinearizationError:
#   cannot linearize profile inheritance: contradictory precedence
#   constraints (x < y, y < x)
```

Cycles are reported separately as
`Dry::Configurable::CyclicProfileInheritanceError`, and referencing an
undefined profile raises `Dry::Configurable::UnknownProfileError`.
