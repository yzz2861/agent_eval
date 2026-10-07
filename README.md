# Distributed Ruby: dRuby

dRuby is a distributed object system for Ruby.  It allows an object in one
Ruby process to invoke methods on an object in another Ruby process on the
same or a different machine.

For an introduction and examples of usage see the documentation to the
DRb module.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'drb'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install drb

## Usage

### dRuby in client/server mode

This illustrates setting up a simple client-server drb
system.  Run the server and client code in different terminals,
starting the server code first.

#### Server code

```rb
require 'drb/drb'

# The URI for the server to connect to
URI = 'druby://localhost:8787'

class TimeServer
  def current_time
    Time.now
  end
end

# The object that handles requests on the server
FRONT_OBJECT = TimeServer.new

DRb.start_service(URI, FRONT_OBJECT)
# Wait for the drb server thread to finish before exiting.
DRb.thread.join
```

#### Client code

```rb
require 'drb/drb'

# The URI to connect to
SERVER_URI = 'druby://localhost:8787'

# Start a local DRbServer to handle callbacks.

# Not necessary for this small example, but will be required
# as soon as we pass a non-marshallable object as an argument
# to a dRuby call.

# Note: this must be called at least once per process to take any effect.
# This is particularly important if your application forks.
DRb.start_service

timeserver = DRbObject.new_with_uri(SERVER_URI)
puts timeserver.current_time
```

#### Security

As DRb allows remote clients to invoke arbitrary methods, it is not suitable to
expose to untrusted clients.

When using DRb, try to avoid exposing it over the network if possible. If this
isn't possible and you need to expose DRb to the world, you *must* configure an
appropriate security policy with +DRb::ACL+.

## Capability proxies

When one internal object must be shared with several background components
that should each see a different interface, DRb.publish creates an
optional *capability*: a reference that may call only a server-declared
allow-list of methods.  The capability table is stored in the server, so
editing fields on the client-side stub never widens the interface.

Server:

    require 'drb'

    class Vault
      include DRb::DRbUndumped
      def open; :opened; end
      def close; :closed; end
      def admin_reset; :reset; end
    end

    vault = Vault.new
    # A tiny front object that hands out the capability.
    front = Object.new
    front.define_singleton_method(:vault_view) do
      DRb.publish(vault, [:open, :close]).proxy
    end
    DRb.start_service('druby://localhost:0', front)

    grant = DRb.publish(vault, [:open, :close])
    proxy = grant.proxy             # hand this stub to a component

    view = proxy.derive([:open])    # strictly weaker, independently revocable
    grant.revoke                    # old references now fail with
                                    # DRb::DRbCapabilityRevoked

Client:

    proxy.open                      # => :opened
    proxy.admin_reset               # denied (DRbCapabilityDenied remotely)
    proxy.send(:admin_reset)        # indirect entries share the allow-list
    proxy.respond_to?(:open)        # => true
    proxy.respond_to?(:admin_reset) # => false

Return values can be packaged per method with the +policies+ argument:
:copy forces a marshalled copy, :reference returns an unrestricted
DRbObject, and an Array or Hash of method names wraps the returned object
in another capability.  Capabilities reuse the normal dRuby transport;
they do not change dRuby's Marshal usage and are not a general defense
against connecting untrusted peers.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/drb.
