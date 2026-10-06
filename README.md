# IPAddr

IPAddr provides a set of methods to manipulate an IP address.  Both
IPv4 and IPv6 are supported.

[![build](https://github.com/ruby/ipaddr/actions/workflows/test.yml/badge.svg)](https://github.com/ruby/ipaddr/actions/workflows/test.yml)

## Installation

This library is part of the standard ruby distribution as default gem
and synchronized periodically, but you can explicitly depend on this
gem with version constraints as necessary, like when you need a newer
version than comes with older versions of ruby.

For example, you can add this line to your application's Gemfile:

```ruby
gem 'ipaddr', '~> 1.2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ipaddr

## Usage

```ruby
require 'ipaddr'

ipaddr1 = IPAddr.new "3ffe:505:2::1"

p ipaddr1                   #=> #<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0001/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>

p ipaddr1.to_s              #=> "3ffe:505:2::1"

ipaddr2 = ipaddr1.mask(48)  #=> #<IPAddr: IPv6:3ffe:0505:0002:0000:0000:0000:0000:0000/ffff:ffff:ffff:0000:0000:0000:0000:0000>

p ipaddr2.to_s              #=> "3ffe:505:2::"

ipaddr3 = IPAddr.new "192.168.2.0/24"

p ipaddr3                   #=> #<IPAddr: IPv4:192.168.2.0/255.255.255.0>
```

### NAT64 (RFC 6052) translation

IPAddr::NAT64 translates between IPv4 and IPv6 addresses against an
explicitly declared NAT64 prefix, covering every prefix length allowed
by RFC 6052 (32, 40, 48, 56, 64 and 96):

    nat64 = IPAddr::NAT64.new("64:ff9b::/96")  # or IPAddr::NAT64.well_known

    nat64.embed("192.0.2.33").to_s           #=> "64:ff9b::c000:221"
    nat64.extract("64:ff9b::c000:221").to_s  #=> "192.0.2.33"

    # Reverse translation validates prefix membership and the reserved
    # bits (the "u" octet and the suffix), and rejects anything else:
    nat64.extract("64:ff9c::c000:221")       #=> raises IPAddr::NAT64::Error

    # IPv4 networks map to the exactly covering IPv6 prefix set, or raise
    # if no single prefix can express the translation:
    nat64.embed_prefix("192.0.2.0/24").map(&:cidr)  #=> ["64:ff9b::c000:200/120"]

## Alternative

The [ipaddress](https://rubygems.org/gems/ipaddress) gem is a popular,
extensive library for manipulating IP addresses with a layer of
compatibility with `ipaddr`.  If you need a richer set of features
than `ipaddr` has, try this library instead.

## Development

After checking out the repo, run `bundle install` to install dependencies. Then, run `rake test` to run the tests.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/ipaddr.

## License

The gem is available as open source under the terms of the [2-Clause BSD License](https://opensource.org/licenses/BSD-2-Clause).
