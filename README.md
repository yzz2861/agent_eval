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

## CIDR sets

`IPAddr::CIDRSet` represents a set of network prefixes for rules of
the shape "this range, minus a few exceptions".  Blocks are stored as
address intervals rather than individual addresses, so even an IPv6
/32 costs only a handful of intervals: memory usage stays
proportional to the number of prefixes, never to the number of
addresses.  IPv4 and IPv6 blocks are tracked separately; whether an
IPv4-mapped IPv6 address counts as IPv4 is decided by the explicit
`ipv4_mapped:` option (`:ipv6` by default, `:ipv4` to convert).

```ruby
require 'ipaddr'

set = IPAddr::CIDRSet.new(%w[10.0.0.0/8 192.168.0.0/16])
set -= IPAddr::CIDRSet.new("10.1.2.0/24")   # union: |, intersection: &, difference: -

set.include?("10.1.2.3")    #=> false
set.include?("10.1.3.3")    #=> true

set.to_a.map(&:cidr)        #=> normalized blocks: contained entries removed,
                            #   exactly mergeable neighbors combined
```

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
