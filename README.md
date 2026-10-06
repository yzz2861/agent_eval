![TOML Logo](https://github.com/toml-lang/toml/blob/main/logos/toml-100.png)


toml-rb
=======

[![Gem Version](https://badge.fury.io/rb/toml-rb.svg)](http://badge.fury.io/rb/toml-rb)
[![Build Status](https://github.com/emancu/toml-rb/actions/workflows/ruby.yml/badge.svg)](https://github.com/emancu/toml-rb/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/emancu/toml-rb/badges/gpa.svg)](https://codeclimate.com/github/emancu/toml-rb)
[![RubyGem](https://img.shields.io/gem/dt/toml-rb.svg)](https://rubygems.org/gems/toml-rb)

A pure Ruby [TOML](https://github.com/toml-lang/toml) parser and dumper with no runtime dependencies.

toml-rb implements [TOML 1.1.0](https://toml.io/en/v1.1.0) and passes all [toml-test](https://github.com/toml-lang/toml-test) v2.2.0 decoder tests for that version.

Installation
------------

    $ gem install toml-rb

Or add this line to your Gemfile:

    gem "toml-rb", "~> 6.0"

Parser Usage
------------

```ruby
require 'toml-rb'

# From a file!
path = File.join(File.dirname(__FILE__), 'path', 'to', 'file')
TomlRB.load_file(path)

# From a stream!
stream = <<-EOS
  title = "wow!"

  [awesome]
    you    = true
    others = false
EOS
TomlRB.parse(stream)
# => {"title"=>"wow!", "awesome"=>{"you"=>true, "others"=>false}}

# You want symbols as your keys? No problem!
TomlRB.load_file(path, symbolize_keys: true) 
# Works the same for TomlRB.parse

# Dates and times are exact value objects, not Ruby Time objects.
times = <<-EOS
  odt = 1979-05-27T07:32:00Z
  ldt = 1979-05-27T07:32:00
  ld  = 1979-05-27
  lt  = 07:32:00
EOS
TomlRB.parse(times).transform_values(&:class)
# => {"odt"=>TomlRB::OffsetDateTime, "ldt"=>TomlRB::LocalDateTime,
#     "ld"=>TomlRB::LocalDate, "lt"=>TomlRB::LocalTime}
#
# Every fractional second digit is retained, even past the nine nanosecond
# digits a Ruby Time can hold:
parsed = TomlRB.parse("ts = 1979-05-27T07:32:00.123456789012")["ts"]
parsed.fraction # => "123456789012"
parsed.subsec   # => (30864197253/250000000000)
#
# Converting to a Time is explicit. Local values have no time zone, so the
# caller must name one; when more than nine fraction digits are present, the
# caller must also say how to round them to nanoseconds:
parsed.to_time(zone: :utc, rounding: :truncate) # => 1979-05-27 07:32:00.123456789 UTC
parsed.to_time(zone: "+09:00", rounding: :round)
#
# Offset date-times convert in their declared offset:
TomlRB.parse("ts = 1979-05-27T00:32:00-07:00")["ts"].to_time
# => 1979-05-27 00:32:00 -0700
#
# Local values are never compared as UTC: a local date-time is not equal to
# an offset date-time, even when their wall-clock fields look the same.
```

Dumper Usage
------------

```ruby
require 'toml-rb'

# Simple example
TomlRB.dump( simple: true)
# => "simple = true\n"


# Complex example
hash = { 
    "title"=>"wow!", 
    "awesome"=> {
        "you"=>true, 
        "others"=>false
    }
}

TomlRB.dump(hash)
# => "title = \"wow!\"\n[awesome]\nothers = false\nyou = true\n"
```

Conformance
-----------

`toml-rb` is exercised against the official
[toml-test](https://github.com/toml-lang/toml-test) conformance suite for both
TOML 1.0.0 and TOML 1.1.0. The harness lives in:

- `tool/toml-test-decoder` — toml-test decoder shim.
- `.github/workflows/conformance.yml` — CI workflow (per-version matrix).
- `.github/toml-test-skip-1.0.txt` and `.github/toml-test-skip-1.1.txt` —
  skip-lists of toml-test names for each spec version.

The TOML 1.1.0 skip-list is empty. The TOML 1.0.0 skip-list has 9 tests with
documents that TOML 1.0.0 forbids and TOML 1.1.0 allows. `toml-rb` accepts
TOML 1.1.0 syntax and has no option to select the spec version, so these tests
fail. CI runs toml-test with `-skip-must-err`, so the run fails when a skipped
test passes.

Contributing
------------

1. Fork it
2. Create your feature branch `git checkout -b my-new-feature`
3. Add tests and commit your changes `git commit -am 'Add some feature'`
4. Run tests `$ rake`
5. Push the branch `git push origin my-new-feature`
6. Create new Pull Request

License
-------

MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
