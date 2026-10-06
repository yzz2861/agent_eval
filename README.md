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

# Local datetimes, dates and times are subclasses of Time. Offset datetimes are Time.
times = <<-EOS
  odt = 1979-05-27T07:32:00Z
  ldt = 1979-05-27T07:32:00
  ld  = 1979-05-27
  lt  = 07:32:00
EOS
TomlRB.parse(times).transform_values(&:class)
# => {"odt"=>Time, "ldt"=>TomlRB::LocalDateTime, "ld"=>TomlRB::LocalDate, "lt"=>TomlRB::LocalTime}
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

Layered Configuration Merge
---------------------------

TomlRB.merge merges configuration hashes from lowest to highest
precedence. Tables are merged deeply. Plain arrays are replaced as a whole,
while arrays of tables can be declared as member collections.

```ruby
base = TomlRB.parse(<<~TOML)
  [[services]]
  name = "api"
  port = 80

  [[services]]
  name = "web"
  port = 8080
TOML

environment = TomlRB.parse(<<~TOML)
  [[services]]
  name = "api"
  port = 8081

  [[services]]
  name = "worker"
  port = 9000
TOML

local = {
  "services" => [
    TomlRB.delete_member("name", "web"),
    {"name" => "api", "debug" => true},
    {"name" => "admin", "port" => 7000}
  ]
}

merged = TomlRB.merge(
  base,
  environment,
  local,
  array_tables: {"services" => "name"}
)
# services are, in order: api, worker, admin
```

- array_tables maps a table path, such as "services" or [:app, :services],
  to the field that identifies each member, such as "name".
- Matching members are merged in place. New members are appended. Use
  TomlRB.delete_member(identity_key, identity_value) in a higher layer to
  remove a member.
- Use TomlRB::DELETE as a scalar or nested-table value to delete that key.
  The object is provided by Ruby, so it cannot equal a value parsed from TOML.
- Do not use either deletion operation in a plain array; those arrays are
  replaced wholesale.
- Missing identities, repeated identities and table/scalar incompatibilities
  raise TomlRB::MergeConflictError.
- The merger returns a new hash and does not modify the input layers.
- TomlRB.dump(merged) writes each surviving member once as [[services]], so
  the merged result remains valid TOML.

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
