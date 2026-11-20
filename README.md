PyYAML
======

A full-featured YAML processing framework for Python

## Installation

To install, type `python setup.py install`.

By default, the `setup.py` script checks whether LibYAML is installed and if
so, builds and installs LibYAML bindings.
To skip the check and force installation of LibYAML bindings, use the option
`--with-libyaml`: `python setup.py --with-libyaml install`.
To disable the check and skip building and installing LibYAML bindings, use
`--without-libyaml`: `python setup.py --without-libyaml install`.

When LibYAML bindings are installed, you may use fast LibYAML-based parser and
emitter as follows:

    >>> yaml.load(stream, Loader=yaml.CLoader)
    >>> yaml.dump(data, Dumper=yaml.CDumper)

If you don't trust the input YAML stream, you should use:

    >>> yaml.safe_load(stream)

## Testing

PyYAML includes a comprehensive test suite.

To run the complete local test suite, type:

    make test

This creates a local Python environment, runs the pure Python tests, builds a
local copy of LibYAML, and then runs the LibYAML extension tests. The local
LibYAML build is pinned by `LIBYAML-REF`, which defaults to `0.2.5`.

To run only one test mode:

    make test-python
    make test-libyaml

To test with a specific Python version:

    make test PYTHON-VERSION=3.13.5

## Offline release checks

`yaml.release_check()` parses a configuration with `SafeLoader` and checks
secret identifiers after YAML aliases and merge keys have been expanded.  It
does not construct Python objects or read a secret store.  The caller supplies
the identifiers and the consumer locations that may use them:

    report = yaml.release_check(
        source,
        {"secret://payments/db": ["/release/token"]},
    )

Each finding retains the destination path and location.  Alias findings also
carry the anchor name and definition location, but never the source scalar
value.  The inverse rule form is available with
`consumer_rules={"/release/token": {"secret://payments/db"}}`.

## Further Information

* For more information, check the
  [PyYAML homepage](https://github.com/yaml/pyyaml).

* [PyYAML tutorial and reference](http://pyyaml.org/wiki/PyYAMLDocumentation).

* Discuss PyYAML with the maintainers on
  Matrix at https://matrix.to/#/#pyyaml:yaml.io or
  IRC #pyyaml irc.libera.chat

* Submit bug reports and feature requests to the
  [PyYAML bug tracker](https://github.com/yaml/pyyaml/issues).

## License

The PyYAML module was written by Kirill Simonov <xi@resolvent.net>.
It is currently maintained by the YAML and Python communities.

PyYAML is released under the MIT license.

See the file LICENSE for more details.
