# Internationalized Domain Names in Applications (IDNA)

Support for [Internationalized Domain Names in Applications
(IDNA)](https://tools.ietf.org/html/rfc5891) and [Unicode IDNA
Compatibility Processing](https://unicode.org/reports/tr46/). It
supersedes the standard library's `encodings.idna`, which only
implements the 2003 specification, offering broader script coverage and
limiting domains with known security vulnerabilities.

## Usage

Package may be installed from [PyPI](https://pypi.org/project/idna/) via
the typical methods (e.g. `python3 -m pip install idna`)

For typical usage, the `encode` and `decode` functions will take a
domain name argument and perform a conversion to ASCII-compatible encoding
(known as A-labels), or to Unicode strings (known as U-labels)
respectively.

```pycon
>>> import idna
>>> idna.encode('ドメイン.テスト')
b'xn--eckwd4c7c.xn--zckzah'
>>> print(idna.decode('xn--eckwd4c7c.xn--zckzah'))
ドメイン.テスト
```

Conversions can be applied at a per-label basis using the `ulabel` or
`alabel` functions for specialized use cases.


### Compatibility Mapping (UTS #46)

This library provides support for [Unicode IDNA Compatibility
Processing](https://unicode.org/reports/tr46/) which normalizes input from
different potential ways a user may input a domain prior to performing the IDNA
conversion operations. This functionality, known as a
[mapping](https://tools.ietf.org/html/rfc5895), is considered by the
specification to be a local user-interface issue distinct from IDNA
conversion functionality.

For example, "Königsgäßchen" is not a permissible label as capital letters
are not allowed. UTS #46 will convert this into lower case prior to applying
the IDNA conversion.

```pycon
>>> import idna
>>> idna.encode('Königsgäßchen')
...
idna.core.InvalidCodepoint: Codepoint U+004B at position 1 of 'Königsgäßchen' not allowed
>>> idna.encode('Königsgäßchen', uts46=True)
b'xn--knigsgchen-b4a3dun'
>>> idna.decode('xn--knigsgchen-b4a3dun')
'königsgäßchen'
```

When performing a decode operation for display purposes, `decode()`
accepts a `display=True` argument that leaves any `xn--` label that
fails to decode unchanged. This is useful for user interface display
where a domain is in use, the A-label form can be presented when it
is not a valid IDN.


## Canonical name comparison

Comparing a user-supplied domain against an identifier such as a DNS
name in a certificate SAN must not be done by lowercasing the raw
input: that skips the UTS #46 mappings, Unicode label separators,
normalisation and A-label encoding, and wrongly rejects valid names
that differ only in case or carry a trailing dot. Use
`idna.canonicalize()`, which applies the full mapping-then-IDNA 2008
pipeline and returns an `idna.CanonicalName`:

```pycon
>>> import idna
>>> name = idna.canonicalize('WWW.Example.COM.')
>>> name
CanonicalName(alabel=b'www.example.com', idna_version='3.20', unicode_version='18.0.0')
>>> name.alabel == idna.canonicalize('www.example.com').alabel
True
```

`idna.match()` canonicalises both sides and performs the byte
comparison, accepting an existing `CanonicalName` to avoid repeating
the work:

```pycon
>>> idna.match('xn--ZCKZAH.', 'テスト')
True
```

The result carries the library release (`idna_version`) and the
Unicode release of the lookup tables (`unicode_version`) that
produced it, so services can log or verify which rule set was used
and avoid comparing names canonicalised with different tables.


## Exceptions

All errors raised during conversion derive from the `idna.IDNAError`
base class. The more specific exceptions are:

* `idna.IDNABidiError` — raised when a label contains an illegal
  combination of left-to-right and right-to-left characters.
* `idna.InvalidCodepoint` — raised when a label contains a codepoint
  that is INVALID for IDNA.
* `idna.InvalidCodepointContext` — raised when a CONTEXTO or CONTEXTJ
  codepoint appears in a position whose contextual requirements are
  not satisfied.

Exceptions carry machine-readable attributes so that applications do
not need to parse the message: `code` is a short, stable identifier
for the rule that failed (such as `disallowed_codepoint` or
`label_too_long`); and, when the failure can be attributed to a
particular character, `text` (the label or domain being validated),
`codepoint` (the offending codepoint as an integer) and `position`
are set. 


## Command-line tool

The package supports command-line usage to convert domain names
between their Unicode and ASCII-compatible forms. It can be run either
as a module (`python3 -m idna`) or, once installed (such as with `uv
tool` or `pipx`), via the `idna` script:

```bash
$ uv tool install idna
$ idna xn--e1afmkfd.xn--p1ai
пример.рф
$ idna пример.рф
xn--e1afmkfd.xn--p1ai
```

Mode can be specified with `-e`/`--encode` or `-d`/`--decode`, otherwise
it will be chosen automatically based on the first input. Multiple
domains can be supplied either as arguments or through standard input.
UTS #46 mapping is applied by default, which lets the tool accept
inputs that aren't strictly valid IDNA 2008 by normalising them first,
pass `--strict` to disable UTS #46.

Conversion failures are reported on stderr together with the
offending input; processing continues with the remaining domains and
the tool exits with a non-zero status if any conversion failed.


## Additional Notes

* **Python version support**. This library supports Python 3.10 and higher.
  As this library serves as a low-level toolkit for a variety of
  applications, we strive to support all versions of Python that are
  not beyond end-of-life. Free-threaded Python is also supported,
  as the library holds no mutable global state the functions can be
  called concurrently from multiple threads.

* **Unicode version**. The IDNA and UTS #46 lookup tables are generated
  from a specific Unicode release. Some Unicode data depends on the
  running Python's `unicodedata` module, so on an older Python a
  character new to Unicode may be rejected as unknown even if this
  library knows about it.

* **Emoji**. It is an occasional request to support emoji domains in
  this library. Encoding of symbols like emoji is expressly prohibited by
  the IDNA technical standard, and emoji domains are broadly phased
  out across the domain industry due to associated security risks.

* **Regenerating lookup tables**. The IDNA and UTS #46 functionality
  relies upon pre-calculated lookup tables, generated using the
  `idna-data` script in [`tools/`](tools/README.md).
