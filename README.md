# Python-Multipart

[![CI](https://github.com/Kludex/python-multipart/actions/workflows/main.yml/badge.svg)](https://github.com/Kludex/python-multipart/actions/workflows/main.yml)
[![PyPI](https://img.shields.io/pypi/v/python-multipart.svg)](https://pypi.org/project/python-multipart)
[![Python versions](https://img.shields.io/pypi/pyversions/python-multipart.svg)](https://pypi.org/project/python-multipart)
[![Discord](https://img.shields.io/discord/1051468649518616576?logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/RxKUF5JuHs)

Python-Multipart reads the data that a web browser sends when someone submits a form or uploads a file.

```console
pip install python-multipart
```

It powers file uploads in [Starlette](https://starlette.dev) and [FastAPI](https://fastapi.tiangolo.com).

## What problem does it solve?

### A form sends data

When you fill in a form on a website and click "Submit", your browser sends the data to a server.
The server is a program, maybe written in Python, that has to read that data and make sense of it.

### Files need a special format

A form with only text, like a username, is sent as one short line: `username=alice`.

A form with a file is different. A file can contain anything, even text that looks like `username=alice`.
So the browser uses a format called `multipart/form-data`. It splits the request into **parts**, one per form field, separated by a **boundary**: a marker string the browser picks.

This is what the server receives when you send a username and a file called `cat.txt`:

```text
--boundary
Content-Disposition: form-data; name="username"

alice
--boundary
Content-Disposition: form-data; name="avatar"; filename="cat.txt"
Content-Type: text/plain

meow
--boundary--
```

Each part has some headers (the field name, the file name) and then the content.
Every line ends with `\r\n` (a carriage return and a newline), which is why the examples below write `\r\n` explicitly.
A **parser** is the code that turns this text back into fields and files. Python-Multipart is that parser.

### Big files do not fit in memory

An upload can be a 5 GB video. If the server reads the whole request before it starts working, it needs 5 GB of memory, per upload.

Python-Multipart is a **streaming** parser. You give it the request a small piece (a **chunk**) at a time, and it tells you what it found as soon as it finds it. The full request never has to be in memory.

## Usage

### Parse a whole form

```python
from io import BytesIO

from python_multipart import parse_form

body = (
    b"--boundary\r\n"
    b'Content-Disposition: form-data; name="username"\r\n'
    b"\r\n"
    b"alice\r\n"
    b"--boundary\r\n"
    b'Content-Disposition: form-data; name="avatar"; filename="cat.txt"\r\n'
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"meow\r\n"
    b"--boundary--\r\n"
)
headers = {"Content-Type": "multipart/form-data; boundary=boundary"}


def on_field(field):
    print("Field:", field.field_name, "=", field.value)


def on_file(file):
    file.file_object.seek(0)
    print("File:", file.field_name, file.file_name, file.file_object.read())


parse_form(headers, BytesIO(body), on_field, on_file)
```

Output:

```text
Field: b'username' = b'alice'
File: b'avatar' b'cat.txt' b'meow'
```

`parse_form` reads the body in chunks and calls your functions:

- `on_field` runs for every text field.
- `on_file` runs for every uploaded file.

Small files stay in memory. Once a file grows past 1 MiB, it is moved to a temporary file on disk, so a large upload does not fill up your memory.

> **Real servers do not use `BytesIO`.** In a real application, the body comes from the network. Any object with a `read()` method that returns `bytes` works.

### Handle each chunk yourself

`parse_form` still saves every file somewhere. When you want full control, for example to send an upload straight to cloud storage, use `MultipartParser`:

```python
from python_multipart import MultipartParser

chunks = [
    b"--boundary\r\n",
    b'Content-Disposition: form-data; name="avatar"; filename="cat.txt"\r\n\r\n',
    b"me",
    b"ow\r\n--boundary--\r\n",
]


def on_part_data(data, start, end):
    print("Got a piece of the file:", data[start:end])


parser = MultipartParser("boundary", callbacks={"on_part_data": on_part_data})
for chunk in chunks:
    parser.write(chunk)
parser.finalize()
```

Output:

```text
Got a piece of the file: b'me'
Got a piece of the file: b'ow'
```

The file arrived in two chunks, and you saw each one as it arrived. Nothing was stored.

Instead of copying data, the parser passes you a buffer plus `start` and `end` positions that mark the part you care about.

### Receive nested MIME packages

A form can contain parts that are themselves MIME packages. The opt-in nested
receiving mode parses those packages recursively and gives every part a
structural path such as `0/1` (first top-level part, second child). Approval
scopes are attached to those paths.

```python
from io import BytesIO

from python_multipart import ApprovalScope, parse_nested_form

body = (
    b"--outer\r\n"
    b'Content-Disposition: form-data; name="bundle-a"\r\n'
    b"Content-Type: multipart/mixed; boundary=pkg-a\r\n\r\n"
    b"--pkg-a\r\n"
    b'Content-Disposition: attachment; name="attachment"; filename="a.pdf"\r\n'
    b"Content-Type: application/pdf\r\n"
    b"X-Correlation-ID: a\r\n\r\n"
    b"AAA\r\n"
    b"--pkg-a--\r\n"
    b"--outer\r\n"
    b'Content-Disposition: form-data; name="bundle-b"\r\n'
    b"Content-Type: multipart/mixed; boundary=pkg-b\r\n\r\n"
    b"--pkg-b\r\n"
    b'Content-Disposition: attachment; name="attachment"; filename="b.pdf"\r\n'
    b"Content-Type: application/pdf\r\n"
    b"X-Correlation-ID: b\r\n\r\n"
    b"BBB\r\n"
    b"--pkg-b--\r\n"
    b"--outer--\r\n"
)

scopes = [
    ApprovalScope(path=(), allowed_nested_types={"multipart/mixed"}),
    ApprovalScope(path=(0,), name=b"bundle-a", content_type="multipart/mixed", allowed_types={"application/pdf"}),
    ApprovalScope(path=(1,), name=b"bundle-b", content_type="multipart/mixed", allowed_types={"application/pdf"}),
    ApprovalScope(path=(0, 0), name=b"attachment", content_type="application/pdf", correlation_id=b"a"),
    # This declaration is in package 0, but the matching part is in package 1.
    ApprovalScope(path=(0, 1), name=b"attachment", content_type="application/pdf", correlation_id=b"b"),
]

receipt = parse_nested_form(
    {"Content-Type": b"multipart/form-data; boundary=outer"},
    BytesIO(body),
    scopes=scopes,
    require_declaration=True,
)

for part in receipt:
    print(part.path, part.decision.value, part.declared_at, part.declared_in_own_package)
```

Output:

```text
0/0 accepted 0/0 True
0 accepted 0 True
1/0 rejected 0/1 False
1 accepted 1 True
```

Both children are named `attachment`; their paths keep them distinct. The
second child is rejected because its only matching declaration lives in the
neighbouring package, not in its own package. `PartReceipt.belongs_to` makes
that explicit.

The mode follows these rules:

- A scope at a path approves only the part at that exact path. A parent
  package approval never fills in a declaration for a child.  This is enforced
  by default (`require_declaration=True`); set it to false for receipt-only
  inspection.
- `allowed_types` and `allowed_nested_types` are ceilings for a package's
  direct children. Child scopes intersect with the parent's effective sets and
  cannot widen them; package receipts report the effective sets.
- Same-named children are keyed by path. A local correlation identifier
  (`X-Correlation-ID` by default) is compared only inside the package where it
  appears.
- `missing_child_header` controls a missing `Content-Disposition` or `name`:
  `"reject"` (default) records a rejected receipt, `"error"` raises, and
  `"allow"` keeps the part with no name.  A missing `Content-Type` leaves the
  part untyped; if its scope declares a type, the receipt records
  `missing_content_type`.
- `unknown_encoding` controls an unknown `Content-Transfer-Encoding`:
  `"reject"` (default) records a rejected receipt, `"opaque"` accepts raw
  bytes, and `"error"` raises. An encoded package cannot be recursed into.
  Leaf payloads are not transfer-decoded by this mode; the receipt records the
  encoding and `on_part_data` receives the raw bytes.
- Multipart parts are only recursed into when their media type is allowed and
  they have a boundary. Otherwise the receipt records `nested_type_not_allowed`
  or `missing_boundary`.

Receipts are streaming too. `on_receipt` fires only when the part's subtree is
structurally complete. If a child package is unterminated, its receipt and its
parent package receive `pending` instead of a guessed decision. The normal
`on_part_begin`, header, `on_part_end`, and `on_end` callbacks still fire;
`on_end` fires once for the root package.  For path-aware streaming use
`on_part_begin_path(path)`, `on_part_headers(path, headers)` and
`on_part_data_path(path, data, start, end)`.  `on_part_data` receives leaf data
only.

## Learn more

- [Documentation](https://kludex.github.io/python-multipart/)
- [API reference](https://kludex.github.io/python-multipart/api/)
- [Changelog](https://github.com/Kludex/python-multipart/blob/main/CHANGELOG.md)

## License

Apache 2.0. See [LICENSE.txt](LICENSE.txt).
