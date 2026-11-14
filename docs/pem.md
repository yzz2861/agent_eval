# PEM Decoder and Encoder

Often times DER-encoded data is wrapped in PEM encoding. This allows the binary
DER data to be identified and reliably sent over various communication channels.

The `asn1crypto.pem` module includes the following functions and data types:

 - `detect(byte_string)`
 - `unarmor(pem_bytes)`
 - `unarmor_one(pem_bytes, expected_label)`
 - `unarmor_certificate(pem_bytes)`
 - `unarmor_certificates(pem_bytes)`
 - `unarmor_private_key(pem_bytes)`
 - `PEMBlock`
 - `armor(type_name, der_bytes, headers=None)`

## detect()

The `detect()` function accepts a byte string and looks for a `BEGIN` block
line. This is useful to determine in a byte string needs to be PEM-decoded
before parsing.

```python
from asn1crypto import pem, x509

with open('/path/to/cert', 'rb') as f:
    der_bytes = f.read()
    if pem.detect(der_bytes):
        der_bytes = pem.unarmor_certificate(der_bytes)
```

## unarmor()

The `unarmor()` function accepts a byte string and returns an explicit list of
every PEM block it contains. It never silently returns only the first block.
Each block is represented by a `PEMBlock` named tuple with five elements.

 - `label`: a unicode string of the PEM label, such as `CERTIFICATE` or
   `PRIVATE KEY`
 - `headers`: an `OrderedDict` of legacy header fields in the `Name: Value`
   format, typically used by encrypted OpenSSL private keys
 - `der_bytes`: a byte string of the decoded block contents
 - `start_offset`: the byte offset where the block begins
 - `end_offset`: the byte offset immediately after the block

Every block is validated before being returned:

 - the `BEGIN` and `END` labels must match exactly
 - labels must use uppercase ASCII letters, digits and single spaces
 - the base64 body must use canonical base64 with valid padding
 - the decoded content must begin with a DER SEQUENCE and contain complete TLVs
 - empty blocks, nested PEM boundaries and data outside of blocks are rejected
 - CRLF and LF line endings, blank lines and legacy header fields are accepted

Unknown but syntactically valid labels are retained in the returned list.
Callers must inspect or filter the labels instead of assuming the first block
has the expected object type. Error messages never include the base64 body.

```python
from asn1crypto import pem

with open('/path/to/bundle', 'rb') as f:
    blocks = pem.unarmor(f.read())

for block in blocks:
    print(block.label, block.start_offset, block.end_offset)
```

## unarmor_one()

The `unarmor_one()` function requires exactly one block and an explicitly
declared expected label. The label may be a unicode string or an iterable of
allowed labels, such as `pem.PRIVATE_KEY_LABELS`. A different label, multiple
blocks or invalid PEM data raises `ValueError`.

```python
from asn1crypto import pem, x509

block = pem.unarmor_one(pem_bytes, 'CERTIFICATE REQUEST')
csr = x509.Csr.load(block.der_bytes)
```

## Certificate and private key helpers

The convenience functions encode the common label policies while still
rejecting ambiguous input.

 - `unarmor_certificate(pem_bytes)` reads exactly one certificate block and
   returns its DER bytes. Both `CERTIFICATE` and `TRUSTED CERTIFICATE` are
   accepted; private-key labels are rejected.
 - `unarmor_certificates(pem_bytes)` reads one certificate or a bundle of
   certificates and returns all matching `PEMBlock` objects.
 - `unarmor_private_key(pem_bytes)` reads exactly one block using one of the
   labels in `pem.PRIVATE_KEY_LABELS`. Certificate and unrecognized labels are
   rejected, so key parsing never falls back to treating a certificate as key
   material.

```python
from asn1crypto import pem

certs = []
with open('/path/to/ca_certs', 'rb') as f:
    for block in pem.unarmor_certificates(f.read()):
        certs.append(block.der_bytes)

key_block = pem.unarmor_private_key(key_pem_bytes)
```

## armor()

The `armor()` function accepts three parameters: a unicode string of the block
type name, a byte string to encode and an optional keyword argument `headers`,
that should be a `dict` of headers to add after the `BEGIN` line. Headers are
typically only used by encrypted OpenSSL private keys.

```python
from asn1crypto import pem, x509

# cert is an instance of x509.Certificate

with open('/path/to/cert', 'wb') as f:
    der_bytes = cert.dump()
    pem_bytes = pem.armor('CERTIFICATE', der_bytes)
    f.write(pem_bytes)
```
