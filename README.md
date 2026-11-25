# dpkt

![Python package](https://github.com/kbandla/dpkt/workflows/Python%20package/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/kbandla/dpkt/badge.svg?branch=master)](https://coveralls.io/github/kbandla/dpkt?branch=master)
[![supported-versions](https://img.shields.io/pypi/pyversions/dpkt.svg)](https://pypi.python.org/pypi/dpkt)
[![supported-versions](https://img.shields.io/pypi/implementation/dpkt.svg)](https://pypi.python.org/pypi/dpkt)

The dpkt project is a python module for fast, simple packet parsing, with definitions for the basic TCP/IP protocols.

### Offline evidence projection

`dpkt.evidence` produces a read-only, allow-listed projection of link-layer
and IPv4 header fields for selected pcap records.  It reports the exact byte
range of every disclosed field in the saved capture, redacts MAC/IP addresses
with projection-scoped HMAC-SHA256 pseudonyms, and binds each value and source
position with independent commitments.  It never rewrites or sends packets.

See [docs/evidence_projection.md](docs/evidence_projection.md) for the schema
and CLI.  A small gzip fixture and its generator live in
`examples/data/evidence_projection.pcap.gz` and
`examples/make_evidence_fixture.py`.

### Installation
```
pip install dpkt
```

### Examples and Documentation
- [Main Docs for DPKT](https://kbandla.github.io/dpkt)


