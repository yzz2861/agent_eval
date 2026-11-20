universal_guard
===============

Release protection coverage checks for Mach-O universal artifacts, built on
top of :mod:`macholib`.

The library answers one release-gate question: given the supported
architecture/platform matrix, the deployment scope of every slice and the
required protection attributes, which terminals are actually **covered**,
which ones are **at risk**, and which ones **lack evidence**?

What the library does and does not do
-------------------------------------

* It parses every slice of a universal (or thin) Mach-O image with
  ``macholib``: CPU type/subtype, platform and minimum OS declaration
  (``LC_BUILD_VERSION`` or legacy ``LC_VERSION_MIN_*``), header flags,
  segment protections, FairPlay encryption and the embedded code signature
  SuperBlob (CodeDirectory flags, cdhash, identifier and team id).
* It computes a digest (SHA-256/SHA-1) of every slice and reads the
  CodeDirectory cdhash. The cdhash implementation is cross-checked against
  the system ``codesign`` tool on real binaries.
* It never performs cryptographic verification. The publishing backend
  verifies signatures itself and passes the verdict in. The library binds
  that verdict to a concrete architecture and to the digest of the exact
  slice bytes that were inspected, so a valid verdict for one slice can
  never be replayed against a different or re-signed slice.

Inputs
------

1. **Architecture/platform matrix** - a list of :class:`Terminal` objects,
   each with ``cpu_type``, ``cpu_subtype`` (capability bits are masked),
   ``platform`` and the running ``os_version``.
2. **Per-slice deployment scope** - optional :class:`DeploymentScope`
   restrictions (platform list, OS range, CPU types).
3. **Required protection attributes** - a :class:`ProtectionPolicy` naming
   the attributes every released slice must have.
4. **Verification results** - caller-supplied dicts/VerificationEvidence
   carrying ``verified`` plus the claimed slice digest, architecture and
   optional expected cdhash.

Status model
------------

* ``covered`` - a selectable slice exists, evidence binds to its digest and
  passes, and every required protection attribute is present.
* ``at_risk`` - a selectable slice exists with sound evidence but a
  protection policy rule is not met.
* ``missing_evidence`` - no selectable slice, the deployment scope excludes
  the terminal, or the evidence is absent / fails to bind / reports a
  verification failure.

Every verdict carries stable machine-readable reason codes
(:class:`ReasonCode`) explaining the decision.

Slice selection follows the kernel/dyld rules: CPU type must match, the
slice subtype (after masking capability bits) must not exceed the terminal
subtype, the platform must match, and the terminal OS must be at least the
slice minimum OS. When several slices qualify, the most specific subtype
wins.

Synthetic artifacts and minimum-OS changes
------------------------------------------

:mod:`universal_guard.synthesize` emits minimal, spec-conformant 64-bit
Mach-O slices (``mach_header_64``, non-writable ``__TEXT``,
``LC_BUILD_VERSION`` and a hand-built SuperBlob/CodeDirectory) and packs
them into a fat image. ``rewrite_minimum_os`` changes the minimum OS of one
slice in place, and ``diff_reports`` / ``explain_change`` report which
terminals moved between states and why.

Example
-------

``examples/release_gate_demo.py`` builds a two-slice artifact whose arm64
slice fails backend verification, classifies the terminal matrix, then
raises the x86_64 minimum OS from 10.13 to 10.15 and prints the affected
terminal set and the reason for the change::

    .venv/bin/python examples/release_gate_demo.py

Run the tests with::

    .venv/bin/python -m unittest discover -t . -s universal_guard_tests
