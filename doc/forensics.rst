:mod:`macholib.forensics` --- Verify multi-architecture excerpt records
=======================================================================

.. module:: macholib.forensics
   :synopsis: Verify forensic excerpt records against Mach-O slices

Mach-O files contain two coordinate systems for file offsets:

* **file coordinates** are measured from the start of the complete file,
  including the fat header of a universal binary.  Older evidence tooling
  recorded these offsets.
* **slice coordinates** are measured from the start of one Mach-O image.
  ``LC_SEGMENT``/``LC_SEGMENT_64`` ``fileoff`` values and section ``offset``
  values use this coordinate system.

The two systems coincide for a thin Mach-O, but differ by the slice base in a
universal binary.  Consequently two excerpts can have identical bytes and
identical digests while belonging to different slices, or to different
positions in the same slice.  A digest match alone therefore never proves
ownership; the declaration must also state its coordinate system and owning
architecture.

Declarations
------------

An excerpt declaration is a mapping (or an object with matching attributes):

.. code-block:: python

   {
       "id": "payload@0x200",
       "coordinate_system": "slice",       # or "file"
       "offset": 0x200,
       "length": 16,
       "digest": "<hex sha256>",
       "arch": "arm64",
       # optional:
       "slice_index": 0,
       "segment_lengths": {"__TEXT": 16},
       "parts": [
           {"offset": 0x200, "length": 8},
           {"offset": 0x300, "length": 8},
       ],
   }

``coordinate_system`` accepts the aliases ``file``/``absolute``/``legacy``
and ``slice``/``image``/``relative``.  ``arch`` accepts an architecture name
(``arm64``, ``x86_64``), a cputype, a ``(cputype, cpusubtype)`` pair, or a
mapping.  A digest may be given as ``"digest"`` with ``"digest_algorithm"``,
or with a key such as ``"sha256"``; the ``"sha256:<hex>"`` form is accepted
too.  A legacy record that has no coordinate marker can set ``legacy: true``
(or ``old: true``); the numeric offset alone is never used to guess that.

When ``parts`` is present the digest is calculated over the concatenation of
the parts in declaration order, and every part has its own coordinate system
and length.  ``segment_lengths``, when supplied, is checked against the
segments that actually cover the excerpt.

Verification
------------

.. function:: verify_excerpt(source, declaration, ...)

   Verify one declaration and return a :class:`VerificationResult`.
   ``source`` may be a filename, a path-like object, or a parsed
   :class:`macholib.MachO.MachO` instance.  ``default_coordinate_system`` and
   ``default_arch`` supply values for declarations that omit them.

.. function:: verify_excerpts(source, declarations, ...)

   Verify a bound ledger of declarations.  Returns a :class:`LedgerResult`
   whose ``ok`` attribute is true only when every entry is verified.

.. function:: verify_ledger(declarations, source=None, ...)

   Verify a ledger whose entries may each carry their own
   ``path``/``filename``/``file``.  Entries that omit a path use ``source``.
   Declarations for the same file share one parsed verifier.

.. function:: convert_offset(source, offset, coordinate_system, arch=None, slice_index=None, length=1)

   Convert between file and slice coordinates.  For an old file-coordinate
   record the result contains the reconstructed slice-relative ``offset``
   and ``reconstructed=True``.  If the owning slice cannot be identified
   uniquely an :class:`AmbiguousOffsetError` lists the missing evidence.

.. class:: ExcerptVerifier(source)

   Reusable verifier bound to one file, with ``verify()``, ``verify_all()``
   and ``convert()`` methods.

Result fields include the resolved ``coordinate_system``, ``slice``,
``slice_index``, ``resolved_arch``, per-part offsets, ``segment_lengths``,
the declared and actual digests, the converted offsets, ``missing_evidence``
and diagnostic ``problems``.  Typical statuses are ``verified``,
``ambiguous``, ``ownership_mismatch``, ``digest_mismatch``,
``coordinate_missing`` and ``segment_length_mismatch``.

.. code-block:: python

   from macholib.forensics import verify_excerpt

   result = verify_excerpt("universal.bin", {
       "coordinate_system": "file",
       "offset": 0x1200,
       "length": 16,
       "digest": "<hex sha256>",
       "arch": "arm64",
   })
   print(result.status, result.converted["offset"])

Entry points on the parsed objects are also available:
``MachO.verify_excerpt``/``verify_excerpts`` and
``MachOHeader.verify_excerpt`` (which defaults to that header's slice).
