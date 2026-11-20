:mod:`macholib.data_in_code` --- Read-only data-in-code evidence
================================================================

This module builds a per-slice evidence manifest for offline disassembly.
It reads ``LC_DATA_IN_CODE`` records, executable section attributes and
symbol locations without modifying the Mach-O file.

The manifest separates:

* ``data_regions`` for intervals backed by a known data-in-code kind;
* ``instruction_candidates`` for executable bytes that are not covered by
  a data-in-code record (these are candidates, not confirmed instructions);
* ``conflicts`` for contradictory clues, including overlapping records and
  symbols that point inside a recorded data interval;
* ``unresolved`` for records with unknown kinds.  Unknown records are not
  treated as data support and are not promoted to confirmed instructions.

Every record, region, candidate, conflict and symbol includes the slice
index, slice-relative file offset, absolute file offset and virtual address
where those values can be derived.

Usage
-----

.. code-block:: python

   from macholib.data_in_code import build_evidence_manifest

   manifest = build_evidence_manifest("firmware.bin")
   for slice_data in manifest["slices"]:
       print(slice_data["slice_index"], slice_data["endian"])
       print(slice_data["data_regions"])
       print(slice_data["instruction_candidates"])
       print(slice_data["conflicts"])

The same manifest is available from a loaded object:

.. code-block:: python

   from macholib.MachO import MachO

   macho = MachO("firmware.bin")
   manifest = macho.build_data_in_code_manifest()

To emit JSON without writing to the input file:

.. code-block:: shell

   python -m macholib data-in-code firmware.bin

The small dual-slice fixture in
``macholib_tests/samples/dual_slice_data_in_code.bin`` records a jump table
in one slice and leaves the same relative interval as an instruction
candidate in the other.
