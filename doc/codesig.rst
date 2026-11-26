:mod:`macholib.codesig` --- Read-only verification of code directory page hashes
=====================================================================================

.. module:: macholib.codesig
   :synopsis: Read-only verification of embedded CodeDirectory page hashes

This module recomputes the *normal code slots* recorded in the embedded
CodeDirectory blobs of every slice of a (possibly universal) Mach-O file
and compares them with the digests stored in the file.  Contiguous paged
directories using SHA-1 or SHA-256 are supported; the last page is hashed
with its actual (short) length.  Directories that use a scatter vector,
an unknown hash algorithm, or that are truncated are reported as such,
without affecting the independent conclusions of the other directories.

.. warning::

   The result is evidence about *page contents* only.  Even when every
   recorded digest matches, this says nothing about the identity or
   trustworthiness of the signer: the cryptographic signature itself is
   not validated.

.. function:: verify_code_signature(filename)

   Verify all slices of *filename* and return a
   :class:`VerificationResult`.  The file is only read, never modified.

.. class:: VerificationResult

   .. attribute:: filename

      The verified file.

   .. attribute:: slices

      A list of :class:`SliceVerification`, one per Mach-O slice.

   .. attribute:: note

      A reminder that matching page hashes are not evidence about signer
      trust.

   .. attribute:: matches

      True when every slice has at least one code directory and all of
      them verified cleanly.

   .. method:: describe()

      Return a plain dictionary describing the full result, suitable
      for display or serialisation.

.. class:: SliceVerification

   .. attribute:: arch

      CPU type name of the slice (for example `"x86_64"` or `"ARM64"`).

   .. attribute:: offset

   .. attribute:: size

      File range of the slice.

   .. attribute:: signature_offset

   .. attribute:: signature_size

      File range of the embedded signature blob.

   .. attribute:: directories

      A list of :class:`CodeDirectoryVerification` for the primary and
      alternate code directories.

   .. attribute:: error

      Slice-level problem description, or `None`.

.. class:: CodeDirectoryVerification

   .. attribute:: slot_type

      SuperBlob index type (0 for the primary directory, 0x1000+n for
      alternates).

   .. attribute:: file_offset

      File offset of the CodeDirectory blob.

   .. attribute:: status

      One of `"ok"`, `"mismatch"`, `"unsupported"` or `"truncated"`.

   .. attribute:: reason

      Explanation for non-ok statuses, or `None`.

   .. attribute:: hash_name

   .. attribute:: page_size

   .. attribute:: code_limit

      Hash algorithm, page size and code limit the slots were
      recomputed with.

   .. attribute:: slots

      A list of :class:`PageSlotVerification`, one per normal code
      slot.

.. class:: PageSlotVerification

   .. attribute:: index

      Code slot index.

   .. attribute:: file_range

      Half-open file range `(start, end)` of the page backing this
      slot; the tail page uses its actual length.

   .. attribute:: expected

   .. attribute:: actual

      The digest recorded in the directory and the digest recomputed
      from the file contents (`None` when the page data is missing).

   .. attribute:: matches

      True when both digests are present and equal.

