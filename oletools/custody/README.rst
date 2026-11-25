Progressive custody inspection
==============================

This package gives oletools a backend for staged, custody-managed
inspection of documents that may contain embedded objects.

Workflow
--------

1. **First sampling (structure only).** ``Backend.create_manifest`` opens
   just the container metadata - the OLE header/FAT/directory or the ZIP
   central directory - and records every embedded object's name, logical
   size and physical byte location in a :class:`CustodyManifest`.  No
   object payload is read.
2. **Approval.** The security team records an :class:`Approval` for a
   specific observed object.  Approvals are anchored to the object's name,
   offset and size and to the root document digest.
3. **Progressive pass.** ``Backend.inspect`` takes the manifest as input,
   re-observes the current structure without reading payloads, and
   re-associates each approval with a fresh observation:

   * a replaced root document revokes approvals (``file_replaced``);
   * a same-named object whose byte location moved revokes its approval
     (``object_moved``);
   * a disappearing object revokes its approval (``object_removed``);
   * a digest mismatch on release revokes the approval
     (``content_mismatch``).

4. **Single-object release.** Only an active approval is released.  The
   read goes through a :class:`RangeGate` that permits exactly the bytes
   of that one object; neighbouring objects stay sealed but remain visible
   in the structural observation.

Safety guarantees
-----------------

* A :class:`GuardedFile` rejects any read outside its gate *before*
  touching the underlying stream, including unbounded ``read()`` calls, so
  automated checks cannot consume full unapproved content.
* ZIP members are decompressed from bytes already read through a gate; the
  archive is never reopened for unapproved members.
* OLE streams are rebuilt sector by sector from the FAT / mini-FAT chain
  and truncated to the logical stream size, so sector slack and adjacent
  streams never leak.

Persistence
-----------

Manifests are JSON documents (``CustodyManifest.save`` / ``load``) and can
be handed between the first-line reviewer and the security group.  The
``python -m oletools.custody`` CLI exposes ``seal``, ``approve`` and
``inspect`` subcommands.
