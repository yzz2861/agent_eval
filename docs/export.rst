.. _export-chapter:
.. highlight:: python

============================
Re-exporting cleaned content
============================

Sometimes a fragment is cleaned once and then sent through a *second*
policy: a customer-service representative pastes a cleaned user comment into
a rich-text e-mail, while the back office can still edit the original
comment.  Re-running :py:func:`bleach.clean` on its own is not enough,
because the second policy may be wider than the first and silently bring
back markup that was deliberately removed.

The :py:mod:`bleach.export` module pairs each cleaned fragment with a
:py:class:`~bleach.export.PolicyRecord` describing the capabilities (tags,
attributes and protocols) the cleaning pass was actually allowed to keep.
On re-export those recorded capabilities are intersected with the new
policy, so a wider export can never restore something the first pass
removed--even when a :py:class:`~bleach.linkifier.Linker` or one of its
callbacks (such as :py:func:`bleach.callbacks.target_blank`) would re-add
it.

If the body no longer matches the record, or the record was produced by an
older version, the material is treated as *unconfirmed*: it follows the
full inbound rules of the new policy and the returned status says so.

The plain :py:func:`bleach.clean` and :py:func:`bleach.linkify` entry
points are unchanged; this is an opt-in layer on top of them.

Admitting material
==================

:py:func:`bleach.export.admit` runs the first cleaning pass and returns the
cleaned text together with a record::

    from bleach import admit

    result = admit(
        comment,
        tags=["a", "blockquote", "p"],
        attributes={"a": ["href", "title", "rel"]},
        protocols=["http", "https", "mailto"],
    )

    clean_body = result.text
    record = result.record          # store this next to the comment

Re-exporting
============

:py:func:`bleach.export.reexport` consumes a body, its record and the new
export's :py:class:`~bleach.sanitizer.Cleaner`.  An optional
:py:class:`~bleach.linkifier.Linker` runs before the final clean::

    from bleach import reexport, CONFIRMED, UNCONFIRMED
    from bleach.sanitizer import Cleaner

    preview = Cleaner(
        tags=["a", "blockquote", "p", "b", "i"],
        attributes={"a": ["href", "title", "rel", "target"]},
    )

    result = reexport(stored_body, stored_record, preview)

    if result.status == CONFIRMED:
        # Same body, current record: the intersected (narrower) policy wins.
        ...
    elif result.status == UNCONFIRMED:
        # Edited body or stale record: full inbound rules of `preview` apply.
        ...

Records are plain-data friendly via
:py:meth:`~bleach.export.PolicyRecord.to_dict` and
:py:meth:`~bleach.export.PolicyRecord.from_dict`, so they can be serialised
to JSON and stored in a database.

Reference
=========

.. automodule:: bleach.export
   :members:
   :undoc-members:
