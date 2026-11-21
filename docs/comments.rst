.. _comments-chapter:
.. highlight:: python

=================================
Moderated comment link approvals
=================================

Comments can be sanitized with Bleach and then reviewed by a moderator one
paragraph at a time.  The :class:`bleach.comments.CommentReviewer` class keeps
the sanitization, approval, and re-send check in one revision-aware workflow.

The key rule is that an approval is for a **link occurrence in a reviewed
source block**, not merely for a URL.  An approval survives an edit to another
block, but it expires when the reviewed block changes or when the same-looking
link is moved to a different block.  Duplicate blocks and duplicate links keep
separate occurrence identities.

Typical use::

    from bleach.comments import CommentReviewer

    reviewer = CommentReviewer()
    revision = reviewer.submit(user_html)

    # The moderator approves one occurrence in one block.
    reviewer.approve(revision.blocks[0].links[0], moderator="alice")

    check = reviewer.resend_check(edited_html)
    if check.ok:
        publish(check.revision.sanitized)
    else:
        for link in check.pending_links:
            show_for_review(link.block_id, link.href, link.excerpt)

Only links that survived sanitization are exposed for approval.  A URL whose
``href`` was removed by Bleach never becomes an approvable link.

Approval records are plain dictionaries and can be serialized::

    records = reviewer.export_approvals()
    reviewer.load_approvals(records)

See :class:`bleach.comments.CommentReviewer`,
:class:`bleach.comments.ApprovalCheck`, and
:class:`bleach.comments.LinkApproval` for the complete API.

.. autoclass:: bleach.comments.CommentReviewer
   :members:

.. autoclass:: bleach.comments.ApprovalCheck
   :members:

.. autoclass:: bleach.comments.LinkApproval
   :members:

.. autofunction:: bleach.comments.sanitize_comment

.. autofunction:: bleach.comments.review_comment
