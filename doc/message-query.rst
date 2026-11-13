.. _message-query:

The dns.message.QueryMessage Class
----------------------------------

.. autoexception:: dns.message.NotQueryResponse
.. autoexception:: dns.message.ChainTooLong
.. autoexception:: dns.message.AnswerForNXDOMAIN
.. autoexception:: dns.message.TrustError
.. autoexception:: dns.message.CNAMELoop

The :py:class:`dns.message.QueryMessage` class is used for ordinary DNS query messages.

.. autoclass:: dns.message.QueryMessage
   :members:

Response Trust Policy
---------------------

A stub resolver cannot assume that every RRset in an upstream response is
relevant to its question: an answer section might contain an out-of-bailiwick
address record, an authority section might smuggle a cacheable record, and a
CNAME chain might loop or be excessively long.  The
:py:meth:`dns.message.QueryMessage.apply_trust_policy` method applies an
explicit trust policy that validates the CNAME/DNAME chain rooted at the
question name and returns a :py:class:`dns.message.TrustResult` with a
separate *trusted* (cacheable) message.  The original message is never
modified, so records refused by the policy remain available in the raw
response but never enter the cacheable view.

The policy only records coarse audit information (a name category, the RR
class/type categories, and a rejection reason); it never stores owner names,
rdata, or other potentially sensitive upstream response contents.

.. autoclass:: dns.message.TrustPolicy
   :members:

.. autoclass:: dns.message.TrustResult
   :members:

.. autoclass:: dns.message.TrustReject
   :members:

.. autoclass:: dns.message.TrustRejectReason
   :members:

.. autoclass:: dns.message.NameCategory
   :members:

The dns.message.ChainingResult Class
------------------------------------

Objects of the :py:class:`dns.message.ChainingResult` class are returned by the
:py:meth:`dns.message.QueryMessage.resolve_chaining` method.

.. autoclass:: dns.message.ChainingResult
   :members:
