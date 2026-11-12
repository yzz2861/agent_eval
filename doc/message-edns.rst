.. _message-edns:

Message EDNS Options
--------------------

EDNS allows for larger messages and also provides an extension
mechanism for the protocol.  EDNS *options* are typed data, and are
treated much like Rdata.  For example, if dnspython encounters the EDNS
``ECS`` option code when parsing a DNS wire format message, it
will create a :py:class:`dns.edns.ECSOption` object to represent it.
Option codes without a specific implementation are retained as
:py:class:`dns.edns.GenericOption` objects with their original bytes, so
unknown options survive a wire-format round trip.  Malformed option lists
raise :py:class:`dns.edns.EDNSError`, which reports the offending option
code, its offset relative to the start of the OPT rdata, and a length
category; option payloads such as COOKIE values are never included in the
error text.

.. autoexception:: dns.edns.EDNSError
   :members:

.. autodata:: dns.edns.MAX_OPTIONS
.. autodata:: dns.edns.MAX_OPT_RDATA_LENGTH
.. autodata:: dns.edns.LENGTH_CATEGORY_OPTION
.. autodata:: dns.edns.LENGTH_CATEGORY_ADDRESS
.. autodata:: dns.edns.LENGTH_CATEGORY_TOTAL

.. autoclass:: dns.edns.OptionType

.. autodata:: dns.edns.NSID
.. autodata:: dns.edns.DAU
.. autodata:: dns.edns.DHU
.. autodata:: dns.edns.N3U
.. autodata:: dns.edns.ECS
.. autodata:: dns.edns.EXPIRE
.. autodata:: dns.edns.COOKIE
.. autodata:: dns.edns.KEEPALIVE
.. autodata:: dns.edns.PADDING
.. autodata:: dns.edns.CHAIN

.. autoclass:: dns.edns.Option
   :members:

.. autoclass:: dns.edns.GenericOption
   :members:

.. autoclass:: dns.edns.ECSOption
   :members:

.. autoclass:: dns.edns.EDECode

.. autoclass:: dns.edns.EDEOption
   :members:

.. autoclass:: dns.edns.NSIDOption
   :members:

.. autoclass:: dns.edns.CookieOption
   :members:

.. autoclass:: dns.edns.PaddingOption
   :members:

.. autoclass:: dns.edns.ReportChannelOption
   :members:

.. autoclass:: dns.edns.EDEExtraTextLanguageOption
   :members:

.. autoclass:: dns.edns.FilteringContactOption
   :members:

.. autoclass:: dns.edns.FilteringOrganizationOption
   :members:

.. autoclass:: dns.edns.FilteringDBOption
   :members:

.. autofunction:: dns.edns.get_option_class
.. autofunction:: dns.edns.option_from_wire_parser
.. autofunction:: dns.edns.option_from_wire
.. autofunction:: dns.edns.register_type
