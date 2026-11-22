hpack API
=========

This document provides the HPACK API.

.. autoclass:: hpack.Encoder
   :members: header_table_size, encode

.. autoclass:: hpack.Decoder
   :members: header_table_size, decode

.. autoclass:: hpack.HeaderTuple
   :members: indexable

.. autoclass:: hpack.NeverIndexedHeaderTuple
   :members: indexable

.. autoclass:: hpack.HPACKError

.. autoclass:: hpack.HPACKDecodingError

.. autoclass:: hpack.InvalidTableIndexError

.. autoclass:: hpack.InvalidTableIndex

.. autoclass:: hpack.OversizedHeaderListError

.. autoclass:: hpack.InvalidTableSizeError

Offline redacted projections
----------------------------

These helpers replay independently captured HPACK header blocks from trusted
dynamic-table checkpoints.  Header values are exported only when their field
name is explicitly allowed; all other values are replaced by a redaction
marker.  Reported proof ranges identify exactly which fragments remain
decodable when a checkpoint is missing.

.. autofunction:: hpack.build_projection

.. autoclass:: hpack.Fragment
   :members:

.. autoclass:: hpack.TableCheckpoint
   :members:

.. autoclass:: hpack.RedactionPolicy
   :members:

.. autoclass:: hpack.PolicyAddition
   :members:

.. autoclass:: hpack.ProjectionReport
   :members:

.. autoclass:: hpack.FragmentProjection
   :members:

.. autoclass:: hpack.ProjectedHeader
   :members:
