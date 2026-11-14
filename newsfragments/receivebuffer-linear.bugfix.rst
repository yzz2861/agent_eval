The receive buffer now consumes data incrementally using a start offset and
returns zero-copy ``memoryview`` objects for fixed-length reads, instead of
shrinking a ``bytearray`` on every extraction. Consumed prefix space is
reclaimed lazily (and safely even while a returned view is still in use), so
streams made of many tiny pipelined requests no longer risk quadratic CPU
growth. When an incomplete event exceeds ``max_incomplete_event_size``,
:meth:`~h11.Connection.next_event` now raises a ``RemoteProtocolError`` whose
message includes the buffered byte count and the configured limit, rather than
waiting indefinitely.
