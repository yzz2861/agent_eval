Expose HTTP/1 chunk extensions on ``Data`` and ``EndOfMessage``, allow sending
them, and honor ``Data.chunk_start`` / ``Data.chunk_end`` for controlling chunk
boundaries.
