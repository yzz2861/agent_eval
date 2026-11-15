"""
Exceptions that can be thrown by hyperframe.
"""
from __future__ import annotations


class HyperframeError(Exception):
    """
    The base class for all exceptions for the hyperframe module.

    .. versionadded:: 6.0.0
    """


class UnknownFrameError(HyperframeError):
    """
    A frame of unknown type was received.

    .. versionchanged:: 6.0.0
        Changed base class from `ValueError` to :class:`HyperframeError`
    """

    def __init__(self, frame_type: int, length: int) -> None:
        #: The type byte of the unknown frame that was received.
        self.frame_type = frame_type

        #: The length of the data portion of the unknown frame.
        self.length = length

    def __str__(self) -> str:
        return (
            f"UnknownFrameError: Unknown frame type 0x{self.frame_type:X} received, length {self.length} bytes"
        )


class InvalidPaddingError(HyperframeError):
    """
    A frame with invalid padding was received.

    .. versionchanged:: 6.0.0
        Changed base class from `ValueError` to :class:`HyperframeError`
    """


class InvalidFrameError(HyperframeError):
    """
    Parsing a frame failed because the data was not laid out appropriately.

    .. versionadded:: 3.0.2

    .. versionchanged:: 6.0.0
        Changed base class from `ValueError` to :class:`HyperframeError`
    """


class InvalidDataError(HyperframeError):
    """
    Content or data of a frame was is invalid or violates the specification.

    .. versionadded:: 6.0.0
    """


class FrameBoundaryError(HyperframeError):
    """
    A frame violated a stateful protocol boundary on the connection, such as
    a flow-control window overflow, an excessive frame size, an out-of-range
    stream identifier, or an invalid settings value.

    Carries the offending frame type and a snapshot of the connection state
    at the point of failure, so callers do not need to reconstruct it.

    .. versionadded:: 6.2.0
    """

    def __init__(self,
                 message: str,
                 *,
                 frame_type: int | None = None,
                 stream_id: int | None = None,
                 connection_state: dict[str, int] | None = None) -> None:
        super().__init__(message)

        #: The type byte of the frame that violated the boundary, if known.
        self.frame_type = frame_type

        #: The stream identifier of the offending frame, if known.
        self.stream_id = stream_id

        #: A snapshot of the connection state when the failure occurred.
        self.connection_state = connection_state or {}
