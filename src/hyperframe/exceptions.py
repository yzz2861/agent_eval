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


class FrameSizeError(HyperframeError):
    """
    A frame exceeded a bounded size budget or its body did not match the
    length advertised by its frame header.

    Only numeric metadata is retained so that error objects never carry raw
    frame payload bytes.

    .. versionadded:: 6.2.0
    """

    def __init__(
        self,
        frame_type: int,
        declared_length: int,
        allowed_length: int,
        actual_length: int | None = None,
    ) -> None:
        #: The type byte of the frame that violated the size constraint.
        self.frame_type = frame_type

        #: The length advertised in the frame header.
        self.declared_length = declared_length

        #: The maximum length that was permitted for the frame.
        self.allowed_length = allowed_length

        #: The body length actually delivered, when it differs from the
        #: declared length. ``None`` when only the size budget was violated.
        self.actual_length = actual_length

    def __str__(self) -> str:
        if self.actual_length is not None:
            return (
                f"FrameSizeError: frame type 0x{self.frame_type:X} "
                f"declares {self.declared_length} bytes but received "
                f"{self.actual_length} bytes"
            )
        return (
            f"FrameSizeError: frame type 0x{self.frame_type:X} declares "
            f"{self.declared_length} bytes, maximum allowed is "
            f"{self.allowed_length} bytes"
        )
