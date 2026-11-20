from __future__ import annotations


class Error(Exception):
    pass


class LexerError(Error):
    pass


class ParserError(Error):
    pass


class ResolveError(Error):
    pass


class NullPointerDereference(Error):
    pass


class ArraySizeError(Error):
    pass


class ExpressionParserError(Error):
    pass


class UnknownIdentifierError(ExpressionParserError):
    pass


class MappingError(Error):
    """Base class for errors raised while reading a logical address mapping.

    Args:
        address: The logical address where the access failed.
        size: The number of bytes that could not be read, if known.
        message: Optional custom message.
        label: Optional label of the segment involved in the error.
    """

    def __init__(
        self,
        address: int,
        size: int | None = None,
        message: str | None = None,
        *,
        label: str | None = None,
    ):
        self.address = address
        self.size = size
        self.label = label
        super().__init__(message or self._default_message())

    def _default_message(self) -> str:
        size = f" ({self.size} bytes)" if self.size is not None else ""
        return f"{self.__class__.__name__} at {self.address:#x}{size}"


class MissingPage(MappingError, EOFError):
    """The requested logical address is not backed by any fragment."""


class SegmentConflict(MappingError, ValueError):
    """Overlapping fragments disagree about bytes or permissions in the shared range."""


class AccessDenied(MappingError, PermissionError):
    """The requested logical address is mapped but explicitly not readable."""


# Descriptive aliases for callers that use a different fault vocabulary.
AddressMappingError = MappingError
AddressSpaceError = MappingError
MemoryMapError = MappingError
MappingFault = MappingError
ConflictingFragmentsError = SegmentConflict
ConflictingMapping = SegmentConflict
ConflictingSegmentsError = SegmentConflict
ForbiddenRegion = AccessDenied
MissingPageError = MissingPage
OverlappingSegmentError = SegmentConflict
OverlappingSegments = SegmentConflict
PageFault = MissingPage
PageFaultError = MissingPage
UnmappedPage = MissingPage
MissingAddressError = MissingPage
ProhibitedAccessError = AccessDenied
AccessFault = AccessDenied
ReadAccessDenied = AccessDenied
SegmentConflictError = SegmentConflict
UnmappedAddress = MissingPage
UnmappedAddressError = MissingPage
