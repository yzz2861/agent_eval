class FormParserError(ValueError):
    """Base error class for our form parser."""


class ParseError(FormParserError):
    """This exception (or a subclass) is raised when there is an error while
    parsing something.
    """

    def __init__(self, message: str, *, offset: int = -1, category: str | None = None) -> None:
        super().__init__(message)
        self.offset = offset
        self.category = category

    @property
    def reason(self) -> str | None:
        """Alias for :attr:`category`, kept for callers that use reason codes."""
        return self.category

    @property
    def rejection_category(self) -> str | None:
        """Alias for :attr:`category`, expressing the rejection class."""
        return self.category

    @property
    def part_offset(self) -> int:
        """Offset relative to the start of the current multipart part."""
        return self.offset


class MultipartParseError(ParseError):
    """This is a specific error that is raised when the MultipartParser detects
    an error while parsing.
    """


class QuerystringParseError(ParseError):
    """This is a specific error that is raised when the QuerystringParser
    detects an error while parsing.
    """


class DecodeError(ParseError):
    """This exception is raised when there is a decoding error - for example
    with the Base64Decoder or QuotedPrintableDecoder.
    """


class FileError(FormParserError, OSError):
    """Exception class for problems with the File class."""
