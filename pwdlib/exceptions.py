class PwdlibError(Exception):
    """
    Base pwdlib error.
    """

    def __init__(self, message: str) -> None:
        """
        Args:
            message:
                The error message.
        """
        self.message = message
        super().__init__(message)


class InputLimitError(PwdlibError, ValueError):
    """
    Base error raised when untrusted input is rejected before it reaches a hasher.
    """


class PasswordLimitError(InputLimitError):
    """
    Base error raised when a password violates the configured input policy.

    Error messages never contain the rejected password.
    """


class PasswordTooLongError(PasswordLimitError):
    """
    Error raised when a password exceeds the maximum UTF-8 byte length.
    """

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        super().__init__(
            f"Password exceeds the maximum allowed length of {max_bytes} UTF-8 bytes."
        )


class PasswordTooShortError(PasswordLimitError):
    """
    Error raised when a password is shorter than the configured minimum length.
    """

    def __init__(self, min_bytes: int) -> None:
        self.min_bytes = min_bytes
        super().__init__(
            f"Password is shorter than the minimum allowed length of {min_bytes} "
            "UTF-8 bytes."
        )


class PasswordEncodingError(PasswordLimitError):
    """
    Error raised when a password is not valid UTF-8.
    """

    def __init__(self) -> None:
        super().__init__("Password must be valid UTF-8.")


class PasswordNULByteError(PasswordLimitError):
    """
    Error raised when a password contains a NUL byte.
    """

    def __init__(self) -> None:
        super().__init__("Password must not contain NUL bytes.")


class HasherNotAvailable(PwdlibError):
    """
    Error raised when an unavailable hash algorithm was installed.
    """

    def __init__(self, hasher: str) -> None:
        """
        Args:
            hasher:
                The unavailable hash algorithm.
        """
        self.hasher = hasher
        message = (
            f"The {hasher} hash algorithm is not available. "
            "Are you sure it's installed? "
            f"Try to run `pip install pwdlib[{hasher}]`."
        )
        super().__init__(message)


class UnknownHashError(PwdlibError):
    """
    Error raised when the hash can't be identified from the list of provided hashers.
    """

    def __init__(self, hash: str | bytes) -> None:
        """
        Args:
            hash:
                The hash we failed to identify.
        """
        self.hash = hash
        message = (
            "This hash can't be identified. "
            "Make sure it's valid and that its corresponding hasher is enabled."
        )
        super().__init__(message)


class HashFormatError(UnknownHashError, ValueError):
    """
    Base error for an encoded hash that cannot be accepted.
    """


class UnsupportedHashError(HashFormatError):
    """
    Error raised when an encoded hash has an unsupported format or prefix.

    It is a subclass of :class:`UnknownHashError` for backwards compatibility.
    """

    def __init__(self, hash: str | bytes | None = None) -> None:
        self.hash = hash
        message = (
            "This hash format is not supported. "
            "Make sure it's valid and that its corresponding hasher is enabled."
        )
        PwdlibError.__init__(self, message)


class InvalidHashEncodingError(UnsupportedHashError):
    """
    Error raised when an encoded hash is not ASCII or contains NUL bytes.
    """

    def __init__(self, hash: str | bytes | None = None) -> None:
        self.hash = hash
        PwdlibError.__init__(self, "Encoded hashes must contain only ASCII characters.")


class HashLengthError(HashFormatError):
    """
    Base error for an encoded hash whose length is outside its format bounds.
    """


class HashTooShortError(HashLengthError):
    """
    Error raised when an encoded hash is shorter than its format allows.
    """

    def __init__(self, min_bytes: int | None = None) -> None:
        self.hash = None
        self.min_bytes = min_bytes
        if min_bytes is None:
            message = "The encoded hash is shorter than the minimum supported length."
        else:
            message = (
                "The encoded hash is shorter than the minimum supported length "
                f"of {min_bytes} bytes."
            )
        PwdlibError.__init__(self, message)


class HashTooLongError(HashLengthError):
    """
    Error raised when an encoded hash exceeds the maximum supported length.
    """

    def __init__(self, max_bytes: int | None = None) -> None:
        self.hash = None
        self.max_bytes = max_bytes
        if max_bytes is None:
            message = "The encoded hash exceeds the maximum supported length."
        else:
            message = (
                "The encoded hash exceeds the maximum supported length "
                f"of {max_bytes} bytes."
            )
        PwdlibError.__init__(self, message)


class HashFieldCountError(UnsupportedHashError):
    """
    Error raised when an encoded hash contains too many fields.
    """

    def __init__(self, max_fields: int) -> None:
        self.hash = None
        self.max_fields = max_fields
        PwdlibError.__init__(
            self,
            f"The encoded hash contains more than the supported {max_fields} fields.",
        )
