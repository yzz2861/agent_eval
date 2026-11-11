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


class CorruptedHashError(PwdlibError):
    """
    Error raised when a hash has a recognizable algorithm prefix but its
    content is malformed (truncated, invalid parameters, ...).

    This is distinct from :class:`UnknownHashError` (no matching hasher at
    all) and from a plain password mismatch, so callers don't have to infer
    corruption from a ``False`` result.
    """

    def __init__(self, hash: str | bytes, algorithm: str) -> None:
        """
        Args:
            hash:
                The corrupted hash.
            algorithm:
                Name of the hasher that recognized the hash prefix.
        """
        self.hash = hash
        self.algorithm = algorithm
        message = (
            f"This {algorithm} hash is corrupted: its prefix is recognized "
            "but its content can't be parsed or verified."
        )
        super().__init__(message)
