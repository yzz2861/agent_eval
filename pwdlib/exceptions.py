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


class PepperError(PwdlibError):
    """
    Base error for pepper wrapping and key resolution failures.

    The error messages deliberately carry neither the pepper key material nor
    the original hash: both must never leak through logs or exception
    representations.
    """


class CorruptPepperHashError(PepperError):
    """
    Error raised when a pepper wrapper is present but structurally invalid.
    """

    def __init__(self) -> None:
        message = (
            "The peppered hash wrapper is corrupt and can't be decoded. "
            "The stored hash must be regenerated through a secure recovery flow."
        )
        super().__init__(message)


class UnknownPepperKeyError(PepperError):
    """
    Error raised when a pepper wrapper references a key id that is not
    registered on the current strategy.
    """

    def __init__(self, key_id: str) -> None:
        """
        Args:
            key_id:
                The non-secret key identifier referenced by the wrapper.
        """
        self.key_id = key_id
        message = (
            f"The peppered hash references unknown pepper key id {key_id!r}. "
            "Register the corresponding key or retire the record through a "
            "secure recovery flow."
        )
        super().__init__(message)


class MissingPepperKeyError(PepperError):
    """
    Error raised when a pepper wrapper references a registered key id whose
    secret material is currently unavailable (for example after the key was
    retired at the end of a rotation window).
    """

    def __init__(self, key_id: str) -> None:
        """
        Args:
            key_id:
                The non-secret key identifier referenced by the wrapper.
        """
        self.key_id = key_id
        message = (
            f"The secret material for pepper key id {key_id!r} is not "
            "available. The password can't be verified until the key is "
            "restored or the record goes through a secure recovery flow."
        )
        super().__init__(message)
