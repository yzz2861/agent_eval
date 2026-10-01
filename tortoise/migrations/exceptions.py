class TortoiseMigrationError(Exception):
    """Base migration error."""


class IncompatibleStateError(TortoiseMigrationError):
    """Raised when a migration operation can't be executed on a given State."""


class MigrationCheckpointError(TortoiseMigrationError):
    """Raised when a stored migration checkpoint cannot be used."""


class MigrationLockedError(TortoiseMigrationError):
    """Raised when a migration is already being advanced by another executor."""


class MigrationLockLostError(TortoiseMigrationError):
    """Raised when an executor loses its migration lease during a batch."""
