class TortoiseMigrationError(Exception):
    """Base migration error."""


class IncompatibleStateError(TortoiseMigrationError):
    """Raised when a migration operation can't be executed on a given State."""


class CheckpointMismatchError(TortoiseMigrationError):
    """Raised when a stored resumable-migration checkpoint does not match the
    current migration definition, so the old checkpoint cannot be reused."""


class ConcurrentMigrationError(TortoiseMigrationError):
    """Raised when another executor is already advancing the same resumable
    migration operation."""
