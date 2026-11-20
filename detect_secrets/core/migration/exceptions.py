class InvalidLinkageMaterialError(ValueError):
    """Think of this as a 400 for the trusted linkage material,
    if an invalid JSON manifest were an HTTP response.
    """
    pass


class LinkageProjectMismatchError(ValueError):
    """Raised when linkage material claims a project other than the one
    currently being migrated. Equality of an old desensitized identifier
    must never bridge two projects.
    """
    pass


class UnsafeMigrationReportError(ValueError):
    """Raised when a migration report still carries a value that would
    expose secret material or allow correlation across projects.
    """
    pass
