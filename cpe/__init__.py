from .cpe import CPE

__all__ = ["CPE", "analyze", "review_rollback"]


def analyze(*args, **kwargs):
    # Import lazily so ``python -m cpe.review`` does not execute the module
    # twice, while keeping ``from cpe import analyze`` available everywhere.
    from .review import analyze as _analyze
    return _analyze(*args, **kwargs)


def review_rollback(*args, **kwargs):
    from .review import review_rollback as _review_rollback
    return _review_rollback(*args, **kwargs)
