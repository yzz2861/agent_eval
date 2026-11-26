"""Compatibility alias for exchange offline receipt support."""

from .exchange_receipt import (
    REAL_UPDATE,
    TRANSFORMED,
    UNVERIFIABLE,
    build_exchange_receipt,
    build_offline_receipt,
    main,
)

__all__ = [
    "REAL_UPDATE",
    "TRANSFORMED",
    "UNVERIFIABLE",
    "build_exchange_receipt",
    "build_offline_receipt",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
