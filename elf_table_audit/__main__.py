"""Allow ``python -m elf_table_audit`` as an alias for the CLI module."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
