"""Allow ``python -m regression`` style execution from the parent directory."""

from regression.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
