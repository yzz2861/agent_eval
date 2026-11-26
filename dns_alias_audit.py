"""Compatibility entrypoint for the offline DNS auditor."""
from dns_audit import *  # noqa: F401,F403
from dns_audit.cli import main
from dns_audit.demo import build_demo_audit

if __name__ == "__main__":
    raise SystemExit(main())
