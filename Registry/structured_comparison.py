"""PEP 8 alias for :mod:`Registry.StructuredComparison`."""
from Registry.StructuredComparison import *  # noqa: F401,F403
from Registry.StructuredComparison import (  # noqa: F401
    FIELD_CATALOG,
    KIND_FIREWALL,
    KIND_SECURITY_DESCRIPTOR,
    KIND_SERVICE_RECORD,
    compare_firewall_rules,
    compare_service_snapshots,
    compare_snapshots,
    build_registry_snapshot,
    build_service_snapshot,
    parse_firewall_rule,
    resolve_field_alias,
)
from Registry.StructuredComparison import main  # noqa: F401


if __name__ == "__main__":
    raise SystemExit(main())
