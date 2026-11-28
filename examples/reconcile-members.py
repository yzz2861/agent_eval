#!/usr/bin/env python3
#
# Reconcile externally reported metadata row ranges against a parsed .NET file.
#
# The external tool's row numbers may come from a different snapshot, so each
# segment carries its own caller-approved renumbering map.  A member is only
# attributed to an owning type when the parsed TypeDef MethodList/FieldList
# runs structurally contain it; same-named types never merge evidence.

import sys

import dnfile
from dnfile.reconcile import Reconciler, RenumberingMap, RowRange, Segment


def reconcile_file(fname):
    dn = dnfile.dnPE(fname)
    if not getattr(dn, "net", None) or dn.net.mdtables is None:
        print("no .NET metadata found")
        return

    # Example: the external tool reported MethodDef rows 10-12, and the
    # reviewer approved a map from those external rows to the parsed rows.
    approved = RenumberingMap("MethodDef", {10: 1, 11: 2, 12: 3})
    segment = Segment("external-report", RowRange("MethodDef", 10, 12), approved)
    reconciler = Reconciler(dn.net.mdtables, [segment])

    for result in reconciler.reconcile_range("external-report", only_public=True):
        provenance = "external row %d -> parsed row %d" % (result.external_row, result.parsed_row)
        if result.confirmed:
            evidence = result.evidence
            owner = "%s.%s (TypeDef row %d)" % (
                evidence.owner_type_namespace or "",
                evidence.owner_type_name,
                evidence.owner_row,
            )
            print("CONFIRMED %s: %s owned by %s [%s]" % (
                result.member_name, result.table_name, owner, provenance
            ))
        else:
            print("UNRESOLVED %s: %s [%s]" % (result.member_name, result.reason, provenance))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: reconcile-members.py <file>")
        sys.exit(1)
    reconcile_file(sys.argv[1])

