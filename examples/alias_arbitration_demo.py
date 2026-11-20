"""End-to-end demonstration of the enterprise alias arbitration layer.

Two small asset books, in-memory only: no database and no online bulletin
source.  The original CPE equivalence judgement is reused unchanged; the
enterprise layer only adds explicit, fully-evidenced alias relations.
"""

from datetime import date

from cpe.alias import (
    AliasRegistry,
    AliasRelation,
    Disposition,
    EnterpriseArbitrator,
    ProductCatalog,
    AssetBook,
    Bulletin,
    RelationConflict,
    ScopeViolation,
)


def build_catalog():
    catalog = ProductCatalog()
    catalog.register("skylake", "cpe:2.3:a:acme:skylake:1.0:*:*:*:*:*:*:*", "Skylake Core")
    catalog.register("cloudengine", "cpe:2.3:a:acme:cloudengine:1.0:*:*:*:*:*:*:*", "CloudEngine")
    catalog.register("databus", "cpe:2.3:a:acme:databus:2.0:*:*:*:*:*:*:*", "DataBus")
    catalog.register("edgeproxy", "cpe:2.3:a:acme:edgeproxy:3.0:*:*:*:*:*:*:*", "EdgeProxy")
    return catalog


def build_books():
    book_a = AssetBook("book-A")
    book_a.add("asset-A1", "BU-ALPHA", "skylake",
                "cpe:2.3:a:acme:skylake:1.0:*:*:*:*:*:*:*")
    book_a.add("asset-A2", "BU-ALPHA", "databus",
                "cpe:2.3:a:acme:databus:2.0:*:*:*:*:*:*:*")
    book_b = AssetBook("book-B")
    book_b.add("asset-B1", "BU-BETA", "cloudengine",
                "cpe:2.3:a:acme:cloudengine:1.0:*:*:*:*:*:*:*")
    book_b.add("asset-B2", "BU-BETA", "edgeproxy",
                "cpe:2.3:a:acme:edgeproxy:3.0:*:*:*:*:*:*:*")
    return book_a, book_b


def build_registry():
    registry = AliasRegistry()
    registry.register(AliasRelation.create(
        relation_id="R1-ORIGINAL",
        product_from="skylake",
        product_to="cloudengine",
        source="product-office",
        business_scope=["BU-ALPHA", "BU-BETA"],
        valid_from="2025-01-01",
        valid_to="2026-06-30"))
    registry.register(AliasRelation.create(
        relation_id="R1-RENEWED",
        product_from="skylake",
        product_to="cloudengine",
        source="product-office",
        business_scope=["BU-ALPHA"],
        valid_from="2026-07-01",
        valid_to=None))
    registry.register(AliasRelation.create(
        relation_id="R2-MANDA",
        product_from="cloudengine",
        product_to="databus",
        source="m-and-a-integration",
        business_scope=["BU-ALPHA"],
        valid_from="2026-01-01",
        valid_to=None))
    registry.register(AliasRelation.create(
        relation_id="R3-REVOKABLE",
        product_from="databus",
        product_to="edgeproxy",
        source="m-and-a-integration",
        business_scope=["BU-ALPHA"],
        valid_from="2026-01-01",
        valid_to=None))
    return registry


def build_bulletins():
    return (
        Bulletin("ADV-CLOUD", "cpe:2.3:a:acme:cloudengine:1.0:*:*:*:*:*:*:*", "CloudEngine advisory"),
        Bulletin("ADV-DATABUS", "cpe:2.3:a:acme:databus:2.0:*:*:*:*:*:*:*", "DataBus advisory"),
        Bulletin("ADV-EDGE", "cpe:2.3:a:acme:edgeproxy:3.0:*:*:*:*:*:*:*", "EdgeProxy advisory"),
    )


def print_report(title, report):
    print("=" * 78)
    print(title, "(audit date: {0})".format(report.query_date))
    print("=" * 78)
    for result in report:
        for line in result.explain_lines():
            print(line)
    print()


def main():
    catalog = build_catalog()
    book_a, book_b = build_books()
    registry = build_registry()
    bulletins = build_bulletins()
    books = (book_a, book_b)
    arbitrator = EnterpriseArbitrator(registry, catalog)

    before = date(2026, 5, 1)
    print_report("Run 1: original agreement still covers both units",
                 arbitrator.run_match(books, bulletins, before))

    after = date(2026, 8, 1)
    print_report("Run 2: renewal only signed for BU-ALPHA",
                 arbitrator.run_match(books, bulletins, after))

    registry.revoke("R3-REVOKABLE", date(2026, 9, 1))
    post_revoke = date(2026, 9, 15)
    print_report("Run 3: after revoking R3 (databus -> edgeproxy)",
                 arbitrator.run_match(books, bulletins, post_revoke))

    print_report("Run 4: audit replay before revocation",
                 arbitrator.run_match(books, bulletins, before))

    try:
        AliasRelation.create(
            relation_id="BAD-WILDCARD",
            product_from="databus",
            product_to="edgeproxy",
            source="risk-team",
            business_scope=["*"],
            valid_from="2026-01-01",
            valid_to=None)
    except ScopeViolation as exc:
        print("Guard (bare wildcard rejected): {0}".format(exc))

    try:
        registry.register(AliasRelation.create(
            relation_id="CONFLICT-X",
            product_from="skylake",
            product_to="cloudengine",
            source="another-office",
            business_scope=["BU-ALPHA"],
            valid_from="2026-07-01",
            valid_to=None))
    except RelationConflict as exc:
        print("Guard (conflicting relation rejected): {0}".format(exc))
    print()


if __name__ == "__main__":
    main()
