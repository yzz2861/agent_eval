from types import SimpleNamespace

from dnfile.scope_audit import ScopedToken, verify_manifest
from dnfile.mdtable import FileRow


def ref(table_name, row_index):
    return SimpleNamespace(
        table=SimpleNamespace(name=table_name),
        table_name=table_name,
        row_index=row_index,
        rid=row_index,
    )


def property_tables(type_flags):
    return {
        "TypeDef": [SimpleNamespace(Flags=type_flags, TypeName="Widget", TypeNamespace="Acme")],
        "Property": [SimpleNamespace(Name="Name")],
        "PropertyMap": [
            SimpleNamespace(Parent=ref("TypeDef", 1), PropertyList=[ref("Property", 1)])
        ],
    }


def test_same_rid_in_two_artifacts_is_scoped_and_classified():
    entries = [
        {"id": "a", "scope": "build-a", "table": "Property", "rid": 1},
        {"id": "b", "scope": "build-b", "table": "Property", "rid": 1},
    ]
    report = verify_manifest(
        entries,
        artifacts={
            "build-a": property_tables(0x00000001),
            "build-b": property_tables(0x00000000),
        },
    )

    assert [item["status"] for item in report] == ["public", "internal"]
    assert report[0].scoped_token == ScopedToken("build-a", 0x17000001)
    assert report[1].scoped_token == ("build-b", 0x17000001)
    assert report[0].declaration_scope.table_name == "TypeDef"
    assert report[1].ok is False
    assert report.ok is False


def test_unscoped_reused_identifier_is_ambiguous():
    report = verify_manifest(
        {"name": "Name", "table": "Property"},
        {
            "build-a": property_tables(1),
            "build-b": property_tables(0),
        },
    )

    assert report[0]["status"] == "ambiguous"
    assert [candidate["scope"] for candidate in report[0].candidates] == ["build-a", "build-b"]
    assert {candidate["scoped_token"].scope for candidate in report[0].candidates} == {
        "build-a",
        "build-b",
    }


def test_exported_type_token_is_scoped_to_implementation_file():
    main_tables = {
        "File": [SimpleNamespace(Name="impl.netmodule")],
        "ExportedType": [
            SimpleNamespace(
                Flags=0,
                TypeDefId=7,
                TypeName="Widget",
                TypeNamespace="Acme",
                Implementation=ref("File", 1),
            )
        ],
    }
    modules = {
        "impl.netmodule": {
            "TypeDef": {7: SimpleNamespace(Flags=1, TypeName="Widget", TypeNamespace="Acme")}
        }
    }

    report = verify_manifest(
        {"table": "ExportedType", "rid": 1},
        main_tables,
        scope="Acme.dll",
        modules=modules,
    )

    result = report[0]
    assert result.ok is True
    assert result.scoped_token == ("Acme.dll", 0x27000001)
    file_scope = result.declaration_scope
    assert file_scope.kind == "file"
    assert file_scope.name == "impl.netmodule"
    assert file_scope.scoped_type_token == ("Acme.dll/impl.netmodule", 0x02000007)
    assert file_scope.declaration_scope["name"] == "Acme.Widget"


def test_positional_table_first_is_supported():
    tables = property_tables(1)
    report = verify_manifest(tables, [{"table": "Property", "rid": 1}], scope="one")
    assert report[0].scope == "one"
    assert report[0].status == "public"


def test_row_token_uses_metadata_table_and_one_based_rid():
    row = FileRow([None] * 45, 1, 1, 1, None, None, None)

    class FileTable:
        number = 38

    row._attach_table(FileTable(), 1)
    assert row.row_index == 1
    assert row.token == 0x26000001
