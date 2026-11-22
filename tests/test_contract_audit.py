import dnfile

from tools.dnfile_contract_audit import MetadataView
from tools.make_metadata_samples import build_samples


IREAD = "MetadataSamples.Contracts.IReadOnlyValue"
IWRITE = "MetadataSamples.Contracts.IValueWriter"
READ_TYPE = "MetadataSamples.ReadOnlyFacade"
WRITE_TYPES = [
    "MetadataSamples.WriteFacade",
    "MetadataSamples.ExplicitWriteFacade",
    "MetadataSamples.InheritedWriteFacade",
]


def _sample_paths(tmp_path):
    return {path.name: path for path in build_samples(tmp_path / "samples")}


def test_generated_samples_are_parseable_without_clr(tmp_path):
    paths = _sample_paths(tmp_path)
    assert set(paths) == {"readonly-overloads.dll", "write-overloads.dll"}
    for path in paths.values():
        pe = dnfile.dnPE(str(path))
        assert pe.net is not None
        assert pe.net.mdtables is not None
        assert pe.net.mdtables.TypeDef.num_rows >= 3
        assert pe.net.mdtables.MethodDef.num_rows >= 7
        assert pe.net.mdtables.MethodSemantics.num_rows >= 4
        stream_warnings = [
            warning
            for warning in pe.get_warnings()
            if "Unable to parse stream" in warning
        ]
        assert stream_warnings == []


def test_readonly_sample_has_no_external_writer(tmp_path):
    view = MetadataView(_sample_paths(tmp_path)["readonly-overloads.dll"])
    findings = view.audit([READ_TYPE], [IREAD, IWRITE], ["Value"])
    by_interface = {finding["interface"]: finding for finding in findings}

    readonly = by_interface[IREAD]
    assert readonly["conclusion"] == "NO_WRITE_INTERFACE_READ_ONLY"
    assert readonly["external_write_accessor"] is False
    assert readonly["target_type_sealed"] is True

    writer = by_interface[IWRITE]
    assert writer["conclusion"] == "NOT_IMPLEMENTED"
    assert writer["external_write_accessor"] is False
    same_name = writer["same_name_methods"]
    assert any(
        item["method"]["rid"] == 4
        and item["same_signature_as_interface_setter"] is True
        and item["relation"] == "unrelated_same_name"
        for item in same_name
    )
    assert {item["method"]["rid"] for item in same_name} == {4, 5, 6}
    assert {item["signature"] for item in same_name} == {
        "instance void (int32)",
        "static void (string)",
        "instance void (int32, string)",
    }


def test_write_sample_routes_and_table_evidence(tmp_path):
    view = MetadataView(_sample_paths(tmp_path)["write-overloads.dll"])
    findings = view.audit(WRITE_TYPES, [IWRITE], ["Value"])
    by_type = {finding["target_type"]: finding for finding in findings}
    assert set(by_type) == set(WRITE_TYPES)

    implicit = by_type["MetadataSamples.WriteFacade"]
    assert implicit["conclusion"] == "WRITE_EXPOSED"
    assert implicit["implementation_route"] == "implicit"
    assert implicit["external_write_accessor"] is True
    assert implicit["implementation_method"]["rid"] == 9
    assert implicit["implementation_method"]["token"] == "0x06000009"
    assert implicit["implementation"]["property_link"]["linked"] is True
    assert implicit["implementation"]["property_link"]["method_semantics"]["rid"] == 7
    assert implicit["interface_setter"]["method_semantics"]["rid"] == 3
    assert implicit["interface_setter"]["method_rid"] == 3
    assert {item["method"]["rid"] for item in implicit["same_name_methods"]} == {6, 7, 9}
    assert next(
        item for item in implicit["same_name_methods"] if item["method"]["rid"] == 9
    )["relation"] == "mapped_implementation"

    explicit = by_type["MetadataSamples.ExplicitWriteFacade"]
    assert explicit["conclusion"] == "WRITE_EXPOSED"
    assert explicit["implementation_route"] == "explicit"
    assert explicit["external_write_accessor"] is True
    assert explicit["implementation_method"]["rid"] == 10
    assert explicit["implementation_method_flags"][0] == "private"
    impl = explicit["implementation"]
    assert impl["methodimpl"]["rid"] == 1
    assert impl["methodimpl"]["token"] == "0x19000001"
    assert impl["declaration_memberref"]["rid"] == 1
    assert impl["declaration_memberref"]["token"] == "0x0A000001"
    assert impl["declaration_name"] == "set_Value"
    assert impl["declaration_signature"] == "instance void (int32)"
    assert impl["property_link"]["explicit_methodimpl"] is True
    assert {item["method"]["rid"] for item in explicit["same_name_methods"]} == {10, 11}

    inherited = by_type["MetadataSamples.InheritedWriteFacade"]
    assert inherited["conclusion"] == "WRITE_EXPOSED"
    assert inherited["implementation_route"] == "inherited-implicit"
    assert inherited["external_write_accessor"] is True
    assert inherited["interface_impl"]["rid"] == 2
    assert inherited["interface_impl_class"] == "MetadataSamples.BaseWriter"
    assert inherited["interface_impl_inherited"] is True
    assert inherited["implementation_method"]["rid"] == 5
    assert inherited["implementation"]["declaring_type"] == "MetadataSamples.BaseWriter"


def test_partial_conclusions_are_preserved(tmp_path):
    view = MetadataView(_sample_paths(tmp_path)["write-overloads.dll"])
    findings = view.audit(
        ["MetadataSamples.WriteFacade"],
        ["Missing.Contracts.INotPresent"],
        ["Value"],
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["conclusion"] == "PARTIAL_UNRESOLVED"
    assert finding["external_write_accessor"] is None
    assert finding["partial_reasons"]

    findings = view.audit(["MetadataSamples.WriteFacade"], [IWRITE], ["Missing"])
    assert findings[0]["conclusion"] == "PARTIAL_UNRESOLVED"
    assert findings[0]["external_write_accessor"] is None


def test_only_write_sample_has_external_interface_writer(tmp_path):
    paths = _sample_paths(tmp_path)
    read_view = MetadataView(paths["readonly-overloads.dll"])
    read_findings = read_view.audit([READ_TYPE], [IREAD, IWRITE], ["Value"])
    assert all(
        finding["external_write_accessor"] is False for finding in read_findings
    )

    write_view = MetadataView(paths["write-overloads.dll"])
    write_findings = write_view.audit(WRITE_TYPES, [IWRITE], ["Value"])
    assert len(write_findings) == len(WRITE_TYPES)
    assert all(
        finding["external_write_accessor"] is True for finding in write_findings
    )
    assert {finding["implementation_route"] for finding in write_findings} == {
        "implicit",
        "explicit",
        "inherited-implicit",
    }
