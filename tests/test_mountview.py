"""Tests for the offline MountView over the three miniature hives."""
import os

import pytest

from Registry import Registry
from Registry.mountview import (
    MountConflictError,
    MountView,
    ResolutionStatus,
)


HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(HERE, "reg_samples", "mountview")
SYSTEM_HIVE = os.path.join(SAMPLE_DIR, "mini_system.hive")
SOFTWARE_HIVE = os.path.join(SAMPLE_DIR, "mini_software.hive")
NTUSER_HIVE = os.path.join(SAMPLE_DIR, "mini_ntuser.hive")


SOFTWARE_ALIASES = {
    r"\HKLM\SOFTWARE": r"HKLM\SOFTWARE",
    r"\HKU\NOT-MOUNTED": r"HKU\NOT-MOUNTED",
}
NTUSER_ALIASES = {
    r"\HKU\alice": r"HKU\alice",
    r"\HKU\.DEFAULT": r"HKU\.DEFAULT",
    r"\HKLM\SOFTWARE": r"HKLM\SOFTWARE",
}


@pytest.fixture
def view():
    mount_view = MountView()
    mount_view.mount("EV-SYSTEM", r"HKLM\SYSTEM", SYSTEM_HIVE)
    mount_view.mount("EV-SOFTWARE", r"HKLM\SOFTWARE", SOFTWARE_HIVE,
                      aliases=SOFTWARE_ALIASES)
    mount_view.mount("EV-NTUSER", r"HKU\alice", NTUSER_HIVE,
                      aliases=NTUSER_ALIASES)
    return mount_view


class TestMountRegistration(object):
    def test_duplicate_evidence_id_rejected(self, view):
        with pytest.raises(MountConflictError):
            view.mount("EV-SYSTEM", r"HKLM\OTHER", SYSTEM_HIVE)

    def test_duplicate_mount_point_rejected(self, view):
        with pytest.raises(MountConflictError):
            view.mount("EV-DUP", r"HKLM\SYSTEM", SYSTEM_HIVE)

    def test_nested_mount_point_rejected(self, view):
        with pytest.raises(MountConflictError):
            view.mount("EV-NEST", r"HKLM\SOFTWARE\Sub", SOFTWARE_HIVE)

    def test_empty_mount_point_rejected(self):
        with pytest.raises(MountConflictError):
            MountView().mount("EV-EMPTY", "", SYSTEM_HIVE)

    def test_every_mount_records_identity(self, view):
        ids = sorted(hive.evidence_id for hive in view.mounts())
        assert ids == ["EV-NTUSER", "EV-SOFTWARE", "EV-SYSTEM"]


class TestDirectReads(object):
    SYSTEM_LINK = r"HKLM\SYSTEM\ControlSet001\Control\NetworkProvider"
    ALICE_LOCAL = r"HKU\alice\Software\NetworkProvider"

    def test_direct_read_keeps_evidence_boundary(self, view):
        result = view.get(self.SYSTEM_LINK)
        assert result.status == ResolutionStatus.OK
        assert result.key.location().evidence_id == "EV-SYSTEM"
        assert result.key.location().source_path == \
            r"ControlSet001\Control\NetworkProvider"

    def test_direct_read_reports_link_without_following(self, view):
        result = view.get(self.SYSTEM_LINK)
        links = result.key.links()
        assert len(links) == 1
        assert links[0].is_link()
        assert links[0].link_target().startswith(r"\HKLM\SOFTWARE")
        assert result.hops == []

    def test_direct_read_distinguishes_link_from_plain_key(self, view):
        result = view.get(self.ALICE_LOCAL)
        assert result.key.links() == []
        assert result.key.value("LocalNote").value() == \
            "alice-local-network-provider"

    def test_direct_read_never_returns_other_evidence(self, view):
        result = view.get(self.SYSTEM_LINK, follow_links=False)
        assert result.key.location().evidence_id == "EV-SYSTEM"
        assert result.key.registry_key()._nkrecord.offset() == \
            result.key.location().record_offset


class TestLinkFollowing(object):
    SYSTEM_LINK = r"HKLM\SYSTEM\ControlSet001\Control\NetworkProvider"
    SHADOW_LINK = r"HKU\alice\Software\Policy\NetworkProvider"
    SOFTWARE_TARGET = \
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetworkProvider"

    def test_legal_cross_mount_resolves_and_records_hop(self, view):
        result = view.get(self.SYSTEM_LINK, follow_links=True)
        assert result.status == ResolutionStatus.OK
        assert result.key.location().evidence_id == "EV-SOFTWARE"
        assert result.key.view_path() == self.SOFTWARE_TARGET
        assert len(result.hops) == 1
        hop = result.hops[0]
        assert hop.source.evidence_id == "EV-SYSTEM"
        assert hop.link_value_name == "SymbolicLink"
        assert hop.target_view_path == self.SOFTWARE_TARGET

    def test_legal_cross_mount_is_not_flagged_shadow(self, view):
        result = view.get(self.SYSTEM_LINK, follow_links=True)
        assert result.status == ResolutionStatus.OK
        assert result.shadowed is None

    def test_same_name_impostor_returns_shadow_status(self, view):
        result = view.get(self.SHADOW_LINK, follow_links=True)
        assert result.status == ResolutionStatus.NAME_SHADOWED
        assert result.key.location().evidence_id == "EV-SOFTWARE"
        assert len(result.shadowed) == 1
        assert result.shadowed[0].evidence_id == "EV-SOFTWARE"
        assert result.shadowed[0].source_path.endswith("NetworkProvider")

    def test_direct_read_of_impostor_stays_with_owner(self, view):
        direct = view.get(self.SHADOW_LINK)
        assert direct.status == ResolutionStatus.OK
        assert direct.key.location().evidence_id == "EV-NTUSER"
        assert direct.key.links()[0].link_target().startswith(
            r"\HKLM\SOFTWARE")


class TestStructuredFailureStatus(object):
    @pytest.mark.parametrize("path", [
        r"HKLM\SOFTWARE\Policies\CycleA",
        r"HKU\alice\Software\LoopA",
    ])
    def test_link_cycle_detected(self, view, path):
        result = view.get(path, follow_links=True)
        assert result.status == ResolutionStatus.LINK_CYCLE
        assert result.key is None
        assert len(result.hops) >= 2
        identities = [hop.source.identity() for hop in result.hops]
        assert len(identities) != len(set(identities)) or \
            "cycle" in result.message.lower()

    @pytest.mark.parametrize("path", [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKU\alice\Software\Dangling",
    ])
    def test_unmounted_target_detected(self, view, path):
        result = view.get(path, follow_links=True)
        assert result.status == ResolutionStatus.UNMOUNTED_TARGET
        assert result.key is None
        assert "host registry" in result.message

    def test_unknown_view_path_is_not_found(self, view):
        result = view.get(r"HKCR\Undefined\Path")
        assert result.status == ResolutionStatus.NOT_FOUND

    def test_missing_key_inside_mount_is_not_found(self, view):
        result = view.get(r"HKLM\SYSTEM\No\Such\Key")
        assert result.status == ResolutionStatus.NOT_FOUND


class TestOffsetTraceability(object):
    def test_location_offset_matches_nk_record(self, view):
        result = view.get(
            r"HKLM\SYSTEM\ControlSet001\Control\ProductOptions")
        key = result.key
        raw_registry = Registry.Registry(SYSTEM_HIVE)
        raw_key = raw_registry.open(
            r"ControlSet001\Control\ProductOptions")
        assert key.location().record_offset == raw_key._nkrecord.offset()
        assert key.registry_key() is not raw_key

    def test_link_hop_preserves_source_and_target_offsets(self, view):
        result = view.get(
            r"HKLM\SYSTEM\ControlSet001\Control\NetworkProvider",
            follow_links=True)
        hop = result.hops[0]
        system_reg = Registry.Registry(SYSTEM_HIVE)
        system_link_key = system_reg.open(
            r"ControlSet001\Control\NetworkProvider")
        assert hop.source.record_offset == \
            system_link_key._nkrecord.offset()
        software_reg = Registry.Registry(SOFTWARE_HIVE)
        software_target = software_reg.open(
            r"Microsoft\Windows\CurrentVersion\NetworkProvider")
        assert result.key.location().record_offset == \
            software_target._nkrecord.offset()

    def test_value_offsets_are_reported(self, view):
        result = view.get_value(
            r"HKLM\SYSTEM\ControlSet001\Control\ProductOptions",
            "ProductType")
        assert result.status == ResolutionStatus.OK
        offsets = result.value.value_record_offset()
        assert offsets["evidence_id"] == "EV-SYSTEM"
        assert offsets["vk_offset"] > 0x1000
        assert offsets["nk_offset"] > 0x1000


class TestCaseBoundaryIsolation(object):
    def test_result_dict_is_fully_serializable(self, view):
        result = view.get(
            r"HKLM\SYSTEM\ControlSet001\Control\NetworkProvider",
            follow_links=True)
        payload = result.as_dict()
        assert payload["status"] == "ok"
        assert payload["hops"][0]["source"]["evidence_id"] == "EV-SYSTEM"
        assert payload["terminal"]["evidence_id"] == "EV-SOFTWARE"
        assert payload["terminal"]["record_offset"] > 0x1000

    def test_failure_result_dict_is_serializable(self, view):
        result = view.get(r"HKU\alice\Software\LoopA", follow_links=True)
        payload = result.as_dict()
        assert payload["status"] == "link_cycle"
        assert payload["terminal"] is None
        assert payload["hops"]

    def test_no_query_changes_mount_bounds(self, view):
        before = [(h.evidence_id, tuple(h.mount_point)) for h in view.mounts()]
        view.get(r"HKU\alice\Software\Dangling", follow_links=True)
        view.get(r"HKLM\SOFTWARE\Policies\CycleA", follow_links=True)
        after = [(h.evidence_id, tuple(h.mount_point)) for h in view.mounts()]
        assert before == after

    def test_module_does_not_import_host_registry(self):
        import Registry.mountview as mountview
        source = open(mountview.__file__).read()
        assert "winreg" not in source.lower()


class TestOriginalRegistryApiUnaffected(object):
    def test_plain_registry_still_parses_each_hive(self):
        for path in (SYSTEM_HIVE, SOFTWARE_HIVE, NTUSER_HIVE):
            registry = Registry.Registry(path)
            assert registry.root().name().startswith("CMI-CreateHive")

    def test_registry_value_api_unchanged(self):
        registry = Registry.Registry(SYSTEM_HIVE)
        key = registry.open(
            r"ControlSet001\Control\ProductOptions")
        assert key.value("ProductType").value() == "WinNT"


class TestShadowInventory(object):
    def test_detect_shadows_lists_cross_evidence_links(self, view):
        shadows = view.detect_shadows()
        owners = sorted(item["link"].evidence_id for item in shadows)
        assert owners == ["EV-NTUSER", "EV-SYSTEM"]
        for item in shadows:
            assert item["target"].evidence_id == "EV-SOFTWARE"

    def test_name_conflicts_reports_shared_root_names(self):
        mount_view = MountView()
        mount_view.mount("EV-A", r"HKLM\A", SYSTEM_HIVE)
        mount_view.mount("EV-B", r"HKLM\B", SYSTEM_HIVE)
        conflicts = mount_view.name_conflicts()
        assert len(conflicts) == 1
        left, right = conflicts[0]
        assert {left["evidence_id"], right["evidence_id"]} == \
            {"EV-A", "EV-B"}


class TestHopProvenance(object):
    SYSTEM_LINK = r"HKLM\SYSTEM\ControlSet001\Control\NetworkProvider"

    def test_each_hop_records_source_and_target_location(self, view):
        result = view.get(self.SYSTEM_LINK, follow_links=True)
        hop = result.hops[0]
        assert hop.source.evidence_id == "EV-SYSTEM"
        assert hop.target is not None
        assert hop.target.evidence_id == "EV-SOFTWARE"
        assert hop.target.source_path == \
            r"Microsoft\Windows\CurrentVersion\NetworkProvider"
        assert hop.target.record_offset == \
            result.key.location().record_offset

    def test_cycle_hops_keep_every_target(self, view):
        result = view.get(r"HKLM\SOFTWARE\Policies\CycleA",
                          follow_links=True)
        assert result.status == ResolutionStatus.LINK_CYCLE
        assert all(hop.target is not None for hop in result.hops)
        assert result.hops[0].target.source_path.endswith("CycleB")
        assert result.hops[1].target.source_path.endswith("CycleA")
