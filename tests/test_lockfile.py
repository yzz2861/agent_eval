import pytest
from packaging.markers import Marker
from packaging.version import Version

from pip_audit._deployment import (
    LockedPackage,
    StageLockfileError,
    read_stage_lockfile,
)


def test_read_stage_lockfile_keeps_role_groups_markers_artifacts(build_lock):
    stage = read_stage_lockfile("build-host", build_lock)

    assert stage.role == "build-host"
    assert stage.environments == ("sys_platform == 'linux'",)
    assert stage.requires_python == ">=3.12"
    assert len(stage.packages) == 4

    wheel = stage.packages[0]
    assert isinstance(wheel, LockedPackage)
    assert wheel.canonical_name == "wheel"
    assert wheel.version == Version("0.45.0")
    assert wheel.dependency_groups == ("build",)
    assert wheel.marker is None
    assert wheel.selected_for({"sys_platform": "linux"}) is True
    assert wheel.selected_for(None) is True
    assert len(wheel.artifacts) == 1
    artifact = wheel.artifacts[0]
    assert artifact.filename == "wheel-0.45.0-py3-none-any.whl"
    assert artifact.sha256.startswith("1111")
    assert artifact.size == 60000


def test_marker_gated_package_selection(build_lock):
    stage = read_stage_lockfile("build-host", build_lock)
    pywin32 = next(pkg for pkg in stage.packages if pkg.name == "pywin32")

    assert isinstance(pywin32.marker, Marker)
    assert pywin32.marker_raw == "sys_platform == 'win32'"
    assert pywin32.selected_for({"sys_platform": "win32"}) is True
    assert pywin32.selected_for({"sys_platform": "linux"}) is False
    assert pywin32.selected_for(None) is False


def test_unversioned_package_is_skipped(runtime_lock):
    stage = read_stage_lockfile("runtime-image", runtime_lock)
    internal = next(pkg for pkg in stage.packages if pkg.name == "internal-utils")

    assert internal.is_skipped is True
    assert internal.version is None
    assert internal.skip_reason == "no version specified"


def test_missing_lockfile_raises(tmp_path):
    with pytest.raises(StageLockfileError, match="lockfile not found"):
        read_stage_lockfile("build-host", tmp_path / "nope.toml")


def test_invalid_toml_raises(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("lock-version = ", encoding="utf-8")
    with pytest.raises(StageLockfileError, match="invalid TOML"):
        read_stage_lockfile("build-host", bad)
