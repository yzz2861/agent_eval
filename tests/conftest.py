from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    assert SAMPLES.is_dir(), f"samples directory missing: {SAMPLES}"
    return SAMPLES


@pytest.fixture(scope="session")
def build_lock(samples_dir: Path) -> Path:
    return samples_dir / "build-host.pylock.toml"


@pytest.fixture(scope="session")
def runtime_lock(samples_dir: Path) -> Path:
    return samples_dir / "runtime-image.pylock.toml"


@pytest.fixture(scope="session")
def advisory_snapshot(samples_dir: Path) -> Path:
    return samples_dir / "offline-advisories.json"


@pytest.fixture(scope="session")
def exemption_file(samples_dir: Path) -> Path:
    return samples_dir / "exemptions.toml"


@pytest.fixture
def linux_env() -> dict[str, str]:
    return {"sys_platform": "linux"}
