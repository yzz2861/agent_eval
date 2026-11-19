"""Path normalization and equivalence for cross-hive evidence alignment.

Different artifacts record the same executable in different spellings:
UserAssist uses environment-variable GUIDs such as ``%SYSTEM32%``, BAM uses
NT device paths such as ``\\Device\\HarddiskVolume2\\Windows\\...``, AmCache
and ShimCache use drive-letter or ``\\??\\`` paths. Facts may only be spliced
when their normalized paths are provably equivalent; unknown volume mappings
must keep the paths distinct rather than collapsing them.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

# Environment placeholders emitted by the UserAssist plugin (see its
# GUID_TO_PATH_MAPPINGS) mapped to their default expansions.
ENV_PLACEHOLDERS = {
    "%SYSTEM32%": r"C:\Windows\System32",
    "%WINDIR%": r"C:\Windows",
    "%PROGRAMFILES%": r"C:\Program Files",
    "%PROGRAMFILES(X86)%": r"C:\Program Files (x86)",
    "%PROGRAMDATA%": r"C:\ProgramData",
}

# Per-user placeholders cannot be expanded without the user profile root.
PER_USER_PLACEHOLDERS = {"%APPDATA%"}

# NT prefixes that simply decorate an otherwise ordinary path.
_DECORATION_PREFIXES = ("\\??\\", "\\\\??\\\\")

_DEVICE_VOLUME_RE = re.compile(r"^\\Device\\HarddiskVolume\d+\\?(.*)$", re.IGNORECASE)
_DEVICE_PREFIX = chr(92)*2 + "Device" + chr(92)
_DRIVE_RE = re.compile(r"^[a-z]:\\", re.IGNORECASE)


@dataclass(frozen=True)
class NormalizedPath:
    """A normalized path plus the equivalence information the normalizer had.

    ``device_form`` keeps ``\\Device\\HarddiskVolumeN`` prefixes when the
    caller did not register the volume-to-drive mapping: two such paths can
    only be compared when the device names are identical. ``unresolved``
    records per-user placeholders that could not be expanded.
    """

    raw: str
    normalized: str
    device_form: bool
    unresolved: tuple[str, ...] = ()

    def equivalent_to(self, other: "NormalizedPath") -> bool:
        if self.unresolved or other.unresolved:
            return False
        if self.device_form or other.device_form:
            return self.device_form == other.device_form and self.normalized == other.normalized
        return self.normalized == other.normalized


def normalize_path(path: str, volume_mappings: Optional[dict[str, str]] = None) -> NormalizedPath:
    """Normalize an artifact path into a comparable spelling.

    ``volume_mappings`` maps NT device roots (e.g. ``\\Device\\
    HarddiskVolume2``) to drive roots (e.g. ``C:``). Without a mapping,
    device paths stay in device form and never collapse onto drive-letter
    paths.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")

    working = path.strip()
    unresolved: list[str] = []

    for prefix in _DECORATION_PREFIXES:
        if working.startswith(prefix):
            working = working[len(prefix) :]
            break

    for placeholder in sorted(set(ENV_PLACEHOLDERS) | PER_USER_PLACEHOLDERS, key=len, reverse=True):
        if placeholder.lower() not in working.lower():
            continue
        if placeholder in PER_USER_PLACEHOLDERS:
            unresolved.append(placeholder)
            continue
        expansion = ENV_PLACEHOLDERS[placeholder]
        idx = working.lower().find(placeholder.lower())
        working = working[:idx] + expansion + working[idx + len(placeholder) :]

    device_form = False
    match = _DEVICE_VOLUME_RE.match(working)
    if match:
        remainder = match.group(1)
        device_root = working[: len(working) - len(remainder)].rstrip("\\")
        mapped = (volume_mappings or {}).get(device_root)
        if mapped:
            working = mapped.rstrip("\\") + "\\" + remainder
        else:
            device_form = True

    working = working.replace("/", "\\")
    working = re.sub(r"\\+", r"\\", working)
    if not device_form:
        working = working.rstrip("\\")

    # Windows paths are case-insensitive; os.path.normcase only lowercases on
    # Windows, so lowercase explicitly to stay identical on every host OS.
    normalized = os.path.normcase(working)
    if _DRIVE_RE.match(normalized) or normalized.startswith("\\\\Device\\\\".replace("\\\\", "\\")):
        normalized = normalized.lower()

    return NormalizedPath(
        raw=path,
        normalized=normalized,
        device_form=device_form,
        unresolved=tuple(unresolved),
    )
