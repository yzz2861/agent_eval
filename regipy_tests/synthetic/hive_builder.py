"""
Minimal offline Windows registry hive (REGF) writer used by the test-suite.

The production ``regipy`` package only parses hives; the service-hijack tests
need deterministic multi-control-set material that cannot be collected from a
live Windows machine, so this module builds just enough of the on-disk hive
format for ``RegistryHive`` to read it back:

* a 4096-byte REGF header with a valid xor32 checksum,
* 4096-byte hbins containing allocated nk/vk/data/lh cells,
* nested key nodes with value lists and hash-leaf subkey lists.

Only the value types consumed by the plugins are supported (REG_SZ,
REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_BINARY). Everything is built in
memory and written to a caller-provided path; no Windows API is involved.
"""

import datetime as dt
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from regipy.utils import calculate_xor32_checksum

HBIN_SIZE = 4096
HBIN_HEADER_SIZE = 32
REGF_HEADER_SIZE = 4096

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7


def filetime(year: int = 2020, month: int = 1, day: int = 1) -> int:
    epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    timestamp = dt.datetime(year, month, day, tzinfo=dt.timezone.utc)
    return int((timestamp - epoch).total_seconds() * 10_000_000)


def _encode_value_data(value_type: int, value: Any) -> bytes:
    if value_type == REG_DWORD:
        return struct.pack("<I", int(value))
    if value_type == REG_BINARY:
        return bytes(value)
    if value_type == REG_MULTI_SZ:
        if not value:
            return b"\x00\x00"
        encoded = "".join(f"{part}\x00" for part in value).encode("utf-16-le")
        return encoded + b"\x00\x00"
    if value_type in (REG_SZ, REG_EXPAND_SZ):
        return str(value).encode("utf-16-le") + b"\x00\x00"
    if value_type == REG_NONE:
        return b""
    raise ValueError(f"Unsupported synthetic value type: {value_type}")


def _pad4(data: bytes) -> bytes:
    remainder = len(data) % 4
    if remainder:
        data += b"\x00" * (4 - remainder)
    return data


@dataclass
class SyntheticKey:
    name: str
    values: dict = field(default_factory=dict)
    subkeys: dict = field(default_factory=dict)
    timestamp: int = field(default_factory=filetime)

    def ensure_key(self, path: str) -> "SyntheticKey":
        current = self
        for part in [p for p in path.split("\\") if p]:
            current = current.subkeys.setdefault(part, SyntheticKey(name=part))
        return current

    def set_dword(self, path: str, name: str, value: int) -> None:
        self.ensure_key(path).values[name] = (REG_DWORD, value)

    def set_sz(self, path: str, name: str, value: str, value_type: int = REG_SZ) -> None:
        self.ensure_key(path).values[name] = (value_type, value)

    def set_multi_sz(self, path: str, name: str, value: list) -> None:
        self.ensure_key(path).values[name] = (REG_MULTI_SZ, list(value))



class _Cell:
    """An allocated registry cell laid out inside an hbin."""

    def __init__(self, payload: bytes) -> None:
        self.payload = _pad4(payload)
        # Pointer to the cell SIZE field, relative to the start of the first
        # hbin (file offset 4096). This is the convention used by every
        # pointer in an on-disk hive: regipy seeks to REGF_HEADER_SIZE plus
        # the pointer and reads the cell size, then skips it for the payload.
        self.pointer = 0

    @property
    def size(self) -> int:
        return len(self.payload) + 4

    def render(self) -> bytes:
        return struct.pack("<i", -self.size) + self.payload


class _HiveBuilder:
    def __init__(self, root: SyntheticKey, file_name: str) -> None:
        self.root_node = root
        self.file_name = file_name
        self.cells: list = []
        # (child nk pointer, parent nk pointer) for parent offset patching
        self.deferred_parent_patches: list = []
        self._hbin_index = 0
        self._cursor = HBIN_HEADER_SIZE

    def add_cell(self, payload: bytes) -> int:
        cell = _Cell(payload)
        if self._cursor + cell.size > HBIN_SIZE:
            # Continue in a fresh hbin when the cell does not fit.
            self._hbin_index += 1
            self._cursor = HBIN_HEADER_SIZE
        cell.pointer = self._hbin_index * HBIN_SIZE + self._cursor
        self._cursor += cell.size
        self.cells.append(cell)
        return cell.pointer

    def build(self) -> bytes:
        # Two passes so that key nodes are allocated before any value/data
        # cells. regipy treats the very first cell of the first hbin as the
        # root key node, so the root NK must be allocated before anything else.
        node_records = self._allocate_key_nodes(self.root_node)
        for node, nk_pointer, child_pointers in node_records:
            self._populate_key_values(node, nk_pointer, child_pointers)
        hbins = self._render_hbins()
        self._apply_parent_patches(hbins)

        root_offset = node_records[0][1]
        header = bytearray(REGF_HEADER_SIZE)
        header[0:4] = b"regf"
        struct.pack_into("<II", header, 4, 1, 1)
        struct.pack_into("<q", header, 12, self.root_node.timestamp)
        struct.pack_into("<II", header, 20, 1, 3)
        struct.pack_into("<I", header, 32, root_offset)
        struct.pack_into("<I", header, 36, len(hbins) * HBIN_SIZE)
        struct.pack_into("<I", header, 40, 1)
        header[48:112] = self.file_name.encode("utf-16-le")[:64].ljust(64, b"\x00")
        struct.pack_into("<I", header, 508, calculate_xor32_checksum(bytes(header[0:508])))
        return bytes(header) + b"".join(bytes(hbin) for hbin in hbins)

    def _allocate_key_nodes(self, node: SyntheticKey) -> list:
        # Pre-order allocation: parent NK before child NK cells.
        name_bytes = node.name.encode("ascii")
        nk_fixed = self._pack_nk_header(node, name_bytes, 0, 0, 0, 0)
        nk_pointer = self.add_cell(nk_fixed + name_bytes)
        records = [(node, nk_pointer, [])]
        for child in node.subkeys.values():
            child_records = self._allocate_key_nodes(child)
            records[0][2].append(child_records[0][1])
            records.extend(child_records)
        return records

    def _populate_key_values(self, node: SyntheticKey, nk_pointer: int, child_pointers: list) -> None:
        vk_pointers: list = []
        for value_name, (value_type, value) in node.values.items():
            data = _encode_value_data(value_type, value)
            name_bytes = value_name.encode("ascii")
            data_pointer = self.add_cell(data)
            vk_header = struct.pack(
                "=HIIIHH", len(name_bytes), len(data), data_pointer, value_type, 0x0001, 0
            )
            vk_payload = b"vk" + vk_header + name_bytes
            vk_pointers.append(self.add_cell(vk_payload))

        values_list_pointer = 0
        if vk_pointers:
            values_list_pointer = self.add_cell(b"".join(struct.pack("<I", p) for p in vk_pointers))

        subkeys_list_pointer = 0
        if child_pointers:
            lh_payload = b"lh" + struct.pack("<H", len(child_pointers))
            # lh element offsets point directly at the child cell size field.
            for child_pointer in child_pointers:
                lh_payload += struct.pack("<II", child_pointer, 0)
            subkeys_list_pointer = self.add_cell(lh_payload)

        name_bytes = node.name.encode("ascii")
        nk_payload = self._pack_nk_header(
            node, name_bytes, len(child_pointers), subkeys_list_pointer, len(vk_pointers), values_list_pointer
        ) + name_bytes
        self._overwrite_cell(nk_pointer, nk_payload)
        for child_pointer in child_pointers:
            self.deferred_parent_patches.append((child_pointer, nk_pointer))

    @staticmethod
    def _pack_nk_header(
        node: SyntheticKey,
        name_bytes: bytes,
        subkey_count: int,
        subkeys_list_pointer: int,
        value_count: int,
        values_list_pointer: int,
    ) -> bytes:
        return struct.pack(
            "=2sHq4s" + "I" * 13 + "4sHH",
            b"nk",
            0x0020,
            node.timestamp,
            b"\x00\x00\x00\x00",
            0,
            subkey_count,
            0,
            subkeys_list_pointer,
            0,
            value_count,
            values_list_pointer,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
            0,
            0,
            0,
            b"\x00\x00\x00\x00",
            len(name_bytes),
            0,
        )

    def _overwrite_cell(self, pointer: int, payload: bytes) -> None:
        # The NK cell was reserved in pass one; replace its placeholder payload
        # in place. The final payload never exceeds the reserved size because
        # pass one wrote the same-length header plus the key name.
        for cell in self.cells:
            if cell.pointer == pointer:
                cell.payload = _pad4(payload)
                return
        raise KeyError(f"No reserved cell at pointer {pointer}")

    def _render_hbins(self) -> list:
        hbins: list = []
        for index in range(self._hbin_index + 1):
            hbin = bytearray(HBIN_SIZE)
            hbin[0:4] = b"hbin"
            struct.pack_into("<I", hbin, 4, index * HBIN_SIZE)
            struct.pack_into("<I", hbin, 8, HBIN_SIZE)
            hbins.append(hbin)
        for cell in self.cells:
            hbin_index, inside = divmod(cell.pointer, HBIN_SIZE)
            rendered = cell.render()
            hbins[hbin_index][inside : inside + len(rendered)] = rendered
        return hbins

    def _apply_parent_patches(self, hbins: list) -> None:
        # CM_KEY_NODE.parent_key_offset sits at payload offset 14 (flags 2 +
        # last_modified 8 + access_bits 4). The cell size adds another 4.
        for child_pointer, parent_pointer in self.deferred_parent_patches:
            hbin_index, inside = divmod(child_pointer, HBIN_SIZE)
            struct.pack_into("<I", hbins[hbin_index], inside + 4 + 14, parent_pointer)


def build_synthetic_hive(
    root: SyntheticKey,
    output_path: str,
    file_name: str = r"\SystemRoot\System32\Config\SYSTEM",
) -> str:
    """Render ``root`` as a REGF hive and write it to ``output_path``."""
    payload = _HiveBuilder(root, file_name).build()
    with open(output_path, "wb") as writer:
        writer.write(payload)
    return output_path


def make_system_root() -> SyntheticKey:
    """Create an empty root key, matching the root NK of a SYSTEM hive."""
    return SyntheticKey(name="CMI-CreateHive")


def add_service(
    root: SyntheticKey,
    control_set: str,
    name: str,
    service_type: Optional[int] = None,
    start: Optional[int] = None,
    image_path: Optional[str] = None,
    service_dll: Optional[str] = None,
    dependencies: Optional[list] = None,
    object_name: Optional[str] = None,
) -> SyntheticKey:
    """Add a service key under ``<control_set>\\Services`` with common values."""
    service_path = rf"{control_set}\Services\{name}"
    service_key = root.ensure_key(service_path)
    if service_type is not None:
        service_key.values["Type"] = (REG_DWORD, service_type)
    if start is not None:
        service_key.values["Start"] = (REG_DWORD, start)
    if image_path is not None:
        service_key.values["ImagePath"] = (REG_EXPAND_SZ, image_path)
    if object_name is not None:
        service_key.values["ObjectName"] = (REG_SZ, object_name)
    if dependencies is not None:
        service_key.values["DependOnService"] = (REG_MULTI_SZ, list(dependencies))
    if service_dll is not None:
        parameters = root.ensure_key(rf"{service_path}\Parameters")
        parameters.values["ServiceDll"] = (REG_EXPAND_SZ, service_dll)
    return service_key
