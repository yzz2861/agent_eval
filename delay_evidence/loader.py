"""Read-only input layer.

The view never asks the operating system to load or map the image. Only two
input shapes are accepted:

* a complete PE file, parsed with the bundled static ``pefile`` parser;
* a raw byte fragment (a local dump / small byte sample), parsed manually
  against an RVA base supplied by the caller.

Importing this module does not touch ``ctypes``, ``subprocess`` or any loader
API; a guard test asserts that the package stays loader-free.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

import pefile


class LoaderError(ValueError):
    """Raised when the bytes cannot be interpreted statically."""


@dataclass
class LoadedInput:
    """A normalized handle over either a full PE or a raw fragment."""

    source: str
    data: bytes
    is_fragment: bool
    pe: Optional[pefile.PE]
    base_rva: int = 0
    is_64bit: bool = True

    @property
    def image_base(self) -> Optional[int]:
        if self.pe is None:
            return None
        return self.pe.OPTIONAL_HEADER.ImageBase

    @property
    def machine(self) -> str:
        if self.pe is not None:
            machine = self.pe.FILE_HEADER.Machine
            return pefile.MACHINE_TYPE.get(machine, f"0x{machine:x}")
        return "FRAGMENT"

    def contains_rva(self, rva: int) -> bool:
        if self.pe is not None:
            try:
                self.pe.get_offset_from_rva(rva)
                return True
            except pefile.PEFormatError:
                return False
        offset = rva - self.base_rva
        return 0 <= offset < len(self.data)

    def rva_to_offset(self, rva: int) -> int:
        if self.pe is not None:
            return self.pe.get_offset_from_rva(rva)
        offset = rva - self.base_rva
        if not (0 <= offset < len(self.data)):
            raise LoaderError(f"RVA 0x{rva:x} is outside the fragment")
        return offset

    def read(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_offset(rva)
        if offset + size > len(self.data):
            raise LoaderError(
                f"read of {size} bytes at RVA 0x{rva:x} exceeds the input"
            )
        return self.data[offset : offset + size]

    def read_u32(self, rva: int) -> int:
        return struct.unpack("<I", self.read(rva, 4))[0]

    def read_u64(self, rva: int) -> int:
        return struct.unpack("<Q", self.read(rva, 8))[0]

    def read_pointer(self, rva: int) -> int:
        if self.is_64bit:
            return self.read_u64(rva)
        return self.read_u32(rva)

    def read_cstring(self, rva: int, max_len: int = 260) -> str:
        offset = self.rva_to_offset(rva)
        bound = min(len(self.data), offset + max_len)
        end = self.data.find(b"\x00", offset, bound)
        if end == -1:
            raise LoaderError(f"unterminated string at RVA 0x{rva:x}")
        return self.data[offset:end].decode("ascii", errors="replace")


def load_path(path: str, fragment_base_rva: Optional[int] = None) -> LoadedInput:
    """Load ``path`` without ever invoking the system loader."""
    if not os.path.isfile(path):
        raise LoaderError(f"input not found: {path}")
    with open(path, "rb") as handle:
        data = handle.read()
    return load_bytes(
        data, source=os.path.basename(path),
        fragment_base_rva=fragment_base_rva,
    )


def load_bytes(
    data: bytes,
    source: str = "<bytes>",
    fragment_base_rva: Optional[int] = None,
) -> LoadedInput:
    """Parse bytes as a full PE, or fall back to a raw fragment."""
    if data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as exc:
            raise LoaderError(f"not a parseable PE: {exc}") from exc
        return LoadedInput(
            source=source,
            data=data,
            is_fragment=False,
            pe=pe,
            is_64bit=pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS,
        )

    if fragment_base_rva is None:
        raise LoaderError(
            "raw fragments require --base-rva so RVAs can map to offsets"
        )
    return LoadedInput(
        source=source,
        data=data,
        is_fragment=True,
        pe=None,
        base_rva=fragment_base_rva,
        is_64bit=True,
    )
