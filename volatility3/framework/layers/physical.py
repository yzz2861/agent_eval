# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import threading
from typing import Any, Dict, IO, Iterable, List, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources

vollog = logging.getLogger(__name__)


class BufferDataLayer(interfaces.layers.DataLayerInterface):
    """A DataLayer class backed by a buffer in memory, designed for testing and
    swift data access."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        buffer: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        holes: Optional[Iterable[Tuple[int, int]]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )
        self._buffer = buffer
        self._holes: Tuple[Tuple[int, int], ...] = ()
        self.set_holes(holes or ())

    @property
    def holes(self) -> Tuple[Tuple[int, int], ...]:
        """Returns the invalid (start, length) ranges in the buffer."""
        return self._holes

    def set_holes(self, holes: Iterable[Tuple[int, int]]) -> None:
        """Set physical ranges that read as holes rather than zeroes."""
        normalized = []
        for start, length in holes:
            if start < 0 or length < 0:
                raise ValueError("Hole offsets and lengths must not be negative")
            if length:
                normalized.append((start, length))
        self._holes = tuple(sorted(normalized))

    def add_hole(self, offset: int, length: int) -> None:
        """Mark a physical range as absent from the buffer."""
        self.set_holes(self._holes + ((offset, length),))

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        return len(self._buffer) - 1

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        if length <= 0:
            return True
        in_buffer = bool(
            self.minimum_address <= offset <= self.maximum_address
            and self.minimum_address <= offset + length - 1 <= self.maximum_address
        )
        if not in_buffer:
            return False
        end = offset + length
        return not any(
            start < end and start + size > offset for start, size in self._holes
        )

    def _first_invalid_address(self, address: int, length: int) -> int:
        if address < self.minimum_address:
            return self.minimum_address
        if address > self.maximum_address:
            return address
        end = address + length
        if end > self.maximum_address + 1:
            return self.maximum_address + 1
        for start, size in self._holes:
            hole_end = start + size
            if start < end and hole_end > address:
                return max(start, address)
        return address

    def _read_runs(
        self, address: int, length: int
    ) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
        """Split a range into readable runs and gaps without scanning bytes."""
        requested_end = address + length
        buffer_start = max(address, self.minimum_address)
        buffer_end = min(requested_end, self.maximum_address + 1)
        runs: List[Tuple[int, int]] = []
        gaps: List[Tuple[int, int]] = []

        if buffer_start > address:
            gaps.append((address, buffer_start - address))
        if buffer_start >= buffer_end:
            if buffer_end < requested_end:
                gaps.append(
                    (max(buffer_end, address), requested_end - max(buffer_end, address))
                )
            return runs, gaps

        position = buffer_start
        for start, size in self._holes:
            hole_end = start + size
            if hole_end <= position:
                continue
            if start >= buffer_end:
                break
            if start > position:
                run_end = min(start, buffer_end)
                runs.append((position, run_end - position))
                position = run_end
            if hole_end > position:
                gap_end = min(hole_end, buffer_end)
                gaps.append((position, gap_end - position))
                position = gap_end
            if position >= buffer_end:
                break

        if position < buffer_end:
            runs.append((position, buffer_end - position))
        if buffer_end < requested_end:
            gaps.append((buffer_end, requested_end - buffer_end))
        return runs, gaps

    def read(self, address: int, length: int, pad: bool = False) -> bytes:
        """Reads the data from the buffer."""
        if length < 0:
            raise ValueError("Length must be positive or zero")
        if length == 0:
            return b""
        if not self.is_valid(address, length):
            if not pad:
                raise exceptions.InvalidAddressException(
                    self.name,
                    self._first_invalid_address(address, length),
                    "Offset outside of the buffer boundaries or inside a hole",
                )
            report = self.read_with_evidence(address, length, pad=True)
            return report.data
        return self._buffer[address : address + length]

    def read_with_evidence(
        self, address: int, length: int, pad: bool = False
    ) -> interfaces.layers.ReadReport:
        """Read the buffer while separating data from hole padding."""
        if length < 0:
            raise ValueError("Length must be positive or zero")
        if length == 0:
            return interfaces.layers.ReadReport(self.name, address, length, b"")

        runs, gaps = self._read_runs(address, length)
        if gaps and not pad:
            raise exceptions.InvalidAddressException(
                self.name,
                gaps[0][0],
                "Offset outside of the buffer boundaries or inside a hole",
            )

        output: List[bytes] = []
        evidence: List[interfaces.layers.ReadEvidence] = []
        gap_records: List[interfaces.layers.ReadGap] = []
        position = address
        for start, size in sorted(runs + gaps):
            if start > position:
                # The sorted runs and gaps should be contiguous, but retain a
                # defensive fill if a custom hole layout overlaps unexpectedly.
                missing = start - position
                output.append(b"\x00" * missing)
                gap_records.append(interfaces.layers.ReadGap(position, missing))
            if (start, size) in runs:
                data = self._buffer[start : start + size]
                output.append(data)
                evidence.append(
                    interfaces.layers.ReadEvidence(
                        start, size, start, size, self.name, data
                    )
                )
            else:
                output.append(b"\x00" * size)
                gap_records.append(interfaces.layers.ReadGap(start, size))
            position = start + size

        report_data = b"".join(output)
        if len(report_data) != length:
            raise ValueError("Reported buffer data does not match the requested length")

        return interfaces.layers.ReadReport(
            layer=self.name,
            offset=address,
            length=length,
            data=report_data,
            mappings=interfaces.layers.coalesce_mappings(
                interfaces.layers.MappingInterval(
                    item.offset, item.length, item.offset, item.length, self.name
                )
                for item in evidence
            ),
            evidence=interfaces.layers.coalesce_evidence(evidence),
            gaps=tuple(gap_records),
        )

    def write(self, address: int, data: bytes):
        """Writes the data from to the buffer."""
        self._buffer = (
            self._buffer[:address] + data + self._buffer[address + len(data) :]
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # No real requirements (only the buffer).  Need to figure out if there's a better way of representing this
        return [
            requirements.BytesRequirement(
                name="buffer",
                description="The direct bytes to interact with",
                optional=False,
            )
        ]


class DummyLock:
    def __enter__(self) -> None:
        pass

    def __exit__(self, type, value, traceback) -> None:
        pass


class FileLayer(interfaces.layers.DataLayerInterface):
    """a DataLayer backed by a file on the filesystem."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

        self._write_warning = False
        self._location = self.config["location"]
        self._accessor = resources.ResourceAccessor()
        self._file_: Optional[IO[Any]] = None
        self._size: Optional[int] = None
        self._maximum_address: Optional[int] = None
        # Construct the lock now (shared if made before threading) in case we ever need it
        self._lock: Union[DummyLock, threading.Lock] = DummyLock()
        if constants.PARALLELISM == constants.Parallelism.Threading:
            self._lock = threading.Lock()
        # Instantiate the file to throw exceptions if the file doesn't open
        _ = self._file

    @property
    def location(self) -> str:
        """Returns the location on which this Layer abstracts."""
        return self._location

    @property
    def _file(self) -> IO[Any]:
        """Property to prevent the initializer storing an unserializable open
        file (for context cloning)"""
        # FIXME: Add "+" to the mode once we've determined whether write mode is enabled
        mode = "rb"
        self._file_ = self._file_ or self._accessor.open(self._location, mode)
        return self._file_

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        # Zero based, so we return the size of the file minus 1
        if self._maximum_address:
            return self._maximum_address
        with self._lock:
            orig = self._file.tell()
            self._file.seek(0, 2)
            self._size = self._file.tell()
            self._file.seek(orig)
            self._maximum_address = self._size - 1
        return self._maximum_address

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        if length <= 0:
            raise ValueError("Length must be positive")
        return bool(
            self.minimum_address <= offset <= self.maximum_address
            and self.minimum_address <= offset + length - 1 <= self.maximum_address
        )

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from the file at offset for length."""
        if not self.is_valid(offset, length):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(
                self.name, invalid_address, "Offset outside of the buffer boundaries"
            )

        # TODO: implement locking for multi-threading
        with self._lock:
            self._file.seek(offset)
            data = self._file.read(length)

        if len(data) < length:
            if pad:
                data += b"\x00" * (length - len(data))
            else:
                raise exceptions.InvalidAddressException(
                    self.name,
                    offset + len(data),
                    "Could not read sufficient bytes from the " + self.name + " file",
                )
        return data

    def write(self, offset: int, data: bytes) -> None:
        """Writes to the file.

        This will technically allow writes beyond the extent of the file
        """
        if not self._file.writable():
            if not self._write_warning:
                self._write_warning = True
                vollog.warning(f"Try to write to unwritable layer: {self.name}")
            return None
        if not self.is_valid(offset, len(data)):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(
                self.name,
                invalid_address,
                "Data segment outside of the " + self.name + " file boundaries",
            )
        with self._lock:
            self._file.seek(offset)
            self._file.write(data)

    def __getstate__(self) -> Dict[str, Any]:
        """Do not store the open _file_ attribute, our property will ensure the
        file is open when needed.

        This is necessary for multi-processing
        """
        self._file_ = None
        return self.__dict__

    def destroy(self) -> None:
        """Closes the file handle."""
        self._file.close()

    def __exit__(self, type, value, traceback) -> None:
        self.destroy()

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement(name="location", optional=False)]
