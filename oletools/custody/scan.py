"""Structural observations for the progressive custody backend.

Scanning a container only reads structural metadata (the OLE header/FAT/
directory or the ZIP central directory).  Embedded object payloads are
never read here: each :class:`~oletools.custody.manifest.Observation`
records where a payload physically lives so that a later, explicitly
approved run can open exactly those bytes through a
:class:`~oletools.custody.guard.RangeGate`.
"""

import os
import zipfile

from .errors import CustodyScanError
from .manifest import Observation, sha256_file


FORMAT_RAW = 'raw'
FORMAT_ZIP = 'zip'
FORMAT_OLE = 'ole'

_OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
_OLE_HEADER_BYTES = 512
_ZIP_MAGIC = b'PK\x03\x04'
_STGTY_STREAM = 2
_MACRO_SNIFF_BYTES = 8
_OLE_MACRO_STREAM_NAMES = ('vba', '_vba_project', 'project', 'projectwm',
                           'thisworkbook', '__module_properties')
_OLE_MACRO_STORAGE_NAMES = ('macros', 'objectpool')


class StructuralObservation(object):
    """Result of a structure-only pass over a container."""

    def __init__(self, source_path, container_format, file_size,
                 root_sha256, objects, has_macro=False,
                 macro_evidence=None, header=None):
        self.source_path = source_path
        self.container_format = container_format
        self.file_size = int(file_size)
        self.root_sha256 = root_sha256
        self.objects = list(objects)
        self.has_macro = bool(has_macro)
        self.macro_evidence = list(macro_evidence or [])
        self.header = dict(header or {})

    def find(self, object_id):
        for obj in self.objects:
            if obj.object_id == object_id:
                return obj
        return None

    def find_by_name(self, name):
        for obj in self.objects:
            if obj.name == name:
                return obj
        return None

    def as_observations(self):
        """Return the objects as manifest :class:`Observation` entries."""
        return list(self.objects)

    def __repr__(self):
        return ('StructuralObservation({0!r}, {1}, {2} objects)'
                .format(self.source_path, self.container_format,
                        len(self.objects)))


def detect_format(path):
    """Return :data:`FORMAT_ZIP`, :data:`FORMAT_OLE` or :data:`FORMAT_RAW`."""
    with open(path, 'rb') as handle:
        signature = handle.read(8)
    if signature.startswith(b'PK\x03\x04') or signature.startswith(b'PK\x05\x06'):
        return FORMAT_ZIP
    if signature == _OLE_MAGIC:
        return FORMAT_OLE
    return FORMAT_RAW


def scan_file(path):
    """Build a :class:`StructuralObservation` without reading payloads.

    Only container metadata is opened; the bytes of embedded objects are
    not consumed.  The root file is hashed once so that a replacement of
    the original document is detectable on every later pass.
    """
    fmt = detect_format(path)
    if fmt == FORMAT_ZIP:
        objects, evidence = _scan_zip(path)
    elif fmt == FORMAT_OLE:
        objects, evidence = _scan_ole(path)
    else:
        objects, evidence = _scan_raw(path)
    return StructuralObservation(
        source_path=os.path.abspath(path), container_format=fmt,
        file_size=os.path.getsize(path),
        root_sha256=sha256_file(path), objects=objects,
        has_macro=bool(evidence), macro_evidence=evidence)


# --- ZIP / OOXML / ODF -----------------------------------------------------

_ZIP_EMBEDDED_PREFIXES = ('word/embeddings/', 'xl/embeddings/',
                          'ppt/embeddings/')
_ZIP_MACRO_PARTS = ('word/vbaProject.bin', 'xl/vbaProject.bin',
                    'ppt/vbaProject.bin')


def _scan_zip(path):
    objects = []
    evidence = []
    with open(path, 'rb') as handle:
        archive = zipfile.ZipFile(handle)
        try:
            for index, info in enumerate(archive.infolist()):
                if info.is_dir():
                    continue
                header_length = _zip_local_header_length(handle, info)
                data_offset = info.header_offset + header_length
                member_path = info.filename
                embedded = member_path.startswith(_ZIP_EMBEDDED_PREFIXES)
                macro_like = member_path in _ZIP_MACRO_PARTS
                if macro_like:
                    evidence.append(member_path)
                detail = {
                    'zip_index': index,
                    'header_offset': info.header_offset,
                    'local_header_length': header_length,
                    'compression': info.compress_type,
                    'crc32': info.CRC,
                    'embedded': embedded,
                    'macro_like': macro_like,
                    'physical_offset': data_offset,
                    'physical_length': info.compress_size,
                }
                objects.append(Observation(
                    object_id='zip-{0}'.format(index),
                    kind='zip-member', name=member_path,
                    offset=data_offset, size=info.file_size,
                    has_macros=macro_like, container=FORMAT_ZIP,
                    detail=detail))
        finally:
            archive.close()
    return objects, evidence


def _zip_local_header_length(handle, info):
    """Byte length of a local file header, without touching member payload."""
    handle.seek(info.header_offset)
    fixed = handle.read(30)
    if len(fixed) < 30 or fixed[:4] != _ZIP_MAGIC:
        raise CustodyScanError(
            'invalid local header for {0}'.format(info.filename))
    name_length = int.from_bytes(fixed[26:28], 'little')
    extra_length = int.from_bytes(fixed[28:30], 'little')
    return 30 + name_length + extra_length


# --- OLE2 / CFB ------------------------------------------------------------


def _scan_ole(path):
    import olefile
    objects = []
    evidence = []
    with open(path, 'rb') as handle:
        ole = olefile.OleFileIO(handle)
        try:
            path_by_sid = _ole_path_map(ole)
            for entry in ole.direntries:
                if entry is None or entry.entry_type != _STGTY_STREAM:
                    continue
                if not entry.sect_chain:
                    entry.build_sect_chain(ole)
                location = _ole_stream_location(ole, entry)
                stream_path = path_by_sid.get(entry.sid, entry.name)
                macro_like = _ole_stream_macro_like(stream_path)
                if macro_like:
                    evidence.append(stream_path)
                detail = {
                    'sid': entry.sid,
                    'first_sector_sid': entry.isectStart,
                    'mini_stream': bool(entry.is_minifat),
                    'stream_path': stream_path,
                    'sector_chain': list(entry.sect_chain or ()),
                    'sector_size': ole.sectorsize,
                    'mini_sector_size': ole.minisectorsize,
                    'root_first_sector': location.get('root_first_sector'),
                    'root_chain': list(location.get('root_chain') or ()),
                    'physical_length': location['physical_length'],
                }
                detail.update(location)
                objects.append(Observation(
                    object_id='ole-{0}'.format(entry.sid),
                    kind='ole-stream', name=stream_path,
                    offset=location['offset'], size=int(entry.size),
                    has_macros=macro_like, container=FORMAT_OLE,
                    detail=detail))
        finally:
            ole.close()
    return objects, evidence


def _ole_path_map(ole):
    """Map each stream SID to its full storage path, e.g. ``Macros/VBA``.

    Directory entry names are not unique (several ``CompObj`` streams may
    exist under different storages), so the SID is used as the key instead
    of the leaf name.
    """
    path_by_sid = {}
    entry_by_path = {}
    for entry in ole.direntries:
        if entry is not None:
            entry_by_path.setdefault(entry.name, []).append(entry)
    for parts in ole.listdir(streams=True, storages=True):
        candidates = entry_by_path.get(parts[-1], ())
        if len(candidates) == 1:
            path_by_sid[candidates[0].sid] = '/'.join(parts)
        else:
            chosen = _resolve_unique_sid(ole, parts, candidates)
            if chosen is not None:
                path_by_sid[chosen] = '/'.join(parts)
    return path_by_sid


def _resolve_unique_sid(ole, parts, candidates):
    """Identify the SID of a stream when leaf names collide.

    Walks the storage tree following ``parts`` so that e.g.
    ``ObjectPool/x/CompObj`` never gets confused with another ``CompObj``.
    """
    current = ole.root
    for name in parts:
        kids = [kid for kid in current.kids if kid.name == name]
        if not kids:
            return None
        current = kids[0]
    return current.sid


def _ole_stream_location(ole, entry):
    sector_size = ole.sectorsize
    chain = list(entry.sect_chain or ())
    if entry.is_minifat:
        physical = len(chain) * ole.minisectorsize
        root = ole.root
        if not root.sect_chain:
            root.build_sect_chain(ole)
        root_chain = list(root.sect_chain or ())
        root_first = root_chain[0] if root_chain else None
        if chain and root_first is not None:
            offset = (_OLE_HEADER_BYTES + root_first * sector_size
                      + chain[0] * ole.minisectorsize)
        else:
            offset = None
        return {'offset': offset, 'physical_length': physical,
                'root_first_sector': root_first,
                'root_chain': root_chain}
    physical = len(chain) * sector_size
    offset = (_OLE_HEADER_BYTES + chain[0] * sector_size
              if chain else None)
    return {'offset': offset, 'physical_length': physical,
            'root_first_sector': None}


def _ole_stream_macro_like(stream_path):
    lowered = stream_path.lower()
    leaf = lowered.rsplit('/', 1)[-1]
    if leaf in _OLE_MACRO_STREAM_NAMES:
        return True
    return lowered.startswith('macros/')


# --- raw / flat files ------------------------------------------------------


def _scan_raw(path):
    size = os.path.getsize(path)
    with open(path, 'rb') as handle:
        prefix = handle.read(_MACRO_SNIFF_BYTES)
    macro_like = (prefix[:2] == b'MZ' or prefix == _OLE_MAGIC)
    observation = Observation(
        object_id='raw-0', kind='raw',
        name=os.path.basename(path), offset=0, size=size,
        has_macros=macro_like, container=FORMAT_RAW,
        detail={'embedded': False, 'macro_like': macro_like,
                'physical_offset': 0, 'physical_length': size})
    evidence = [observation.name] if macro_like else []
    return [observation], evidence
