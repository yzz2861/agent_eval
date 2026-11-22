#-------------------------------------------------------------------------------
# elftools: elf/syslib_audit.py
#
# Offline audit of ELF dynamic dependencies against a caller-supplied loader
# environment declaration.
#
# This module is deliberately static: input ELF files are parsed as data and
# library paths mentioned by the environment are never opened, mapped, or
# loaded.  A library is only "verified" when the environment declaration
# contains evidence for it.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence, TextIO

from ..common.exceptions import ELFError
from .dynamic import DynamicSection, DynamicSegment
from .elffile import ELFFile
from .gnuversions import (
    GNUVerDefSection,
    GNUVerNeedSection,
    GNUVerSymSection,
)
from .sections import SymbolTableSection


__all__ = [
    'SCHEMA',
    'ENV_SCHEMA',
    'STATUS_SIGNED_OFF',
    'STATUS_PENDING_EVIDENCE',
    'SyslibAuditError',
    'ElfIdentity',
    'ElfArtifact',
    'LoaderImage',
    'ProviderCandidate',
    'LibraryEnvironment',
    'parse_elf_artifact',
    'parse_environment',
    'audit',
    'audit_elf',
    'audit_manifest',
    'audit_artifacts',
    'main',
]

SCHEMA = 'elf-syslib-audit/v1'
ENV_SCHEMA = 'elf-syslib-env/v1'

STATUS_SIGNED_OFF = 'signed_off'
STATUS_PENDING_EVIDENCE = 'pending_evidence'


class SyslibAuditError(Exception):
    """Raised when an input ELF or environment declaration cannot be read."""


@dataclass(frozen=True)
class ElfIdentity:
    elf_class: int
    endianness: str
    machine: str
    os_abi: str
    e_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'elf_class': self.elf_class,
            'endianness': self.endianness,
            'machine': self.machine,
            'os_abi': self.os_abi,
            'e_type': self.e_type,
        }


@dataclass
class ElfArtifact:
    path: str
    sha256: str
    identity: ElfIdentity
    soname: str | None
    needed: list[str]
    rpath: list[str]
    runpath: list[str]
    required_versions: dict[str, list[str]]
    required_symbols: dict[str, list[dict[str, Any]]]
    defined_versions: list[str]
    exported_symbols: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            'path': self.path,
            'sha256': self.sha256,
            'identity': self.identity.to_dict(),
            'soname': self.soname,
            'needed': list(self.needed),
            'rpath': list(self.rpath),
            'runpath': list(self.runpath),
            'required_versions': {
                name: list(versions)
                for name, versions in self.required_versions.items()
            },
            'required_symbols': {
                name: [dict(item) for item in symbols]
                for name, symbols in self.required_symbols.items()
            },
            'defined_versions': list(self.defined_versions),
            'exported_symbols': {
                name: list(versions)
                for name, versions in self.exported_symbols.items()
            },
        }


@dataclass(frozen=True)
class LoaderImage:
    id: str
    arch: str | None = None
    elf_class: int | None = None
    endianness: str | None = None
    os_abi: str | None = None
    loader: str | None = None
    search_paths: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'arch': self.arch,
            'elf_class': self.elf_class,
            'endianness': self.endianness,
            'os_abi': self.os_abi,
            'loader': self.loader,
            'search_paths': list(self.search_paths),
        }


@dataclass
class ProviderCandidate:
    id: str
    soname: str
    provider: str | None
    provider_version: str | None
    path: str | None
    images: tuple[str, ...]
    arch: str | None
    elf_class: int | None
    endianness: str | None
    os_abi: str | None
    exported_versions: frozenset[str] | None
    exported_symbols: dict[str, frozenset[str]] | None
    verified: bool | None
    evidence: dict[str, Any]
    priority: int | None
    preferred: bool
    origin: str
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def identity_dict(self) -> dict[str, Any]:
        """Return the stable part of a candidate, suitable for a report."""
        return {
            'id': self.id,
            'soname': self.soname,
            'provider': self.provider,
            'provider_version': self.provider_version,
            'path': self.path,
            'images': list(self.images),
            'arch': self.arch,
            'elf_class': self.elf_class,
            'endianness': self.endianness,
            'os_abi': self.os_abi,
            'priority': self.priority,
            'preferred': self.preferred,
            'origin': self.origin,
        }


@dataclass(frozen=True)
class LibraryEnvironment:
    id: str
    images: tuple[LoaderImage, ...]
    target_images: tuple[str, ...]
    search_paths: tuple[str, ...]
    preferred: Mapping[str, str]
    providers: tuple[ProviderCandidate, ...]
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def image_by_id(self, image_id: str) -> LoaderImage | None:
        for image in self.images:
            if image.id == image_id:
                return image
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema': ENV_SCHEMA,
            'id': self.id,
            'images': [image.to_dict() for image in self.images],
            'target_images': list(self.target_images),
            'search_paths': list(self.search_paths),
            'preferred': dict(self.preferred),
            'providers': [
                {
                    **candidate.identity_dict(),
                    'verified': candidate.verified,
                    'evidence': dict(candidate.evidence),
                    'exported_symbol_versions': (
                        sorted(candidate.exported_versions)
                        if candidate.exported_versions is not None else None),
                }
                for candidate in self.providers
            ],
        }


_ARCH_ALIASES: dict[str, set[str]] = {
    'EM_X86_64': {'em_x86_64', 'x86_64', 'x86-64', 'amd64', 'x64'},
    'EM_386': {'em_386', 'x86', 'i386', 'i686', 'ia32', 'x86_32'},
    'EM_AARCH64': {'em_aarch64', 'aarch64', 'arm64'},
    'EM_ARM': {'em_arm', 'arm', 'arm32', 'armhf', 'armel'},
    'EM_RISCV': {'em_riscv', 'riscv', 'riscv64', 'riscv32'},
    'EM_MIPS': {'em_mips', 'mips', 'mips64', 'mipsel'},
    'EM_PPC': {'em_ppc', 'ppc', 'powerpc'},
    'EM_PPC64': {'em_ppc64', 'ppc64', 'powerpc64', 'ppc64le'},
    'EM_S390': {'em_s390', 's390', 's390x'},
    'EM_LOONGARCH': {'em_loongarch', 'loongarch', 'loongarch64'},
}

_ARCH_LOOKUP: dict[str, str] = {
    alias: canonical
    for canonical, aliases in _ARCH_ALIASES.items()
    for alias in aliases
}

_ENDIAN_ALIASES = {
    'little': {'little', 'le', 'lsb', 'elidata2lsb', 'littleendian'},
    'big': {'big', 'be', 'msb', 'elidata2msb', 'bigendian'},
}

_ENDIAN_LOOKUP = {
    alias: canonical
    for canonical, aliases in _ENDIAN_ALIASES.items()
    for alias in aliases
}


def _normalise_arch(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return _ARCH_LOOKUP.get(text.lower(), text.upper()
                            if text.upper().startswith('EM_') else text.lower())


def _normalise_endian(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().replace('-', '').replace('_', '')
    if not text:
        return None
    return _ENDIAN_LOOKUP.get(text.lower(), text.lower())


def _parse_elf_class(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in (32, 64) else None
    text = str(value).strip().lower()
    if text in ('32', '32-bit', 'elf32', 'elfclass32'):
        return 32
    if text in ('64', '64-bit', 'elf64', 'elfclass64'):
        return 64
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ('true', 'yes', '1', 'verified',
                    'attested', 'complete'):
            return True
        if text in ('false', 'no', '0', 'unverified',
                    'missing', 'withheld', 'unknown'):
            return False
    return None


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        if not value.strip():
            return []
        if ':' in value and os.path.sep not in value:
            return [part for part in value.split(':') if part]
        if ',' in value:
            return [part.strip() for part in value.split(',') if part.strip()]
        return [value.strip()]
    if isinstance(value, Mapping):
        return [str(key) for key in value]
    if isinstance(value, Iterable):
        result: list[str] = []
        for item in value:
            if isinstance(item, Mapping):
                for key in ('id', 'name', 'image', 'value'):
                    if key in item:
                        result.append(str(item[key]))
                        break
            elif item is not None:
                result.append(str(item))
        return result
    return [str(value)]


def _first_present(
        mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _version_tokens(value: str) -> tuple[tuple[int, Any], ...]:
    # Compare numeric fields numerically and text fields lexically.  Keeping
    # the token kind in the tuple makes mixed versions comparable.
    tokens: list[tuple[int, Any]] = []
    for token in re.findall(r'\d+|[A-Za-z]+', value):
        if token.isdigit():
            tokens.append((0, int(token)))
        else:
            tokens.append((1, token.lower()))
    return tuple(tokens)


def _version_sort_key(value: str | None) -> tuple[Any, ...]:
    if not value:
        return (0,)
    # Strip the common symbol-version prefix, e.g. GLIBC_2.4 -> 2.4.
    match = re.search(r'\d', value)
    comparable = value[match.start():] if match else value
    return (1, _version_tokens(comparable), value)


def _required_versions_and_symbols(
        elffile: ELFFile,
) -> tuple[dict[str, list[str]], dict[str, list[dict[str, Any]]],
           list[str], dict[str, list[str]]]:
    required_versions: dict[str, list[str]] = {}
    required_symbols: dict[str, list[dict[str, Any]]] = {}
    defined_versions: list[str] = []
    exported_symbols: dict[str, list[str]] = {}

    for section in elffile.iter_sections():
        if isinstance(section, GNUVerNeedSection):
            for verneed, vernaux_iter in section.iter_versions():
                names = required_versions.setdefault(verneed.name or '', [])
                for vernaux in vernaux_iter:
                    if vernaux.name and vernaux.name not in names:
                        names.append(vernaux.name)
        elif isinstance(section, GNUVerDefSection):
            for _verdef, verdaux_iter in section.iter_versions():
                for verdaux in verdaux_iter:
                    if verdaux.name and verdaux.name not in defined_versions:
                        defined_versions.append(verdaux.name)

    versym = elffile.get_section_by_name('.gnu.version')
    dynsym = elffile.get_section_by_name('.dynsym')
    if isinstance(versym, GNUVerSymSection) and isinstance(
            dynsym, SymbolTableSection):
        for index in range(versym.num_symbols()):
            symbol = dynsym.get_symbol(index)
            if not symbol.name:
                continue
            version = versym.get_symbol_version(index)
            if version is None or version['name'] is None:
                continue
            if symbol['st_shndx'] == 'SHN_UNDEF':
                filename = version['filename']
                if not filename:
                    continue
                entries = required_symbols.setdefault(filename, [])
                item = {
                    'name': symbol.name,
                    'version': version['name'],
                    'hidden': bool(version['hidden']),
                }
                if item not in entries:
                    entries.append(item)
            else:
                exported_symbols.setdefault(symbol.name, [])
                version_name = version['name']
                if version_name not in exported_symbols[symbol.name]:
                    exported_symbols[symbol.name].append(version_name)

    return (required_versions, required_symbols,
            defined_versions, exported_symbols)


def parse_elf_artifact(path: str | os.PathLike[str]) -> ElfArtifact:
    """Statically parse one ELF input.

    The file is read as bytes by pyelftools; it is never passed to the dynamic
    loader, mmaped as executable code, or executed.
    """
    filesystem_path = os.fspath(path)
    try:
        sha256 = _sha256_file(filesystem_path)
        with open(filesystem_path, 'rb') as stream:
            elffile = ELFFile(stream)
            identity = ElfIdentity(
                elf_class=elffile.elfclass,
                endianness='little' if elffile.little_endian else 'big',
                machine=_normalise_arch(elffile['e_machine']) or
                        str(elffile['e_machine']),
                os_abi=str(elffile['e_ident']['EI_OSABI']),
                e_type=str(elffile['e_type']),
            )

            soname: str | None = None
            needed: list[str] = []
            rpath: list[str] = []
            runpath: list[str] = []
            dynamic = elffile.get_section_by_name('.dynamic')
            if not isinstance(dynamic, (DynamicSection, DynamicSegment)):
                dynamic = next(
                    (segment for segment in elffile.iter_segments()
                     if isinstance(segment, DynamicSegment)),
                    None,
                )
            if isinstance(dynamic, (DynamicSection, DynamicSegment)):
                for tag in dynamic.iter_tags():
                    tag_name = tag.entry.d_tag
                    if tag_name == 'DT_NEEDED':
                        if tag.needed and tag.needed not in needed:
                            needed.append(tag.needed)
                    elif tag_name == 'DT_SONAME':
                        soname = tag.soname or soname
                    elif tag_name == 'DT_RPATH':
                        rpath.extend(_string_list(tag.rpath))
                    elif tag_name == 'DT_RUNPATH':
                        runpath.extend(_string_list(tag.runpath))

            (required_versions, required_symbols,
             defined_versions, exported_symbols) = (
                _required_versions_and_symbols(elffile))
    except (OSError, ELFError, KeyError, TypeError, ValueError,
            struct.error) as exc:
        raise SyslibAuditError(
            f'cannot parse ELF input {filesystem_path!r}: {exc}') from exc

    # DT_NEEDED is the authoritative dependency list.  Keep version entries
    # only for those libraries, but do not drop malformed/orphan requirements
    # silently: they remain in the artifact report.
    return ElfArtifact(
        path=filesystem_path,
        sha256=sha256,
        identity=identity,
        soname=soname,
        needed=needed,
        rpath=rpath,
        runpath=runpath,
        required_versions=required_versions,
        required_symbols=required_symbols,
        defined_versions=defined_versions,
        exported_symbols=exported_symbols,
    )


def _candidate_evidence(
        raw: Mapping[str, Any]) -> tuple[bool | None, dict[str, Any]]:
    evidence_raw = raw.get('evidence', raw.get('attestation'))
    evidence: dict[str, Any] = {}
    verified: bool | None = None

    if isinstance(evidence_raw, bool):
        verified = evidence_raw
        evidence['verified'] = evidence_raw
    elif isinstance(evidence_raw, str):
        evidence['source'] = evidence_raw
    elif isinstance(evidence_raw, Mapping):
        evidence.update({str(key): value
                         for key, value in evidence_raw.items()})
        if 'verified' in evidence:
            verified = _as_bool(evidence['verified'])

    if 'verified' in raw and not isinstance(raw['verified'], Mapping):
        raw_verified = _as_bool(raw['verified'])
        if raw_verified is not None:
            verified = raw_verified
    elif 'attested' in raw:
        raw_attested = _as_bool(raw['attested'])
        if raw_attested is not None:
            verified = raw_attested

    if _as_bool(raw.get('unverified')) is True:
        verified = False
    status = str(raw.get('status', '')).lower()
    if status in ('unverified', 'missing', 'unknown', 'withheld'):
        verified = False

    for key in ('source', 'digest', 'sha256', 'build_id', 'signature',
                'provenance', 'note'):
        if key in raw and key not in evidence:
            evidence[key] = raw[key]

    if verified is not None:
        evidence['verified'] = verified
    return verified, evidence


def _candidate_versions(raw: Mapping[str, Any]) -> frozenset[str] | None:
    keys = (
        'symbol_versions',
        'symbol_version',
        'exported_versions',
        'provided_versions',
        'version_nodes',
        'abi_versions',
        'versions',
    )
    value = _first_present(raw, keys)
    if value is None:
        if raw.get('versions_known') is False:
            return None
        return None

    names: list[str] = []
    if isinstance(value, Mapping):
        for key, symbols in value.items():
            names.append(str(key))
            if isinstance(symbols, str):
                names.append(symbols)
            elif isinstance(symbols, Iterable):
                names.extend(str(item) for item in symbols)
    else:
        names.extend(_string_list(value))
    return frozenset(name for name in names if name)


def _candidate_symbols(
        raw: Mapping[str, Any]) -> dict[str, frozenset[str]] | None:
    value = _first_present(
        raw, ('symbols', 'exported_symbols', 'exports'))
    if value is None:
        if raw.get('symbols_known') is False:
            return None
        return None

    symbols: dict[str, list[str]] = {}
    if isinstance(value, Mapping):
        for name, versions in value.items():
            if isinstance(versions, str):
                symbols.setdefault(str(name), []).append(versions)
            elif isinstance(versions, Iterable):
                for version in versions:
                    symbols.setdefault(str(name), []).append(str(version))
            else:
                symbols.setdefault(str(name), [])
    elif isinstance(value, Iterable):
        for item in value:
            if isinstance(item, str):
                name, _, version = item.partition('@')
                symbols.setdefault(name, [])
                if version:
                    symbols[name].append(version)
            elif isinstance(item, Mapping):
                name = item.get('name', item.get('symbol'))
                if not name:
                    continue
                versions = item.get('versions', item.get('version'))
                symbols.setdefault(str(name), [])
                if versions is not None:
                    symbols[str(name)].extend(_string_list(versions))
    return {
        name: frozenset(versions)
        for name, versions in symbols.items()
    }


_PROVIDER_RELEASE_RE = re.compile(r'^[vV]?\d+(?:\.\d+)*(?:[-+._].*)?$')


def _expand_provider_entries(
        entry: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Expand one manifest entry that lists several provider releases.

    A numeric ``versions``/``version``/``provider_versions`` array is treated
    as a list of provider releases.  Symbol-version nodes such as
    ``GLIBC_2.4`` are left on the entry and are not expanded.
    """
    for key in ('provider_versions', 'provider_version',
                'versions', 'version'):
        value = entry.get(key)
        if not isinstance(value, (list, tuple)) or not value:
            continue
        if not all(
                isinstance(item, str) and
                _PROVIDER_RELEASE_RE.match(item)
                for item in value):
            continue
        expanded: list[Mapping[str, Any]] = []
        for item in value:
            clone = dict(entry)
            clone.pop('provider_versions', None)
            clone.pop('versions', None)
            clone.pop('version', None)
            clone['provider_version'] = item
            expanded.append(clone)
        return expanded
    return [entry]


def _candidate_from_raw(
        raw: Mapping[str, Any],
        *,
        inherited_soname: str | None,
        origin: str,
        index: int,
) -> ProviderCandidate:
    soname = (
        inherited_soname or
        raw.get('soname') or
        raw.get('name') or
        raw.get('library') or
        raw.get('lib') or
        raw.get('needed')
    )
    path = _first_present(
        raw, ('path', 'file', 'location', 'filename',
              'resolved_path'))
    if not soname and path:
        soname = os.path.basename(str(path))
    if not soname:
        raise SyslibAuditError(
            f'environment provider #{index} has no soname/name')

    provider = raw.get('provider', raw.get('vendor', raw.get('package')))
    provider_version = _first_present(
        raw, ('provider_version', 'library_version', 'lib_version',
              'version', 'release'))
    images = tuple(_string_list(_first_present(
        raw, ('images', 'hardware_images', 'available_on', 'only_on',
              'platforms', 'targets'))))

    elf_raw = _as_mapping(raw.get('elf'))
    arch = _first_present(raw, ('arch', 'architecture', 'machine',
                                'em_machine', 'target_arch'))
    if arch is None:
        arch = _first_present(elf_raw, ('arch', 'machine', 'em_machine'))
    elf_class = _first_present(raw, ('elf_class', 'class', 'bits'))
    if elf_class is None:
        elf_class = _first_present(elf_raw, ('elf_class', 'class', 'bits'))
    endianness = _first_present(raw, ('endianness', 'endian', 'byteorder',
                                      'ei_data'))
    if endianness is None:
        endianness = _first_present(
            elf_raw, ('endianness', 'endian', 'byteorder', 'ei_data'))
    os_abi = _first_present(
        raw, ('os_abi', 'abi', 'elf_osabi', 'EI_OSABI'))
    if os_abi is None:
        os_abi = _first_present(elf_raw, ('os_abi', 'abi', 'elf_osabi'))

    verified, evidence = _candidate_evidence(raw)
    exported_versions = _candidate_versions(raw)
    exported_symbols = _candidate_symbols(raw)
    if exported_versions is None and exported_symbols is not None:
        inferred_versions = {
            version
            for versions in exported_symbols.values()
            for version in versions
            if version
        }
        exported_versions = frozenset(inferred_versions)
    priority = _first_present(raw, ('priority', 'rank', 'order'))
    if priority is not None:
        try:
            priority = int(priority)
        except (TypeError, ValueError):
            priority = None

    preferred = bool(raw.get('preferred') or raw.get('default') or
                     raw.get('selected') or raw.get('pin'))

    explicit_id = raw.get('id') or raw.get('candidate_id')
    if explicit_id:
        candidate_id = str(explicit_id)
    else:
        candidate_id = '::'.join([
            str(soname),
            str(provider or 'unknown'),
            str(provider_version or 'unversioned'),
            str(path or 'no-path'),
        ])

    return ProviderCandidate(
        id=candidate_id,
        soname=str(soname),
        provider=str(provider) if provider is not None else None,
        provider_version=(
            str(provider_version) if provider_version is not None else None),
        path=str(path) if path is not None else None,
        images=images,
        arch=_normalise_arch(arch),
        elf_class=_parse_elf_class(elf_class),
        endianness=_normalise_endian(endianness),
        os_abi=str(os_abi) if os_abi is not None else None,
        exported_versions=exported_versions,
        exported_symbols=exported_symbols,
        verified=verified,
        evidence=evidence,
        priority=priority,
        preferred=preferred,
        origin=origin,
        raw=raw,
    )


def _local_candidates(artifact: ElfArtifact) -> list[ProviderCandidate]:
    """Turn another input ELF into a statically evidenced provider."""
    if not artifact.soname:
        return []
    return [ProviderCandidate(
        id=f'{artifact.soname}::input::{artifact.path}',
        soname=artifact.soname,
        provider='input-elf',
        provider_version=None,
        path=artifact.path,
        images=(),
        arch=artifact.identity.machine,
        elf_class=artifact.identity.elf_class,
        endianness=artifact.identity.endianness,
        os_abi=artifact.identity.os_abi,
        exported_versions=frozenset(artifact.defined_versions),
        exported_symbols={
            name: frozenset(versions)
            for name, versions in artifact.exported_symbols.items()
        },
        verified=True,
        evidence={
            'source': 'input-elf',
            'verified': True,
            'sha256': artifact.sha256,
        },
        priority=None,
        preferred=False,
        origin='input',
    )]


def parse_environment(source: str | os.PathLike[str] | Mapping[str, Any]
                      ) -> LibraryEnvironment:
    """Parse a caller-supplied loader environment declaration.

    Both a JSON filename and an already-decoded mapping are accepted.  The
    parser intentionally accepts several common key spellings so manifests
    produced by release tooling do not need to be rewritten.
    """
    if isinstance(source, Mapping):
        raw: Mapping[str, Any] = source
        source_label = '<mapping>'
    elif isinstance(source, (list, tuple)):
        raw = {'providers': list(source)}
        source_label = '<sequence>'
    else:
        source_label = os.fspath(source)
        try:
            with open(source_label, 'r', encoding='utf-8') as stream:
                loaded = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise SyslibAuditError(
                f'cannot read environment declaration {source_label!r}: '
                f'{exc}') from exc
        if not isinstance(loaded, Mapping):
            raise SyslibAuditError(
                f'environment declaration {source_label!r} must be an object')
        raw = loaded

    loader = _as_mapping(raw.get('loader', raw.get('runtime_loader')))
    environment_id = str(
        raw.get('id') or raw.get('environment') or raw.get('name') or
        'caller-declared-environment')

    images_raw = _first_present(
        raw, ('hardware_images', 'images', 'platforms', 'boards'))
    if images_raw is None:
        images_raw = _first_present(
            loader, ('hardware_images', 'images', 'platforms', 'boards'))

    images: list[LoaderImage] = []
    if isinstance(images_raw, Mapping):
        image_items: Iterable[tuple[str | None, Any]] = (
            (str(key), value) for key, value in images_raw.items())
    elif isinstance(images_raw, str):
        image_items = ((None, images_raw),)
    elif isinstance(images_raw, Iterable) and not isinstance(
            images_raw, (str, bytes)):
        image_items = ((None, value) for value in images_raw)
    else:
        image_items = ()

    for index, (key, item) in enumerate(image_items):
        if isinstance(item, str):
            image_id = item
            image_raw: Mapping[str, Any] = {}
        elif isinstance(item, Mapping):
            image_raw = item
            image_id = str(
                key or item.get('id') or item.get('name') or
                item.get('image') or f'image-{index}')
        else:
            continue
        image_search_paths = _string_list(_first_present(
            image_raw,
            ('search_paths', 'library_paths', 'ld_library_path',
             'loader_paths')))
        images.append(LoaderImage(
            id=image_id,
            arch=_normalise_arch(_first_present(
                image_raw, ('arch', 'architecture', 'machine',
                            'em_machine'))),
            elf_class=_parse_elf_class(_first_present(
                image_raw, ('elf_class', 'class', 'bits'))),
            endianness=_normalise_endian(_first_present(
                image_raw, ('endianness', 'endian', 'byteorder'))),
            os_abi=(
                str(_first_present(image_raw, ('os_abi', 'abi')))
                if _first_present(image_raw, ('os_abi', 'abi')) is not None
                else None),
            loader=(
                str(_first_present(image_raw, ('loader', 'ld_so',
                                               'dynamic_loader')))
                if _first_present(image_raw, ('loader', 'ld_so',
                                              'dynamic_loader')) is not None
                else None),
            search_paths=tuple(image_search_paths),
            raw=image_raw,
        ))

    declared_image = raw.get('image', raw.get('hardware_image'))
    if isinstance(declared_image, str) and not any(
            image.id == declared_image for image in images):
        images.append(LoaderImage(id=declared_image))

    target_images = _string_list(_first_present(
        raw, ('target_images', 'target_image', 'selected_images',
              'current_images')))
    if not target_images:
        target_images = _string_list(_first_present(
            loader, ('target_images', 'target_image', 'selected_images',
                     'current_images')))
    if not target_images:
        target_images = [image.id for image in images]
    known_image_ids = {image.id for image in images}
    for image_id in target_images:
        if image_id not in known_image_ids:
            images.append(LoaderImage(id=image_id))
            known_image_ids.add(image_id)
    if not target_images:
        target_images = [image.id for image in images] or ['<unspecified>']

    search_paths = _string_list(_first_present(
        raw, ('search_paths', 'library_paths', 'ld_library_path',
              'loader_paths')))
    if not search_paths:
        search_paths = _string_list(_first_present(
            loader, ('search_paths', 'library_paths', 'ld_library_path',
                     'loader_paths')))

    preferred_raw = _first_present(
        raw, ('preferred', 'selection', 'pins', 'preferred_versions'))
    if not preferred_raw:
        preferred_raw = _first_present(
            loader, ('preferred', 'selection', 'pins',
                     'preferred_versions'))
    preferred: dict[str, str] = {}
    if isinstance(preferred_raw, Mapping):
        preferred = {str(key): str(value)
                     for key, value in preferred_raw.items()}

    providers_raw = _first_present(
        raw, ('providers', 'libraries', 'candidates', 'system_libraries',
              'libs', 'ld_so_cache', 'cache'))
    if providers_raw is None:
        providers_raw = _first_present(
            loader, ('providers', 'libraries', 'candidates',
                     'system_libraries', 'libs', 'ld_so_cache', 'cache'))
    if providers_raw is None:
        # Accept a bare soname-to-candidate map as a convenience.
        implicit = {
            str(key): value
            for key, value in raw.items()
            if isinstance(key, str) and '.so' in key and isinstance(
                value, (Mapping, list, tuple, str, os.PathLike))
        }
        if implicit:
            providers_raw = implicit

    provider_candidates: list[ProviderCandidate] = []
    if isinstance(providers_raw, Mapping):
        provider_items: Iterable[tuple[str | None, Any]] = (
            (str(key), value) for key, value in providers_raw.items())
    elif isinstance(providers_raw, Iterable) and not isinstance(
            providers_raw, (str, bytes)):
        provider_items = ((None, value) for value in providers_raw)
    else:
        provider_items = ()

    seen_ids: dict[str, int] = {}
    for index, (soname, item) in enumerate(provider_items):
        if isinstance(item, Mapping):
            entries: Iterable[Mapping[str, Any]] = (item,)
        elif isinstance(item, (str, os.PathLike)):
            entries = ({'path': os.fspath(item)},)
        elif isinstance(item, Iterable) and not isinstance(
                item, (str, bytes)):
            entries = (entry for entry in item
                       if isinstance(entry, Mapping))
        else:
            continue
        for entry in entries:
            for expanded_entry in _expand_provider_entries(entry):
                candidate = _candidate_from_raw(
                    expanded_entry,
                    inherited_soname=soname,
                    origin='environment',
                    index=index,
                )
                count = seen_ids.get(candidate.id, 0)
                seen_ids[candidate.id] = count + 1
                if count:
                    candidate.id = f'{candidate.id}#{count + 1}'
                provider_candidates.append(candidate)

    return LibraryEnvironment(
        id=environment_id,
        images=tuple(images),
        target_images=tuple(dict.fromkeys(target_images)),
        search_paths=tuple(search_paths),
        preferred=preferred,
        providers=tuple(provider_candidates),
        raw=raw,
    )


def _image_mismatch(
        artifact: ElfArtifact,
        image: LoaderImage | None,
) -> list[str]:
    if image is None:
        return []
    reasons: list[str] = []
    artifact_arch = _normalise_arch(artifact.identity.machine)
    if image.arch and artifact_arch and image.arch != artifact_arch:
        reasons.append(
            f'input architecture {artifact_arch} does not match image '
            f'{image.id} architecture {image.arch}')
    if image.elf_class and artifact.identity.elf_class != image.elf_class:
        reasons.append(
            f'input ELF class {artifact.identity.elf_class} does not match '
            f'image {image.id} ELF class {image.elf_class}')
    if (image.endianness and
            image.endianness != artifact.identity.endianness):
        reasons.append(
            f'input endianness {artifact.identity.endianness} does not match '
            f'image {image.id} endianness {image.endianness}')
    return reasons


def _candidate_availability(
        candidate: ProviderCandidate,
        image: LoaderImage | None,
) -> tuple[bool, str | None]:
    if image is None or not candidate.images:
        return True, None
    if image.id in candidate.images:
        return True, None
    return False, (
        f'candidate {candidate.id} is only declared for hardware image(s) '
        f'{", ".join(candidate.images)}')


def _candidate_compatibility(
        candidate: ProviderCandidate,
        artifact: ElfArtifact,
        image: LoaderImage | None,
) -> list[str]:
    reasons: list[str] = []
    target_arch = image.arch if image and image.arch else (
        _normalise_arch(artifact.identity.machine))
    target_class = image.elf_class if image and image.elf_class else (
        artifact.identity.elf_class)
    target_endian = image.endianness if image and image.endianness else (
        artifact.identity.endianness)

    if candidate.arch and target_arch and candidate.arch != target_arch:
        reasons.append(
            f'candidate architecture {candidate.arch} does not match '
            f'{target_arch}')
    if candidate.elf_class and candidate.elf_class != target_class:
        reasons.append(
            f'candidate ELF class {candidate.elf_class} does not match '
            f'{target_class}')
    if candidate.endianness and candidate.endianness != target_endian:
        reasons.append(
            f'candidate endianness {candidate.endianness} does not match '
            f'{target_endian}')
    return reasons


def _candidate_satisfaction(
        candidate: ProviderCandidate,
        dependency: str,
        artifact: ElfArtifact,
) -> tuple[list[str], list[str], list[str], list[str]]:
    required_versions = list(artifact.required_versions.get(dependency, []))
    required_symbols = list(artifact.required_symbols.get(dependency, []))
    missing_versions: list[str] = []
    missing_symbols: list[str] = []
    notes: list[str] = []
    reasons: list[str] = []

    if required_versions:
        if candidate.exported_versions is None:
            reasons.append(
                f'candidate {candidate.id} has no declared symbol-version '
                f'evidence')
        else:
            missing_versions = [
                version for version in required_versions
                if version not in candidate.exported_versions
            ]
            if missing_versions:
                reasons.append(
                    f'candidate {candidate.id} lacks required symbol '
                    f'version(s): {", ".join(missing_versions)}')

    if required_symbols:
        if candidate.exported_symbols is None:
            notes.append(
                f'candidate {candidate.id} does not declare individual '
                f'symbol evidence; version-node evidence was used')
        else:
            for requirement in required_symbols:
                name = str(requirement['name'])
                version = str(requirement['version'])
                versions = candidate.exported_symbols.get(name)
                if versions is None or version not in versions:
                    missing_symbols.append(f'{name}@{version}')
            if missing_symbols:
                reasons.append(
                    f'candidate {candidate.id} lacks required symbol(s): '
                    f'{", ".join(missing_symbols)}')

    return missing_versions, missing_symbols, notes, reasons


def _path_rank(path: str | None, search_paths: Sequence[str]) -> int:
    if not path or not search_paths:
        return len(search_paths) + 1
    for index, search_path in enumerate(search_paths):
        prefix = search_path.rstrip('/')
        if path == prefix or path.startswith(prefix + '/'):
            return index
    return len(search_paths) + 1


def _selection_key(
        candidate: ProviderCandidate,
        search_paths: Sequence[str],
        preferred: str | None,
) -> tuple[Any, ...]:
    preferred_match = 0
    if preferred:
        tokens = {
            candidate.id,
            candidate.provider,
            candidate.provider_version,
            candidate.path,
            os.path.basename(candidate.path) if candidate.path else None,
            (
                f'{candidate.provider}-{candidate.provider_version}'
                if candidate.provider and candidate.provider_version
                else None
            ),
            (
                f'{candidate.provider}@{candidate.provider_version}'
                if candidate.provider and candidate.provider_version
                else None
            ),
        }
        if preferred in tokens:
            preferred_match = 0
        else:
            preferred_match = 1
    else:
        preferred_match = 0

    # Lower priority values win.  Candidates without an explicit priority are
    # placed after explicitly ranked ones.  Newer provider versions win only
    # when the loader declaration does not otherwise disambiguate.
    priority = candidate.priority if candidate.priority is not None else 10**9
    return (
        0 if candidate.preferred else 1,
        preferred_match,
        priority,
        _path_rank(candidate.path, search_paths),
        _negated_version_key(candidate.provider_version),
        candidate.path or '',
        candidate.id,
    )


class _DescendingVersion:
    """Wrap a version key so tuple comparison sorts newest first."""
    __slots__ = ('value',)

    def __init__(self, value: str | None) -> None:
        self.value = _version_sort_key(value)

    def __lt__(self, other: '_DescendingVersion') -> bool:
        return self.value > other.value

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, _DescendingVersion) and
                self.value == other.value)


def _negated_version_key(value: str | None) -> _DescendingVersion:
    return _DescendingVersion(value)


def _candidate_report(
        candidate: ProviderCandidate,
        *,
        selected_for_images: Sequence[str],
        evaluations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    result = candidate.identity_dict()
    result.update({
        'verified': candidate.verified,
        'evidence': dict(candidate.evidence),
        'exported_symbol_versions': (
            sorted(candidate.exported_versions)
            if candidate.exported_versions is not None else None),
        'exported_symbols': (
            {name: sorted(versions)
             for name, versions in candidate.exported_symbols.items()}
            if candidate.exported_symbols is not None else None),
        'selected_for_images': list(selected_for_images),
        'selected': bool(selected_for_images),
        'evaluations': {
            image: dict(evaluation)
            for image, evaluation in evaluations.items()
        },
    })
    return result


def _evaluate_dependency(
        artifact: ElfArtifact,
        dependency: str,
        environment: LibraryEnvironment,
        candidates: Sequence[ProviderCandidate],
) -> dict[str, Any]:
    target_images = list(environment.target_images)
    evaluations: dict[str, dict[str, dict[str, Any]]] = {
        candidate.id: {} for candidate in candidates
    }
    selected_candidate_by_image: dict[str, ProviderCandidate | None] = {}
    selected_for_images: dict[str, list[str]] = {
        candidate.id: [] for candidate in candidates
    }
    dependency_reasons: list[str] = []
    dependency_notes: list[str] = []

    for image_id in target_images:
        image = environment.image_by_id(image_id)
        mismatch = _image_mismatch(artifact, image)
        preferred = environment.preferred.get(dependency)
        image_search_paths: list[str] = []
        if image is not None:
            image_search_paths.extend(image.search_paths)
        image_search_paths.extend(environment.search_paths)

        eligible: list[ProviderCandidate] = []
        for candidate in candidates:
            available, unavailable_reason = _candidate_availability(
                candidate, image)
            compatibility = _candidate_compatibility(
                candidate, artifact, image)
            missing_versions, missing_symbols, notes, reasons = (
                _candidate_satisfaction(candidate, dependency, artifact))
            reasons = list(compatibility) + reasons
            if unavailable_reason:
                reasons.append(unavailable_reason)
            if candidate.verified is False:
                reasons.append(
                    f'candidate {candidate.id} is explicitly marked '
                    f'unverified')

            is_eligible = (
                not mismatch and available and not reasons
                and candidate.verified is not False)
            if is_eligible:
                eligible.append(candidate)

            evaluations[candidate.id][image_id] = {
                'eligible': is_eligible,
                'available_on_image': available,
                'missing_symbol_versions': missing_versions,
                'missing_symbols': missing_symbols,
                'notes': notes,
                'reasons': reasons,
            }
            dependency_notes.extend(
                note for note in notes if note not in dependency_notes)

        if mismatch:
            dependency_reasons.extend(
                reason for reason in mismatch
                if reason not in dependency_reasons)
            selected_candidate_by_image[image_id] = None
            continue

        if not eligible:
            selected_candidate_by_image[image_id] = None
            if not candidates:
                reason = (
                    f'no evidence for external library {dependency!r}; '
                    f'library path was not opened')
            else:
                reason = (
                    f'no declared provider for {dependency!r} can be '
                    f'verified on image {image_id}')
            if reason not in dependency_reasons:
                dependency_reasons.append(reason)
            # Surface the concrete candidate-level cause (for example a
            # missing GLIBC node or an architecture mismatch) without
            # pretending that a candidate was selected.
            for candidate in candidates:
                for reason in evaluations[candidate.id][image_id]['reasons']:
                    if reason not in dependency_reasons:
                        dependency_reasons.append(reason)
            continue

        selected = min(
            eligible,
            key=lambda candidate: _selection_key(
                candidate, image_search_paths, preferred))
        selected_for_images[selected.id].append(image_id)
        selected_candidate_by_image[image_id] = selected

    selected_by_image: dict[str, dict[str, Any] | None] = {
        image_id: (
            _candidate_report(
                candidate,
                selected_for_images=selected_for_images[candidate.id],
                evaluations=evaluations[candidate.id],
            )
            if candidate is not None else None)
        for image_id, candidate in selected_candidate_by_image.items()
    }

    image_specific = False
    only_on: list[str] = []
    candidate_hardware_images: list[str] = []
    # A dependency is image-specific only when every declared provider is
    # restricted to hardware images and their union is narrower than the
    # environment's declared image set.  One unrestricted provider means the
    # dependency can appear on every image.
    if candidates and all(candidate.images for candidate in candidates):
        restricted_images = {
            image_id
            for candidate in candidates
            for image_id in candidate.images
        }
        candidate_hardware_images = sorted(restricted_images)
        declared_images = {image.id for image in environment.images}
        if not declared_images or restricted_images != declared_images:
            image_specific = True
            only_on = list(candidate_hardware_images)

    candidate_reports = [
        _candidate_report(
            candidate,
            selected_for_images=selected_for_images[candidate.id],
            evaluations=evaluations[candidate.id],
        )
        for candidate in candidates
    ]
    selected = (
        selected_by_image[target_images[0]]
        if len(target_images) == 1 else None)
    unresolved_images = [
        image_id for image_id in target_images
        if selected_by_image.get(image_id) is None
    ]
    status = (
        STATUS_SIGNED_OFF if not unresolved_images
        else STATUS_PENDING_EVIDENCE)

    return {
        'soname': dependency,
        'required_symbol_versions': list(
            artifact.required_versions.get(dependency, [])),
        'required_symbols': [
            dict(item)
            for item in artifact.required_symbols.get(dependency, [])
        ],
        'status': status,
        'signed_off': status == STATUS_SIGNED_OFF,
        'signoff': status == STATUS_SIGNED_OFF,
        'needs_evidence': status != STATUS_SIGNED_OFF,
        'external': not candidates,
        'evidence_missing': status != STATUS_SIGNED_OFF,
        'evidence_status': (
            'complete' if status == STATUS_SIGNED_OFF else 'missing'),
        'candidate_count': len(candidates),
        'eligible_candidate_count': len({
            candidate.id
            for candidate in candidates
            if any(
                evaluation.get('eligible')
                for evaluation in evaluations[candidate.id].values())
        }),
        'image_specific': image_specific,
        'only_on_hardware_images': only_on,
        'candidate_hardware_images': candidate_hardware_images,
        'target_images': target_images,
        'selected': selected,
        'selected_by_image': {
            image_id: selected_by_image.get(image_id)
            for image_id in target_images
        },
        'unresolved_images': unresolved_images,
        'candidates': candidate_reports,
        'reasons': dependency_reasons,
        'notes': dependency_notes,
    }


def _deduplicate_candidates(
        candidates: Iterable[ProviderCandidate],
) -> list[ProviderCandidate]:
    result: list[ProviderCandidate] = []
    seen: set[tuple[Any, ...]] = set()
    for candidate in candidates:
        key = (
            candidate.soname,
            candidate.provider,
            candidate.provider_version,
            candidate.path,
            candidate.images,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)
    return result


def audit_artifacts(
        artifacts: Sequence[ElfArtifact],
        environment: str | os.PathLike[str] | Mapping[str, Any] |
        LibraryEnvironment,
        *,
        include_input_providers: bool = True,
) -> dict[str, Any]:
    """Audit parsed artifacts against an environment declaration."""
    env = (
        environment if isinstance(environment, LibraryEnvironment)
        else parse_environment(environment))

    local_candidates = (
        [candidate
         for artifact in artifacts
         for candidate in _local_candidates(artifact)]
        if include_input_providers else [])
    all_candidates = _deduplicate_candidates(
        list(env.providers) + local_candidates)

    artifact_reports: list[dict[str, Any]] = []
    image_specific_dependencies: list[dict[str, str]] = []
    unresolved_dependencies: list[dict[str, str]] = []
    dependency_count = 0

    for artifact in artifacts:
        dependencies = []
        for dependency in artifact.needed:
            candidates = [
                candidate for candidate in all_candidates
                if candidate.soname == dependency
            ]
            result = _evaluate_dependency(
                artifact, dependency, env, candidates)
            dependencies.append(result)
            dependency_count += 1
            if result['image_specific']:
                image_specific_dependencies.append({
                    'artifact': artifact.path,
                    'soname': dependency,
                    'images': ', '.join(result['only_on_hardware_images']),
                })
            if result['status'] != STATUS_SIGNED_OFF:
                unresolved_dependencies.append({
                    'artifact': artifact.path,
                    'soname': dependency,
                    'images': ', '.join(result['unresolved_images']),
                })

        pending = [
            dependency['soname']
            for dependency in dependencies
            if dependency['status'] != STATUS_SIGNED_OFF
        ]
        artifact_reports.append({
            'path': artifact.path,
            'sha256': artifact.sha256,
            'identity': artifact.identity.to_dict(),
            'soname': artifact.soname,
            'needed': list(artifact.needed),
            'rpath': list(artifact.rpath),
            'runpath': list(artifact.runpath),
            'defined_versions': list(artifact.defined_versions),
            'status': (
                STATUS_SIGNED_OFF if not pending
                else STATUS_PENDING_EVIDENCE),
            'signed_off': not pending,
            'signoff': not pending,
            'needs_evidence': bool(pending),
            'unresolved_dependencies': pending,
            'image_specific_dependencies': [
                dependency['soname']
                for dependency in dependencies
                if dependency['image_specific']
            ],
            'dependencies': dependencies,
        })

    signed_off_artifacts = sum(
        1 for artifact in artifact_reports if artifact['signed_off'])
    overall_signed_off = (
        bool(artifact_reports) and
        signed_off_artifacts == len(artifact_reports))

    return {
        'schema': SCHEMA,
        'environment': env.to_dict(),
        'artifacts': artifact_reports,
        'summary': {
            'artifact_count': len(artifact_reports),
            'signed_off_artifacts': signed_off_artifacts,
            'pending_evidence_artifacts': (
                len(artifact_reports) - signed_off_artifacts),
            'dependency_count': dependency_count,
            'image_specific_dependencies': image_specific_dependencies,
            'unresolved_dependencies': unresolved_dependencies,
        },
        'status': (
            STATUS_SIGNED_OFF if overall_signed_off
            else STATUS_PENDING_EVIDENCE),
        'signed_off': overall_signed_off,
        'signoff': overall_signed_off,
        'needs_evidence': not overall_signed_off,
    }


def audit(
        elf_paths: str | os.PathLike[str] |
        Sequence[str | os.PathLike[str]],
        environment: str | os.PathLike[str] | Mapping[str, Any] |
        LibraryEnvironment,
        *,
        include_input_providers: bool = True,
) -> dict[str, Any]:
    """Parse ELF inputs and audit them against an environment declaration."""
    if isinstance(elf_paths, (str, os.PathLike)):
        paths: Sequence[str | os.PathLike[str]] = [elf_paths]
    else:
        paths = elf_paths
    if not paths:
        raise SyslibAuditError('at least one ELF input is required')
    artifacts = [parse_elf_artifact(path) for path in paths]
    return audit_artifacts(
        artifacts, environment,
        include_input_providers=include_input_providers)


def audit_elf(
        elf_path: str | os.PathLike[str],
        environment: str | os.PathLike[str] | Mapping[str, Any] |
        LibraryEnvironment,
        *,
        include_input_providers: bool = True,
) -> dict[str, Any]:
    """Audit a single ELF input."""
    return audit(
        [elf_path], environment,
        include_input_providers=include_input_providers)


def audit_manifest(
        elf_paths: str | os.PathLike[str] |
        Sequence[str | os.PathLike[str]],
        environment: str | os.PathLike[str] | Mapping[str, Any] |
        LibraryEnvironment,
        *,
        include_input_providers: bool = True,
) -> dict[str, Any]:
    """Alias for :func:`audit`, matching release-manifest terminology."""
    return audit(
        elf_paths, environment,
        include_input_providers=include_input_providers)


def _format_text(result: Mapping[str, Any], stream: TextIO) -> None:
    environment = _as_mapping(result.get('environment'))
    print(
        f"Environment: {environment.get('id', '<unknown>')}  "
        f"Status: {result['status']}",
        file=stream)
    for artifact in result.get('artifacts', []):
        print(f"\nArtifact: {artifact['path']}", file=stream)
        print(f"  Status: {artifact['status']}", file=stream)
        for dependency in artifact['dependencies']:
            selected = dependency.get('selected')
            if selected:
                selected_text = (
                    f"{selected.get('provider') or 'provider'} "
                    f"{selected.get('provider_version') or ''} "
                    f"({selected.get('path')})").strip()
            else:
                selected_text = '<none>'
            versions = ', '.join(dependency['required_symbol_versions'])
            print(
                f"  {dependency['soname']}: {dependency['status']}  "
                f"selected={selected_text}  "
                f"required_versions=[{versions}]",
                file=stream)
            if dependency['candidates']:
                print(
                    f"    candidates: "
                    f"{len(dependency['candidates'])}",
                    file=stream)
            if dependency['image_specific']:
                print(
                    f"    hardware images: "
                    f"{', '.join(dependency['only_on_hardware_images'])}",
                    file=stream)
            for reason in dependency['reasons']:
                print(f"    reason: {reason}", file=stream)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='elf-syslib-audit',
        description=(
            'Statically audit ELF DT_NEEDED/symbol-version requirements '
            'against a caller-supplied loader environment declaration. '
            'Library paths named by the declaration are never opened.'))
    parser.add_argument(
        'elf', nargs='+', help='input ELF artifact(s); parsed as data only')
    parser.add_argument(
        '-e', '--environment', '--env', required=True,
        help='JSON loader environment declaration')
    parser.add_argument(
        '--format', choices=('json', 'text'), default='json',
        help='output format (default: json)')
    parser.add_argument(
        '--json', dest='format', action='store_const',
        const='json', help='shorthand for --format json')
    parser.add_argument(
        '-o', '--output', '--out',
        help='write the report to this file instead of stdout')
    parser.add_argument(
        '--no-input-providers', action='store_true',
        help='do not treat companion input ELFs as local providers')
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    try:
        result = audit(
            args.elf,
            args.environment,
            include_input_providers=not args.no_input_providers)
    except SyslibAuditError as exc:
        print(f'elf-syslib-audit: {exc}', file=sys.stderr)
        return 1

    output: TextIO
    try:
        if args.output:
            output = open(args.output, 'w', encoding='utf-8')
        else:
            output = sys.stdout
    except OSError as exc:
        print(f'elf-syslib-audit: cannot open output: {exc}',
              file=sys.stderr)
        return 1
    try:
        if args.format == 'json':
            json.dump(result, output, indent=2, sort_keys=False)
            output.write('\n')
        else:
            _format_text(result, output)
    finally:
        if args.output:
            output.close()
    return 0 if result['signed_off'] else 2


if __name__ == '__main__':
    sys.exit(main())
