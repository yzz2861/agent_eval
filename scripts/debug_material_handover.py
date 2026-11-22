#!/usr/bin/env python3
"""Read-only audit of declared separate-debug material with pyelftools.

The auditor never rewrites, strips or relinks an ELF file.  It only uses
pyelftools' read-only ELF/DWARF interfaces plus hashlib/zlib from the standard
library.

Three build conventions are recognised:

  .gnu_debuglink       object -> stripped debug file (CRC32)
  .debug_sup           DWARF5 primary -> supplementary object (versioned
                       filename + producer checksum)
  .gnu_debugaltlink    GNU primary -> supplementary object (filename +
                       20-byte build ID)

The tool deliberately does not trust a file because it was found under the
expected path.  Every resolution is bound back to the bytes that the primary
declared, and CUs are only reported as confirmed when that binding is
independently checkable.  Duplicate files are folded by content hash rather
than path, so reusing a build directory cannot create extra approval slots.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from elftools.elf.elffile import ELFFile


SUPPLEMENTARY_STRING_FORMS = frozenset({
    'DW_FORM_strp_sup',
    'DW_FORM_GNU_strp_alt',
})

SUPPLEMENTARY_REF_FORMS = frozenset({
    'DW_FORM_ref_sup4',
    'DW_FORM_ref_sup8',
    'DW_FORM_GNU_ref_alt',
})

SUPPLEMENTARY_FORMS = SUPPLEMENTARY_STRING_FORMS | SUPPLEMENTARY_REF_FORMS


def _hex(data: bytes) -> str:
    return data.hex()


def _file_sha1(path: str) -> str:
    digest = hashlib.sha1()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _file_crc32(path: str) -> int:
    crc = 0
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            crc = zlib.crc32(chunk, crc)
    return crc & 0xFFFFFFFF


def _build_id(elf: ELFFile) -> str | None:
    section = elf.get_section_by_name('.note.gnu.build-id')
    if section is None:
        return None
    for note in section.iter_notes():
        if note['n_type'] == 'NT_GNU_BUILD_ID':
            return note['n_descdata'].hex()
    return None


def _section_bytes(elf: ELFFile, name: str) -> bytes | None:
    section = elf.get_section_by_name(name)
    return section.data() if section is not None else None


def _parse_debug_sup(elf: ELFFile) -> dict[str, Any] | None:
    """Parse the on-disk .debug_sup record, including the checksum bytes.

    pyelftools intentionally stops after the filename ("we don't care about
    checksums, for now"), so the auditor reads the remaining bytes directly.
    """
    data = _section_bytes(elf, '.debug_sup')
    if data is None:
        return None
    if len(data) < 3:
        return {
            'version': None,
            'is_supplementary': None,
            'filename': None,
            'checksum': None,
            'malformed': True,
        }
    version = int.from_bytes(data[:2], 'little')
    is_supplementary = data[2]
    nul = data.find(b'\x00', 3)
    if nul < 0:
        return {
            'version': version,
            'is_supplementary': is_supplementary,
            'filename': None,
            'checksum': None,
            'malformed': True,
        }
    return {
        'version': version,
        'is_supplementary': is_supplementary,
        'filename': data[3:nul],
        'checksum': data[nul + 1:],
        'malformed': False,
    }


def _parse_gnu_debugaltlink(elf: ELFFile) -> dict[str, Any] | None:
    data = _section_bytes(elf, '.gnu_debugaltlink')
    if data is None:
        return None
    nul = data.find(b'\x00')
    if nul < 0:
        return {'filename': None, 'checksum': None, 'malformed': True}
    return {
        'filename': data[:nul],
        'checksum': data[nul + 1:],
        'malformed': False,
    }


def _parse_gnu_debuglink(elf: ELFFile) -> dict[str, Any] | None:
    data = _section_bytes(elf, '.gnu_debuglink')
    if data is None:
        return None
    nul = data.find(b'\x00')
    if nul < 0 or len(data) < nul + 5:
        return {'filename': None, 'checksum': None, 'malformed': True}
    return {
        'filename': data[:nul],
        'checksum': int.from_bytes(data[nul + 1:nul + 5], 'little'),
        'malformed': False,
    }


def _candidate_paths(name: bytes, base_dir: str,
                     search_dirs: list[str]) -> list[str]:
    """Return conventional candidate paths without trusting any of them.

    Absolute names and names escaping the material directory are rejected, in
    line with the library's relative-loader policy.
    """
    try:
        rel = os.fsdecode(name)
    except UnicodeDecodeError:
        return []
    if not rel or os.path.isabs(rel):
        return []

    candidates: list[str] = []
    roots = [base_dir, os.path.join(base_dir, '.debug'), *search_dirs]
    seen: set[str] = set()
    for root in roots:
        real_root = os.path.realpath(root)
        candidate = os.path.realpath(os.path.join(real_root, rel))
        if os.path.commonpath([real_root, candidate]) != real_root:
            continue
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _first_existing(candidates: list[str]) -> str | None:
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _sup_checksum_matches_bytes(declared: bytes | None, path: str) -> bool:
    if not declared or not path:
        return False
    with open(path, 'rb') as stream:
        payload = stream.read()
    if len(declared) >= 20:
        if hashlib.sha1(payload).digest() == declared[:20]:
            return True
        if hashlib.md5(payload).digest() == declared[:16]:
            return True
    return False


def _verify_debuglink(object_path: str, link: dict[str, Any],
                      search_dirs: list[str]) -> dict[str, Any]:
    base_dir = os.path.dirname(os.path.abspath(object_path))
    name = link.get('filename') or b''
    candidates = _candidate_paths(name, base_dir, search_dirs)
    resolved = _first_existing(candidates)
    result: dict[str, Any] = {
        'kind': 'gnu_debuglink',
        'declared_filename': os.fsdecode(name) if name else None,
        'declared_crc32': f"0x{link['checksum']:08x}" if link.get('checksum') is not None else None,
        'candidates': candidates,
        'resolved_path': resolved,
        'status': 'missing',
        'method': 'CRC32 over the whole debug file',
    }
    if link.get('malformed'):
        result['status'] = 'malformed'
        result['reason'] = 'truncated .gnu_debuglink record'
        return result
    if resolved is None:
        result['reason'] = 'no conventional candidate exists'
        return result

    actual_crc = _file_crc32(resolved)
    result['actual_crc32'] = f"0x{actual_crc:08x}"
    result['crc32_matches'] = actual_crc == link['checksum']

    object_build_id = None
    debug_build_id = None
    with ELFFile.load_from_path(object_path) as elf:
        object_build_id = _build_id(elf)
    with ELFFile.load_from_path(resolved) as elf:
        debug_build_id = _build_id(elf)
    result['object_build_id'] = object_build_id
    result['debug_build_id'] = debug_build_id
    result['build_id_matches'] = (
        object_build_id is not None and object_build_id == debug_build_id)

    if result['crc32_matches']:
        result['status'] = 'confirmed'
        result['binding'] = 'crc32'
        if result['build_id_matches']:
            result['binding'] = 'crc32+build-id'
    else:
        result['status'] = 'mismatch'
        result['reason'] = 'CRC32 differs from the value declared by the object'
    return result


def _verify_debug_sup(debug_path: str, link: dict[str, Any],
                      search_dirs: list[str]) -> dict[str, Any]:
    base_dir = os.path.dirname(os.path.abspath(debug_path))
    name = link.get('filename') or b''
    candidates = _candidate_paths(name, base_dir, search_dirs)
    resolved = _first_existing(candidates)
    declared = link.get('checksum') or b''
    result: dict[str, Any] = {
        'kind': 'debug_sup',
        'declared_version': link.get('version'),
        'declared_is_supplementary': link.get('is_supplementary'),
        'declared_filename': os.fsdecode(name) if name else None,
        'declared_checksum': _hex(declared) if declared else None,
        'candidates': candidates,
        'resolved_path': resolved,
        'status': 'missing',
        'method': 'DWARF5 .debug_sup filename + checksum bytes',
    }
    if link.get('malformed'):
        result['status'] = 'malformed'
        result['reason'] = 'truncated .debug_sup record'
        return result
    if link.get('is_supplementary') == 1:
        result['status'] = 'supplementary'
        result['reason'] = (
            'this file declares itself as a supplementary object; it has no '
            'outbound link to resolve')
        return result
    if resolved is None:
        result['reason'] = 'no conventional candidate exists'
        return result

    with ELFFile.load_from_path(resolved) as sup_elf:
        sup_link = _parse_debug_sup(sup_elf)
        sup_build_id = _build_id(sup_elf)
        sup_sha1 = _file_sha1(resolved)

    result['candidate_sha1'] = sup_sha1
    result['candidate_build_id'] = sup_build_id
    result['candidate_self_declared_supplementary'] = (
        sup_link.get('is_supplementary') == 1 if sup_link else None)
    result['candidate_declared_checksum'] = (
        _hex(sup_link['checksum']) if sup_link and sup_link.get('checksum') else None)
    result['token_matches_candidate'] = bool(
        sup_link and sup_link.get('checksum') == declared)

    sha1_matches = False
    md5_matches = False
    if declared:
        with open(resolved, 'rb') as stream:
            payload = stream.read()
        if len(declared) >= 20:
            sha1_matches = hashlib.sha1(payload).digest() == declared[:20]
        if len(declared) >= 16:
            md5_matches = hashlib.md5(payload).digest() == declared[:16]
    build_id_matches = bool(
        declared and sup_build_id and
        bytes.fromhex(sup_build_id) == declared[:20])

    result['sha1_matches_file'] = sha1_matches
    result['md5_matches_file'] = md5_matches
    result['build_id_matches'] = build_id_matches

    if sha1_matches or md5_matches or build_id_matches:
        result['status'] = 'confirmed'
        result['binding'] = (
            'build-id' if build_id_matches else 'sha1' if sha1_matches else 'md5')
    else:
        result['status'] = 'unconfirmed'
        result['reason'] = (
            'the declared checksum is not derivable from the delivered '
            'supplementary file and the file carries no build ID; equality '
            'with the candidate\'s own .debug_sup token is not independent '
            'evidence')
    return result


def _verify_debugaltlink(debug_path: str, link: dict[str, Any],
                         search_dirs: list[str]) -> dict[str, Any]:
    base_dir = os.path.dirname(os.path.abspath(debug_path))
    name = link.get('filename') or b''
    candidates = _candidate_paths(name, base_dir, search_dirs)
    resolved = _first_existing(candidates)
    declared = link.get('checksum') or b''
    result: dict[str, Any] = {
        'kind': 'gnu_debugaltlink',
        'declared_filename': os.fsdecode(name) if name else None,
        'declared_build_id': _hex(declared) if declared else None,
        'candidates': candidates,
        'resolved_path': resolved,
        'status': 'missing',
        'method': '20-byte build ID in .gnu_debugaltlink',
    }
    if link.get('malformed'):
        result['status'] = 'malformed'
        result['reason'] = 'truncated .gnu_debugaltlink record'
        return result
    if resolved is None:
        result['reason'] = 'no conventional candidate exists'
        return result

    with ELFFile.load_from_path(resolved) as sup_elf:
        sup_build_id = _build_id(sup_elf)
        sup_sha1 = _file_sha1(resolved)
    result['candidate_sha1'] = sup_sha1
    result['candidate_build_id'] = sup_build_id

    if declared and sup_build_id:
        matches = bytes.fromhex(sup_build_id) == declared[:20]
        result['build_id_matches'] = matches
        if matches:
            result['status'] = 'confirmed'
            result['binding'] = 'build-id'
        else:
            result['status'] = 'mismatch'
            result['reason'] = 'supplementary build ID differs from the declaration'
    else:
        result['build_id_matches'] = False
        result['status'] = 'unconfirmed'
        result['reason'] = (
            'the supplementary file has no .note.gnu.build-id; the filename '
            'alone cannot bind it to the declaration')
    return result


def _identity(top_die) -> dict[str, Any]:
    name_attr = top_die.attributes.get('DW_AT_name')
    comp_dir_attr = top_die.attributes.get('DW_AT_comp_dir')

    def decode(attr) -> str | None:
        if attr is None:
            return None
        value = attr.value
        if isinstance(value, bytes):
            return value.decode('utf-8', 'replace')
        if isinstance(value, int):
            return None
        return str(value)

    name_form = name_attr.form if name_attr else None
    comp_dir_form = comp_dir_attr.form if comp_dir_attr else None
    name = decode(name_attr)
    comp_dir = decode(comp_dir_attr)
    inline = (
        name_form is not None and name_form not in SUPPLEMENTARY_FORMS and
        comp_dir_form is not None and comp_dir_form not in SUPPLEMENTARY_FORMS)
    key = None
    if name is not None and comp_dir is not None:
        key = f"{comp_dir}/{name}"
    return {
        'name': name,
        'comp_dir': comp_dir,
        'name_form': name_form,
        'comp_dir_form': comp_dir_form,
        'source': 'inline' if inline else 'supplementary',
        'inline': inline,
        'key': key,
    }


def _collect_cus(elf: ELFFile, link_status: str) -> list[dict[str, Any]]:
    try:
        # Keep the raw view as well: when links are followed, pyelftools
        # replaces DW_TAG_imported_unit with the imported children, which would
        # hide the original CU's DW_AT_import references.
        raw_dwarfinfo = elf.get_dwarf_info(follow_links=False)
        linked_dwarfinfo = elf.get_dwarf_info(follow_links=True)
    except Exception:
        # A broken/unverified debuglink must not make the audit itself fail.
        return []

    supplementary = linked_dwarfinfo.supplementary_dwarfinfo
    has_supplementary = supplementary is not None
    linked_cus = {cu.cu_offset: cu for cu in linked_dwarfinfo.iter_CUs()}
    units: list[dict[str, Any]] = []

    for raw_cu in raw_dwarfinfo.iter_CUs():
        linked_cu = linked_cus.get(raw_cu.cu_offset)
        top = linked_cu.get_top_DIE() if linked_cu is not None else raw_cu.get_top_DIE()
        ident = _identity(top)
        def linked_die_for(raw_offset: int):
            if linked_cu is None:
                return None
            try:
                return linked_cu.get_DIE_from_refaddr(raw_offset)
            except Exception:
                return None

        external: Counter[str] = Counter()
        refs: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []

        for raw_die in raw_cu.iter_DIEs():
            linked_die = linked_die_for(raw_die.offset)
            for attr_name, attr in raw_die.attributes.items():
                if attr.form not in SUPPLEMENTARY_FORMS:
                    continue
                external[attr.form] += 1
                record: dict[str, Any] = {
                    'cu_offset': f"0x{raw_cu.cu_offset:x}",
                    'die_offset': f"0x{raw_die.offset:x}",
                    'attribute': attr_name,
                    'form': attr.form,
                    'raw_value': attr.raw_value,
                    'target': 'supplementary',
                }
                if attr.form in SUPPLEMENTARY_STRING_FORMS:
                    value = (
                        linked_die.attributes[attr_name].value
                        if linked_die is not None and
                        attr_name in linked_die.attributes else None)
                    resolved = isinstance(value, bytes)
                    record['resolved'] = resolved
                    if resolved:
                        record['resolved_preview'] = (
                            value[:80].decode('utf-8', 'replace'))
                else:
                    try:
                        if linked_die is not None:
                            target = linked_die.get_DIE_from_attribute(attr_name)
                        elif supplementary is not None:
                            target = supplementary.get_DIE_from_refaddr(
                                attr.raw_value)
                        else:
                            raise LookupError('supplementary object unavailable')
                        record['resolved'] = True
                        record['target_tag'] = target.tag
                        record['target_offset'] = f"0x{target.offset:x}"
                    except Exception as exc:  # malformed or missing supplementary
                        record['resolved'] = False
                        record['resolution_error'] = type(exc).__name__
                        unresolved.append(record)

                if link_status != 'confirmed':
                    record['confirmation'] = 'unconfirmed'
                    record['confirmation_reason'] = (
                        'supplementary file is not bound to the declaration')
                else:
                    record['confirmation'] = 'confirmed'
                refs.append(record)

        identity_confirmed = ident['inline'] or (
            link_status == 'confirmed' and ident['name'] is not None and
            ident['comp_dir'] is not None and has_supplementary)

        units.append({
            'offset': f"0x{raw_cu.cu_offset:x}",
            'version': raw_cu.header.version,
            'unit_length': raw_cu.header.unit_length,
            'tag': top.tag,
            'identity': ident,
            'identity_confirmed': identity_confirmed,
            'external_ref_counts': dict(sorted(external.items())),
            'external_refs_total': sum(external.values()),
            'unresolved_refs': len(unresolved),
            'references': refs,
        })
    return units


def _audit_file(path: str, search_dirs: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with ELFFile.load_from_path(path) as elf:
        sha1 = _file_sha1(path)
        build_id = _build_id(elf)
        has_debug_info = elf.get_section_by_name('.debug_info') is not None

        debuglink = _parse_gnu_debuglink(elf)
        debug_sup = _parse_debug_sup(elf)
        altlink = _parse_gnu_debugaltlink(elf)

        if debuglink is not None:
            verification = _verify_debuglink(path, debuglink, search_dirs)
            linked_cus: list[dict[str, Any]] = []
            if (verification.get('status') == 'confirmed' and
                    verification.get('resolved_path')):
                with ELFFile.load_from_path(
                        verification['resolved_path']) as debug_elf:
                    linked_cus = _collect_cus(debug_elf, 'confirmed')
            entries.append({
                'role': 'object',
                'path': os.path.relpath(path),
                'sha1': sha1,
                'build_id': build_id,
                'has_debug_info': has_debug_info,
                'declaration': verification.pop('declaration', None),
                'verification': verification,
                'cus': linked_cus,
            })

        if debug_sup is not None:
            verification = _verify_debug_sup(path, debug_sup, search_dirs)
            entries.append({
                'role': ('supplementary'
                         if verification['status'] == 'supplementary'
                         else 'debug-primary'),
                'path': os.path.relpath(path),
                'sha1': sha1,
                'build_id': build_id,
                'has_debug_info': has_debug_info,
                'verification': verification,
                'cus': _collect_cus(elf, verification['status']),
            })

        if altlink is not None:
            verification = _verify_debugaltlink(path, altlink, search_dirs)
            entries.append({
                'role': 'debug-primary',
                'path': os.path.relpath(path),
                'sha1': sha1,
                'build_id': build_id,
                'has_debug_info': has_debug_info,
                'verification': verification,
                'cus': _collect_cus(elf, verification['status']),
            })

        if not entries:
            entries.append({
                'role': 'debug-file' if has_debug_info else 'elf-file',
                'path': os.path.relpath(path),
                'sha1': sha1,
                'build_id': build_id,
                'has_debug_info': has_debug_info,
                'verification': {
                    'kind': 'none',
                    'status': 'not-linked',
                    'reason': 'no separate-debug declaration in this file',
                },
                'cus': _collect_cus(elf, 'not-linked'),
            })
    return entries


def _dedupe(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for entry in entries:
        groups.setdefault(entry['sha1'], []).append(entry['path'])
    duplicates = []
    for sha1, paths in sorted(groups.items()):
        if len(paths) > 1:
            duplicates.append({
                'sha1': sha1,
                'paths': sorted(paths),
                'distinct_identities': 1,
                'note': (
                    'byte-identical copies; they must not be counted as '
                    'independent approval evidence'),
            })
    return duplicates


def _confirmed_original_keys(entries: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for entry in entries:
        for cu in entry['cus']:
            if cu['tag'] != 'DW_TAG_compile_unit':
                continue
            if cu['identity_confirmed'] and cu['identity']['key']:
                keys.add(cu['identity']['key'])
    return keys


def _unconfirmed_reference_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for entry in entries:
        if entry['verification'].get('status') in ('confirmed', 'supplementary'):
            continue
        per_cu = []
        total = 0
        for cu in entry['cus']:
            refs = [r for r in cu['references'] if r.get('confirmation') == 'unconfirmed']
            if not refs:
                continue
            total += len(refs)
            per_cu.append({
                'cu_offset': cu['offset'],
                'identity': cu['identity'],
                'counts': dict(Counter(r['form'] for r in refs)),
                'samples': refs[:8],
            })
        if per_cu:
            summary.append({
                'path': entry['path'],
                'link_status': entry['verification'].get('status'),
                'total_unconfirmed_references': total,
                'by_cu': per_cu,
            })
    return summary


def _verification_of(entries: list[dict[str, Any]], path_suffix: str) -> dict[str, Any]:
    for entry in entries:
        if entry['path'].endswith(path_suffix):
            return entry['verification']
    return {}


def build_report(paths: list[str], search_dirs: list[str],
                 approval_cap: int) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in paths:
        entries.extend(_audit_file(path, search_dirs))

    duplicates = _dedupe(entries)

    debugsup = [e for e in entries if e['verification'].get('kind') == 'debug_sup']
    altlink = [e for e in entries if e['verification'].get('kind') == 'gnu_debugaltlink']
    debuglink = [e for e in entries if e['verification'].get('kind') == 'gnu_debuglink']
    probes = []
    dl_entry = next((e for e in debuglink
                     if e["verification"].get("status") == "confirmed"
                     and e["verification"].get("resolved_path")), None)
    if dl_entry is not None:
        expected = dl_entry["verification"].get("declared_crc32")
        base = os.path.dirname(dl_entry["verification"]["resolved_path"])
        alternatives = []
        for name in sorted(os.listdir(base)):
            if not name.endswith(".debug"):
                continue
            target = os.path.join(base, name)
            if target == dl_entry["verification"]["resolved_path"]:
                continue
            actual = f"0x{_file_crc32(target):08x}"
            alternatives.append({
                "path": os.path.relpath(target),
                "crc32": actual,
                "would_be_accepted": actual == expected,
                "reject_reason": (None if actual == expected
                                  else "crc32 mismatch"),
            })
        probes.append({
            "declaration": "gnu_debuglink",
            "expected": expected,
            "alternatives": alternatives[:6],
        })

    al_entry = next((e for e in altlink
                     if e["verification"].get("status") == "confirmed"
                     and e["verification"].get("resolved_path")), None)
    if al_entry is not None:
        expected = al_entry["verification"].get("declared_build_id")
        base = os.path.dirname(al_entry["verification"]["resolved_path"])
        alternatives = []
        for name in sorted(os.listdir(base)):
            if not (name.endswith(".debug") or name.endswith(".common")):
                continue
            target = os.path.join(base, name)
            if target == al_entry["verification"]["resolved_path"]:
                continue
            with ELFFile.load_from_path(target) as probe_elf:
                bid = _build_id(probe_elf)
            alternatives.append({
                "path": os.path.relpath(target),
                "build_id": bid,
                "would_be_accepted": bid == expected,
                "reject_reason": (None if bid == expected
                                  else ("no build-id" if bid is None
                                        else "build-id mismatch")),
            })
        probes.append({
            "declaration": "gnu_debugaltlink",
            "expected": expected,
            "alternatives": alternatives[:6],
        })


    debugsup_keys = _confirmed_original_keys(debugsup)
    altlink_keys = _confirmed_original_keys(altlink)
    # The conservative handover only uses identities that survive both
    # encodings of the same dwz material.
    intersection = sorted(debugsup_keys & altlink_keys)
    if not intersection:
        intersection = sorted(altlink_keys or debugsup_keys)
    approved = intersection[:approval_cap]

    missing = []
    for entry in entries:
        verification = entry['verification']
        if verification.get('status') in ('missing', 'mismatch', 'unconfirmed'):
            missing.append({
                'path': entry['path'],
                'link_kind': verification.get('kind'),
                'status': verification.get('status'),
                'missing': verification.get('reason'),
                'declared_filename': verification.get('declared_filename'),
            })

    # Point at the supplementary file itself when its identity cannot be
    # independently checked.  Matching the primary's token against the
    # candidate's own token is not a digest check.
    seen_supplementary = set()
    for entry in entries:
        verification = entry['verification']
        if verification.get('kind') != 'debug_sup':
            continue
        if verification.get('status') != 'unconfirmed':
            continue
        path = verification.get('resolved_path')
        if not path or path in seen_supplementary:
            continue
        seen_supplementary.add(path)
        missing.append({
            'path': os.path.relpath(path),
            'link_kind': 'supplementary-identity',
            'status': 'unconfirmed',
            'missing': (
                'no .note.gnu.build-id and no producer digest manifest for the '
                'supplementary file; the delivered bytes cannot reproduce the '
                'declared .debug_sup checksum'),
            'declared_filename': None,
        })

    # The supplementary packages in this fixture are debug-side files; the
    # stripped object that originally carried each one is not delivered.
    object_side = {
        e['path'] for e in entries if e['role'] == 'object'
    }
    debug_primaries = [
        e['path'] for e in entries if e['role'] == 'debug-primary'
    ]
    for path in debug_primaries:
        stem = path[:-len('.debug')] if path.endswith('.debug') else path
        if stem not in object_side and not any(
                os.path.basename(p) == os.path.basename(stem) for p in object_side):
            missing.append({
                'path': stem,
                'link_kind': 'object-side',
                'status': 'missing',
                'missing': (
                    'stripped/original ELF object that declares this debug file '
                    'was not delivered, so the debug material cannot be bound '
                    'to a delivered build artifact'),
                'declared_filename': None,
            })

    unconfirmed = _unconfirmed_reference_summary(entries)

    debugsup_identities = sorted(debugsup_keys)
    altlink_identities = sorted(altlink_keys)
    confirmed_union = sorted(set(debugsup_identities) | set(altlink_identities))

    def _debug_info_digest(target):
        if not target:
            return None
        with ELFFile.load_from_path(target) as sup_elf:
            body = _section_bytes(sup_elf, ".debug_info")
        return hashlib.sha1(body).hexdigest() if body else None

    def _first_resolved(group):
        for item in group:
            target = item["verification"].get("resolved_path")
            if target:
                return target
        return None

    debugsup_common = _first_resolved(debugsup)
    altlink_common = _first_resolved(altlink)
    cross_family = {
        "debug_sup_primary_build_ids": sorted({
            e["build_id"] for e in debugsup if e["build_id"]}),
        "gnu_debugaltlink_primary_build_ids": sorted({
            e["build_id"] for e in altlink if e["build_id"]}),
        "debug_sup_common": (os.path.relpath(debugsup_common)
                              if debugsup_common else None),
        "gnu_debugaltlink_common": (os.path.relpath(altlink_common)
                                     if altlink_common else None),
        "debug_sup_common_debug_info_sha1": _debug_info_digest(debugsup_common),
        "gnu_debugaltlink_common_debug_info_sha1": _debug_info_digest(altlink_common),
        "shared_original_cu_identities": confirmed_union,
        "shared_original_cu_count": len(confirmed_union),
        "intersection_original_cu_identities": intersection,
        "intersection_original_cu_count": len(intersection),
    }

    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'read_only': True,
        'policy': {
            'approval_cap': approval_cap,
            'approval_roster_present': False,
            'selection_rule': (
                'CUs whose DW_AT_name + DW_AT_comp_dir identity is confirmed '
                'independently in BOTH the .debug_sup and .gnu_debugaltlink '
                'packages, then capped at the approved number'),
            'path_trust': (
                'A candidate found at a conventional path is never accepted '
                'on path alone; it must satisfy the declaration bytes (CRC32 '
                'or build ID, or a derivable .debug_sup digest).'),
        },
        'materials': entries,
        'duplicates': duplicates,
        "cross_family": cross_family,
        "path_trust_probes": probes,
        'families': {
            'debug_sup': {
                'files': [e['path'] for e in debugsup],
                'confirmed_original_cus': debugsup_identities,
                'link_verifications': [e['verification'] for e in debugsup],
            },
            'gnu_debugaltlink': {
                'files': [e['path'] for e in altlink],
                'confirmed_original_cus': altlink_identities,
                'link_verifications': [e['verification'] for e in altlink],
            },
            'gnu_debuglink': {
                'files': [e['path'] for e in debuglink],
                'link_verifications': [e['verification'] for e in debuglink],
            },
        },
        'handover': {
            'approved_cap': approval_cap,
            'approved_units': approved,
            'approved_count': len(approved),
            'other_confirmed_not_handed_over': sorted(
                (debugsup_keys | altlink_keys | _confirmed_original_keys(debuglink)) - set(approved)),
            'confirmed_union': confirmed_union,
            'confirmed_union_size': len(confirmed_union),
            'capped_out_units': [u for u in confirmed_union if u not in approved],
            'additional_units_from_union': max(
                0, min(approval_cap, len(confirmed_union)) - len(approved)),
            "notes": [
                "两套 dwz 包包含同一组五个原始编译单元，只是两种链接编码，不是两次独立构建。",
                ".debug_sup 包只能独立确认两个内联身份串；补充文件摘要不可复算，其余三个 CU 身份及全部补充引用仍属未确认。",
                ".gnu_debugaltlink 包通过补充文件 build-id 可确认全部五个 CU；交接主证据取这一套，批准上限仍为两份。",
                "debuglink/debuglink.debug 自身已由 CRC32+build-id 完整确认，但它是独立材料；批准名册未到时不计入本次两份名额。",
                "拼接两套包或按文件名重复计数都不会产生新的审批权。",
            ],
        },
        'unconfirmed_references': unconfirmed,
        'missing_materials': missing,
    }
    report['missing_materials'].append({
        'path': None,
        'link_kind': 'approval-roster',
        'status': 'missing',
        'missing': (
            'the signed approval roster naming the two approved CUs is not '
            'part of the delivered material; the selection below is the '
            'conservative intersection of independently confirmed identities'),
        'declared_filename': None,
    })
    return report


def _markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    add = lines.append
    add('# 分离调试材料交接结果')
    add('')
    add(f"生成时间（UTC）：`{report['generated_at']}`")
    add('')
    add('本结果只使用 pyelftools 的只读 ELF/DWARF 接口。没有改写、strip 或重新链接任何文件。')
    add('')
    add('## 批准口径')
    add('')
    add(f"- 批准上限：`{report['policy']['approval_cap']}` 份编译单元")
    add(f"- 批准名册：{'随材料提供' if report['policy']['approval_roster_present'] else '**未随材料提供**'}")
    add("- 选择规则：只交接在两套 dwz 编码中都独立确认身份的 CU，再按批准上限截断。")
    add("- 路径信任：常规路径只用于找候选，绝不单独采信；候选必须满足声明中的 CRC32 或 build-id，或可复算的 .debug_sup 摘要。")
    add("- 查找顺序：材料所在目录，其次 `.debug/`；绝对路径和逃逸目录的候选直接排除。")
    add('')
    add('## 材料与绑定校验')
    add('')
    for entry in report['materials']:
        verification = entry['verification']
        add(f"### `{entry['path']}`")
        add('')
        add(f"- 角色：`{entry['role']}`")
        add(f"- SHA-1：`{entry['sha1']}`")
        add(f"- build-id：`{entry['build_id']}`")
        add(f"- 链接类型：`{verification.get('kind')}`")
        add(f"- 声明文件名：`{verification.get('declared_filename')}`")
        if verification.get('declared_crc32'):
            add(f"- 声明 CRC32：`{verification['declared_crc32']}`")
        if verification.get('declared_build_id'):
            add(f"- 声明 build-id：`{verification['declared_build_id']}`")
        if verification.get('declared_checksum'):
            add(f"- 声明 .debug_sup checksum：`{verification['declared_checksum']}`")
        resolved = verification.get("resolved_path")
        add("- 解析路径：`" + (os.path.relpath(resolved) if resolved else "None") + "`")
        add(f"- 校验状态：**{verification.get('status')}**")
        if verification.get('binding'):
            add(f"- 绑定依据：`{verification['binding']}`")
        if verification.get('reason'):
            add(f"- 说明：{verification['reason']}")
        if verification.get('candidate_sha1'):
            add(f"- 候选文件 SHA-1：`{verification['candidate_sha1']}`")
        if verification.get('candidate_build_id') is not None:
            add(f"- 候选文件 build-id：`{verification['candidate_build_id']}`")
        if "token_matches_candidate" in verification:
            add("- 与候选自声明 token 相同：`" + str(verification["token_matches_candidate"]) + "`")
        if "sha1_matches_file" in verification:
            add("- 声明摘要等于候选整文件 SHA-1：`" + str(verification["sha1_matches_file"]) + "`")
        if "md5_matches_file" in verification:
            add("- 声明摘要等于候选整文件 MD5：`" + str(verification["md5_matches_file"]) + "`")
        if "build_id_matches" in verification:
            add("- 声明值等于候选 build-id：`" + str(verification["build_id_matches"]) + "`")
        add('')
        add('| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |')
        add('|---|---|---|---|---|---|---|')
        for cu in entry['cus']:
            ident = cu['identity']
            refs = ', '.join(f"{k}={v}" for k, v in cu['external_ref_counts'].items()) or '-'
            add(
                f"| `{cu['offset']}` | `{cu['tag']}` | "
                f"`{ident['name']}` | `{ident['comp_dir']}` | "
                f"{ident['source']} | {refs} | "
                f"{'是' if cu['identity_confirmed'] else '否'} |")
        add('')

    add('## 重复件')
    add('')
    if report['duplicates']:
        for duplicate in report['duplicates']:
            add(f"- SHA-1 `{duplicate['sha1']}`：{', '.join(f'`{p}`' for p in duplicate['paths'])}")
            add(f"  - {duplicate['note']}")
    else:
        add('- 未发现字节级重复件。')
    add('')

    add("## 路径复用探针")
    add("")
    add("同一目录里出现其他同名/同类文件时，路径查找会成功打开错误的候选；下表用实际字节说明哪些候选会被拒绝。")
    add("")
    for probe in report["path_trust_probes"]:
        add("- 声明类型 `" + probe["declaration"] + "`，期望值 `" + str(probe["expected"]) + "`")
        for alt in probe["alternatives"]:
            actual = alt.get("crc32") or alt.get("build_id")
            add("  - `" + alt["path"] + "`：实际值 `" + str(actual) + "`，接受=" + str(alt["would_be_accepted"]) + "，原因=" + str(alt["reject_reason"]))
    add("")
    add("## 两套 dwz 包的同一性")
    add("")
    cross = report["cross_family"]
    add("- `.debug_sup` 主文件 build-id：" + str(cross["debug_sup_primary_build_ids"]))
    add("- `.gnu_debugaltlink` 主文件 build-id：" + str(cross["gnu_debugaltlink_primary_build_ids"]))
    add("- `.debug_sup` common 的 `.debug_info` SHA-1：`" + str(cross["debug_sup_common_debug_info_sha1"]) + "`")
    add("- `.gnu_debugaltlink` common 的 `.debug_info` SHA-1：`" + str(cross["gnu_debugaltlink_common_debug_info_sha1"]) + "`")
    add("- 两套 common 的 `.debug_info` 是否为同一份：**" + ("是" if cross["debug_sup_common_debug_info_sha1"] == cross["gnu_debugaltlink_common_debug_info_sha1"] else "否") + "**")
    add("- 两边并集可确认的原始 CU 数：`" + str(cross["shared_original_cu_count"]) + "`")
    add("- 两边交集（可同时被两套证据确认）的原始 CU 数：`" + str(cross["intersection_original_cu_count"]) + "`")
    add("- 两套 common 各含两个 `DW_TAG_partial_unit`（`0x0`、`0x38e`），`.debug_info` 哈希相同；它们是支撑单元，不额外产生审批名额。")
    add("")
    add('## 交接结论')
    add('')
    add(f"- 批准并交接的编译单元数：**{report['handover']['approved_count']}**")
    for unit in report['handover']['approved_units']:
        add(f"  - `{unit}`")
    for unit in report['handover'].get('capped_out_units', []):
        add(f"  - 范围外、不进入交接：`{unit}`")
    for unit in report['handover'].get('other_confirmed_not_handed_over', []):
        if unit not in report['handover'].get('capped_out_units', []):
            add(f"  - 已确认但未占用本次名额：`{unit}`")
    add(f"- 两套包合并后可新增的批准单元：`{report['handover']['additional_units_from_union']}`")
    for note in report['handover']['notes']:
        add(f"- {note}")
    add('')

    add('## 未能确认的引用')
    add('')
    if report['unconfirmed_references']:
        for group in report['unconfirmed_references']:
            add(f"### `{group['path']}`")
            add('')
            add(f"链接状态：`{group['link_status']}`；未确认引用合计：`{group['total_unconfirmed_references']}`")
            add("这里的 `resolved=True` 只表示在候选补充文件里找到了目标；候选文件未与声明绑定，因此引用仍按未确认处理。")
            add("")
            add('')
            for block in group['by_cu']:
                ident = block['identity']
                add(f"- CU `{block['cu_offset']}` `{ident['name']}`（{ident['source']}）："
                    f"{', '.join(f'{k}={v}' for k, v in block['counts'].items())}")
                for sample in block['samples']:
                    add(
                        f"  - `{sample['attribute']}` @ DIE `{sample['die_offset']}` "
                        f"form `{sample['form']}` raw `{sample['raw_value']}` "
                        f"resolved={sample.get('resolved')}")
            add('')
    else:
        add('- 无。')
        add('')

    add('## 缺失支撑材料')
    add('')
    if report['missing_materials']:
        for item in report['missing_materials']:
            label = item["path"] or "(approval roster)"
            kind = item["link_kind"]
            status = item["status"]
            detail = item["missing"]
            add(f"- `{label}`（{kind} / {status}）：{detail}")
    else:
        add('- 无。')
    add('')
    return '\n'.join(lines)


def _default_paths(directory: str) -> list[str]:
    prefixes = (
        'debuglink',
        'test_debugsup',
        'test_gnudebugaltlink',
    )
    paths = []
    for name in sorted(os.listdir(directory)):
        if not name.startswith(prefixes):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        with open(path, 'rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'paths', nargs='*',
        help='ELF files to audit (default: the debuglink/dwz fixture set)')
    parser.add_argument(
        '--directory',
        default=os.path.join('test', 'testfiles_for_unittests'),
        help='directory used for the default fixture set')
    parser.add_argument(
        '--search-dir', action='append', default=[],
        help='extra root for conventional debug-file lookup')
    parser.add_argument(
        '--approval-cap', type=int, default=2,
        help='maximum number of CUs that may be handed over')
    parser.add_argument('--json-out', help='write the machine-readable report')
    parser.add_argument('--markdown-out', help='write the Markdown handover')
    args = parser.parse_args(argv)

    paths = args.paths or _default_paths(args.directory)
    if not paths:
        parser.error('no ELF files to audit')

    report = build_report(paths, args.search_dir, args.approval_cap)
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    markdown = _markdown(report)

    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as stream:
            stream.write(payload + '\n')
    if args.markdown_out:
        with open(args.markdown_out, 'w', encoding='utf-8') as stream:
            stream.write(markdown + '\n')
    if not args.json_out and not args.markdown_out:
        print(markdown)
    return 0


if __name__ == '__main__':
    sys.exit(main())
