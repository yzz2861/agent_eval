#!/bin/python

#    This file is part of python-registry.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Offline, read-only mount view for a collection of evidence registry hives.

This module never touches a host operating system registry. Every node that
is returned carries an explicit evidence identity (which registered hive it
came from), the original key path inside that hive, and the raw file offset of
the underlying NK/VK record, so every result can be traced back to byte
locations in the source files.

Two access modes are deliberately distinct:

  - direct reads  (``follow_links=False``) never leave the current hive and
                    never cross an evidence/case boundary; a registry link
                    value is reported as a link, not silently dereferenced;
  - link following (``follow_links=True``) resolves ``RegLink`` values one
                    hop at a time, and records every hop. Cycles, link targets
                    whose mount is not registered, and same-name shadowing are
                    returned as structured statuses rather than exceptions or
                    silently corrected results.
"""
from __future__ import print_function

from enum import Enum

from . import Registry
from . import RegistryParse


class ResolutionStatus(Enum):
    """
    Structured terminal status of a resolution attempt.
    """
    OK = "ok"
    NOT_FOUND = "not_found"
    UNMOUNTED_TARGET = "unmounted_target"
    LINK_CYCLE = "link_cycle"
    MALFORMED_LINK = "malformed_link"
    NAME_SHADOWED = "name_shadowed"


class MountConflictError(Exception):
    """
    Raised when a mount registration would overwrite an existing evidence
    identity or occupy a mount point that is already in use. The view never
    silently replaces one case boundary with another.
    """
    pass


def _normalize_segments(path):
    """
    Split a virtual view path into normalized, backslash independent segments.
    """
    if path is None:
        return []
    return [segment for segment in path.replace("/", "\\").split("\\")
                if segment != ""]


def _is_prefix(prefix, segments):
    return len(prefix) <= len(segments) and prefix == segments[:len(prefix)]


class Location(object):
    """
    A physical location of one registry record inside a specific evidence hive.

    Attributes:
      evidence_id:  caller supplied identity of the evidence hive.
      source_path:  original key path inside the hive, without view mount point.
      record_offset: absolute byte offset of the NK record in the hive file.
      mount_point:  virtual mount point segments where this hive is mounted.
    """
    def __init__(self, evidence_id, source_path, record_offset, mount_point):
        self.evidence_id = evidence_id
        self.source_path = source_path
        self.record_offset = record_offset
        self.mount_point = list(mount_point)

    def view_path(self):
        return "\\".join(self.mount_point + _normalize_segments(self.source_path))

    def identity(self):
        """
        Stable identity used for cycle detection across mounted hives.
        """
        return (self.evidence_id, self.record_offset)

    def as_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "record_offset": self.record_offset,
            "mount_point": "\\".join(self.mount_point),
            "view_path": self.view_path(),
        }

    def __repr__(self):
        return ("Location(evidence_id=%r, source_path=%r, offset=0x%x)" %
                (self.evidence_id, self.source_path, self.record_offset))


class Hop(object):
    """
    One hop of link resolution. The first hop describes the physical location
    at which the link was read; subsequent hops describe where the link led.
    """
    def __init__(self, source, link_value_name, target_view_path, target=None):
        self.source = source
        self.link_value_name = link_value_name
        self.target_view_path = target_view_path
        self.target = target

    def as_dict(self):
        result = {
            "source": self.source.as_dict(),
            "link_value_name": self.link_value_name,
            "target_view_path": self.target_view_path,
        }
        if self.target is not None:
            result["target"] = self.target.as_dict()
        return result


class ResolutionResult(object):
    """
    Structured outcome of a view query.

    A resolution always yields an object of this type. Error conditions are
    reported through ``status`` instead of being raised, so callers can record
    the forensic outcome. ``key`` is only populated when ``status`` is
    ``ResolutionStatus.OK`` or ``ResolutionStatus.NAME_SHADOWED``.
    """
    def __init__(self, status, key=None, hops=None, message="",
                 shadowed=None, value=None):
        self.status = status
        self.key = key
        self.hops = hops or []
        self.message = message
        self.shadowed = shadowed
        self.value = value

    @property
    def ok(self):
        return self.status in (ResolutionStatus.OK,
                               ResolutionStatus.NAME_SHADOWED)

    def raise_for_status(self):
        if self.status == ResolutionStatus.NOT_FOUND:
            raise Registry.RegistryKeyNotFoundException(self.message)
        if not self.ok:
            raise RegistryParse.ParseException(
                "%s: %s" % (self.status.value, self.message))
        return self.key

    def as_dict(self):
        return {
            "status": self.status.value,
            "message": self.message,
            "hops": [hop.as_dict() for hop in self.hops],
            "terminal": self.key.location().as_dict() if self.key else None,
            "shadowed": [item.as_dict() for item in self.shadowed]
                        if self.shadowed else [],
        }


class MountedValue(object):
    """
    A value read through the mount view. It retains the evidence identity and
    record offset of the key that owns it.
    """
    def __init__(self, mount, key_location, registry_value):
        self._mount = mount
        self._key_location = key_location
        self._value = registry_value

    def name(self):
        return self._value.name()

    def value_type(self):
        return self._value.value_type()

    def value_type_str(self):
        return self._value.value_type_str()

    def is_link(self):
        return self._value.value_type() == Registry.RegLink

    def value(self):
        return self._value.value()

    def raw_data(self):
        return self._value.raw_data()

    def link_target(self):
        """
        Decode a ``RegLink`` value into its declared target path string.
        Returns None for non-link values.
        Raises RegistryStructureDoesNotExist for malformed link data.
        """
        if not self.is_link():
            return None
        raw = self._value.raw_data()
        try:
            target = raw.decode("utf-16le").partition("\x00")[0]
        except UnicodeDecodeError:
            raise RegistryParse.RegistryStructureDoesNotExist(
                "Malformed RegLink value at %s" %
                (self._key_location.view_path(),))
        if target == "":
            raise RegistryParse.RegistryStructureDoesNotExist(
                "Empty RegLink value at %s" % (self._key_location.view_path(),))
        return target

    def owner_location(self):
        return self._key_location

    def value_record_offset(self):
        """
        Offset of the VK record itself, and the owning NK offset.
        """
        return {
            "vk_offset": self._value._vkrecord.offset(),
            "nk_offset": self._key_location.record_offset,
            "evidence_id": self._mount.evidence_id,
        }

    def __repr__(self):
        return ("MountedValue(evidence_id=%r, name=%r, type=%s)" %
                (self._mount.evidence_id, self.name(), self.value_type_str()))


class MountedKey(object):
    """
    A key resolved inside a specific evidence hive, with full provenance.
    """
    def __init__(self, mount, location, registry_key):
        self._mount = mount
        self._location = location
        self._key = registry_key

    def location(self):
        return self._location

    def registry_key(self):
        """
        The underlying python-registry RegistryKey, for callers that need the
        original, unchanged Registry API.
        """
        return self._key

    def name(self):
        return self._key.name()

    def timestamp(self):
        return self._key.timestamp()

    def view_path(self):
        return self._location.view_path()

    def subkeys(self):
        """
        Direct subkeys only. Links are never followed by this method and no
        mount boundary is crossed: the returned keys all belong to the same
        evidence hive as this key.
        """
        result = []
        for child in self._key.subkeys():
            child_path = self._location.source_path
            if child_path:
                child_path += "\\" + child.name()
            else:
                child_path = child.name()
            location = Location(self._mount.evidence_id, child_path,
                                child._nkrecord.offset(),
                                self._location.mount_point)
            result.append(MountedKey(self._mount, location, child))
        return result

    def values(self):
        return [MountedValue(self._mount, self._location, value)
                for value in self._key.values()]

    def value(self, name):
        return MountedValue(self._mount, self._location,
                            self._key.value(name))

    def links(self):
        """
        All RegLink values attached to this key, reported as links rather
        than dereferenced.
        """
        return [value for value in self.values() if value.is_link()]

    def is_link_key(self):
        return len(self.links()) > 0


class EvidenceHive(object):
    """
    One explicitly registered piece of evidence: a hive file plus its
    evidence identity and virtual mount point.
    """
    def __init__(self, evidence_id, mount_point, source, aliases=None):
        self.evidence_id = evidence_id
        self.mount_point = _normalize_segments(mount_point)
        if not self.mount_point:
            raise MountConflictError(
                "Mount point for evidence %r must not be empty" % evidence_id)
        self.registry = source if isinstance(source, Registry.Registry) \
            else Registry.Registry(source)
        # Aliases map a legacy/host-style target prefix (e.g. the standard
        # Windows "\REGISTRY\MACHINE\SOFTWARE") to a virtual view path. They
        # are fixed at registration time, so target interpretation can never
        # depend on, or fall back to, the host machine.
        self.aliases = {}
        for alias, target in (aliases or {}).items():
            self.aliases[tuple(_normalize_segments(alias))] = \
                _normalize_segments(target)

    def root_key(self):
        return self.registry.root()


class MountView(object):
    """
    An offline, explicitly mounted, read-only view over evidence hives.
    """
    def __init__(self):
        self._mounts = []          # list[EvidenceHive]
        self._by_id = {}           # evidence_id -> EvidenceHive

    # ------------------------------------------------------------------ mount
    def mount(self, evidence_id, mount_point, source, aliases=None):
        """
        Register a hive under an evidence identity and virtual mount point.

        Duplicate evidence ids, duplicate mount points, and mount points that
        nest inside an existing mount are rejected. Nothing is ever replaced
        implicitly.
        """
        hive = EvidenceHive(evidence_id, mount_point, source, aliases)
        point = hive.mount_point

        if evidence_id in self._by_id:
            raise MountConflictError(
                "Evidence id %r is already mounted at %r" %
                (evidence_id, "\\".join(self._by_id[evidence_id].mount_point)))

        for existing in self._mounts:
            existing_point = existing.mount_point
            if existing_point == point:
                raise MountConflictError(
                    "Mount point %r is already registered to evidence %r" %
                    ("\\".join(point), existing.evidence_id))
            if _is_prefix(existing_point, point) or \
               _is_prefix(point, existing_point):
                raise MountConflictError(
                    "Mount point %r overlaps existing mount %r (evidence %r)" %
                    ("\\".join(point), "\\".join(existing_point),
                     existing.evidence_id))

        self._mounts.append(hive)
        self._by_id[evidence_id] = hive
        return hive

    def mounts(self):
        return list(self._mounts)

    def mount_for(self, evidence_id):
        return self._by_id.get(evidence_id)

    # ------------------------------------------------------------- name checks
    def name_conflicts(self):
        """
        Report same-name shadowing across evidence boundaries.

        Two hives whose root keys share a display name are kept separate by
        evidence id and mount point, but the shared name is recorded here so
        a result can never be attributed to the wrong piece of material just
        because the names look identical.
        """
        seen = {}
        conflicts = []
        for hive in self._mounts:
            root_name = hive.root_key().name().lower()
            entry = {
                "evidence_id": hive.evidence_id,
                "mount_point": "\\".join(hive.mount_point),
                "root_name": hive.root_key().name(),
            }
            if root_name in seen:
                conflicts.append((dict(seen[root_name]), dict(entry)))
            else:
                seen[root_name] = entry
        return conflicts

    # --------------------------------------------------------------- locating
    def _mount_for_view_path(self, segments):
        best = None
        for hive in self._mounts:
            if _is_prefix(hive.mount_point, segments):
                if best is None or len(hive.mount_point) > len(best.mount_point):
                    best = hive
        return best

    def _apply_aliases(self, segments):
        for hive in self._mounts:
            for alias_prefix, replacement in hive.aliases.items():
                if _is_prefix(list(alias_prefix), segments):
                    return replacement + segments[len(alias_prefix):]
        return segments

    def _open_physical(self, hive, source_segments):
        """
        Open a key inside one hive without crossing any boundary. Returns a
        RegistryKey or raises RegistryKeyNotFoundException.
        """
        root = hive.root_key()
        current = root
        traversed = []
        for segment in source_segments:
            current = current.subkey(segment)
            traversed.append(segment)
        source_path = "\\".join(traversed)
        location = Location(hive.evidence_id, source_path,
                            current._nkrecord.offset(), hive.mount_point)
        return MountedKey(hive, location, current)

    # ---------------------------------------------------------------- queries
    def get(self, view_path, follow_links=False):
        """
        Resolve a virtual view path.

        With follow_links=False the lookup is strictly direct: only the hive
        that owns the matching mount point is consulted, and link values are
        left untouched.

        With follow_links=True, RegLink values are resolved hop by hop. Each
        hop, including its source hive/source path/offset and declared target,
        is preserved. Cycles, unmounted targets and malformed links produce a
        structured non-OK status.
        """
        segments = _normalize_segments(view_path)
        hive = self._mount_for_view_path(segments)
        if hive is None:
            return ResolutionResult(
                ResolutionStatus.NOT_FOUND,
                message="No mounted hive covers path %r" % view_path)

        source_segments = segments[len(hive.mount_point):]
        try:
            mounted = self._open_physical(hive, source_segments)
        except Registry.RegistryKeyNotFoundException:
            if not follow_links:
                return ResolutionResult(
                    ResolutionStatus.NOT_FOUND,
                    message="Key %r not found inside evidence %r" %
                            (view_path, hive.evidence_id))
            return self._resolve_with_links(view_path, segments)

        if not follow_links:
            return ResolutionResult(ResolutionStatus.OK, key=mounted)
        return self._resolve_with_links(view_path, segments)

    def open(self, view_path, follow_links=False):
        """
        Convenience wrapper that returns the MountedKey or raises. Prefer
        get() when the structured status (cycle/unmounted/shadowed) matters.
        """
        result = self.get(view_path, follow_links=follow_links)
        return result.raise_for_status()

    def get_value(self, view_path, value_name, follow_links=False):
        """
        Resolve a key (direct or via links) and read one of its values.
        Link values themselves are returned as MountedValue; they are never
        auto-dereferenced by a plain value read.
        """
        result = self.get(view_path, follow_links=follow_links)
        if not result.ok:
            return result
        try:
            value = result.key.value(value_name)
        except Registry.RegistryValueNotFoundException:
            return ResolutionResult(
                ResolutionStatus.NOT_FOUND,
                message="Value %r not found at %r" % (value_name, view_path))
        return ResolutionResult(ResolutionStatus.OK, key=result.key,
                                hops=result.hops, value=value)

    # ------------------------------------------------------------ link logic
    def _resolve_with_links(self, original_path, segments):
        hops = []
        visited = set()
        self._pending_hop = None
        current_segments = list(segments)
        shadowed = []

        while True:
            current_segments = self._apply_aliases(current_segments)
            hive = self._mount_for_view_path(current_segments)
            if hive is None:
                return ResolutionResult(
                    ResolutionStatus.UNMOUNTED_TARGET,
                    hops=hops,
                    message="Link target %r is not covered by any mounted "
                            "hive; host registry is not used" %
                            ("\\".join(current_segments),))

            source_segments = current_segments[len(hive.mount_point):]
            try:
                mounted = self._open_physical(hive, source_segments)
            except Registry.RegistryKeyNotFoundException:
                return ResolutionResult(
                    ResolutionStatus.NOT_FOUND,
                    hops=hops,
                    message="Link target %r does not exist in evidence %r" %
                            ("\\".join(current_segments), hive.evidence_id))

            if getattr(self, "_pending_hop", None) is not None:
                self._pending_hop.target = mounted.location()
                self._pending_hop = None
            identity = mounted.location().identity()
            if identity in visited:
                return ResolutionResult(
                    ResolutionStatus.LINK_CYCLE,
                    hops=hops,
                    message="Link cycle detected at %r (evidence %r, "
                            "offset 0x%x)" %
                            (mounted.view_path(), hive.evidence_id,
                             mounted.location().record_offset))
            visited.add(identity)

            link_values = mounted.links()
            if not link_values:
                status = ResolutionStatus.OK
                link_leaf = hops[0].source.view_path().rpartition(chr(92))[2] if hops else ""
                link_owner = hops[0].source.evidence_id if hops else None
                if self._is_shadowed(mounted, link_leaf, link_owner):
                    status = ResolutionStatus.NAME_SHADOWED
                    shadowed = self._shadow_locations(mounted, link_owner)
                return ResolutionResult(
                    status, key=mounted, hops=hops,
                    shadowed=shadowed or None,
                    message="Same-name key exists in another evidence hive"
                            if shadowed else "")

            # A symbolic-link key carries one RegLink value naming its target.
            link = link_values[0]
            try:
                target_text = link.link_target()
            except RegistryParse.RegistryStructureDoesNotExist as exc:
                return ResolutionResult(
                    ResolutionStatus.MALFORMED_LINK,
                    hops=hops, message=str(exc))

            target_segments = self._target_segments(mounted, target_text)
            hop = Hop(mounted.location(), link.name(),
                      "\\".join(target_segments))
            hops.append(hop)
            current_segments = target_segments
            # Record the physical target of this hop on the next loop
            # iteration once the target hive/key is resolved.
            self._pending_hop = hop

    def _target_segments(self, mounted_key, target_text):
        target_segments = self._apply_aliases(_normalize_segments(target_text))
        if target_text.startswith("\\"):
            return target_segments
        # Relative targets resolve against the parent of the link key, inside
        # the same mount; they never escape the evidence boundary implicitly.
        parent = mounted_key.location().mount_point + \
            _normalize_segments(mounted_key.location().source_path)[:-1]
        return parent + target_segments

    def _is_shadowed(self, mounted, link_leaf, link_owner_id):
        """
        A link is a same-name impostor when the link key shares its leaf
        name with an ordinary (non-link) key in an evidence hive other than
        the one that owns the link. Same-name entries inside one hive are an
        ordinary duplicate and are not treated as shadows.
        """
        if not link_leaf:
            return False
        leaf = link_leaf.lower()
        # A shadow only exists when the link name is also used by an
        # ordinary key in the link-owning hive, so an analyst could mistake
        # the link for local material. A unique link name that merely points
        # into another mount is a legal cross-mount reference, not a shadow.
        owner = self._by_id.get(link_owner_id)
        if owner is None:
            return False
        local_ordinary = False
        for key in self._walk_keys(owner.registry.root()):
            if key.name().lower() == leaf and \
               not MountedKey(owner, None, key).is_link_key():
                local_ordinary = True
                break
        if not local_ordinary:
            return False
        for hive in self._mounts:
            if hive.evidence_id == link_owner_id:
                continue
            for key in self._walk_keys(hive.registry.root()):
                if key.name().lower() != leaf:
                    continue
                if not MountedKey(hive, None, key).is_link_key():
                    return True
        return False

    def _shadow_locations(self, mounted, link_owner_id):
        result = []
        leaf = mounted.name().lower()
        for hive in self._mounts:
            if hive.evidence_id == link_owner_id:
                continue
            for key in self._walk_keys(hive.registry.root()):
                if key.name().lower() != leaf:
                    continue
                wrapped = MountedKey(hive, None, key)
                if wrapped.is_link_key():
                    continue
                result.append(Location(
                    hive.evidence_id, key.path().lstrip("\\"),
                    key._nkrecord.offset(), hive.mount_point))
        return result

    @staticmethod
    def _walk_keys(registry_key):
        yield registry_key
        for child in registry_key.subkeys():
            for grandchild in MountView._walk_keys(child):
                yield grandchild

    def detect_shadows(self):
        """
        Enumerate every link value in every mounted hive and report links
        whose key name is reused for a physical key in another evidence hive.
        Each entry pairs the link location with the impostor candidates so a
        reviewer can decide which evidence identity actually owns the name.
        Nothing is remounted or hidden by this check.
        """
        shadows = []
        for hive in self._mounts:
            for key, source_path in self._walk_key_paths(hive.registry.root()):
                location = Location(hive.evidence_id, source_path,
                                    key._nkrecord.offset(), hive.mount_point)
                mounted = MountedKey(hive, location, key)
                for link_value in mounted.links():
                    target_text = link_value.link_target()
                    target_segments = self._target_segments(mounted, target_text)
                    target_mount = self._mount_for_view_path(target_segments)
                    if target_mount is None:
                        continue
                    target_hive = target_mount
                    if target_hive.evidence_id == hive.evidence_id:
                        continue
                    source_segments = target_segments[len(target_hive.mount_point):]
                    try:
                        physical = self._open_physical(
                            target_hive, source_segments)
                    except Registry.RegistryKeyNotFoundException:
                        continue
                    target_key = physical
                    if target_key.name().lower() != mounted.name().lower():
                        continue
                    shadows.append({
                        "link": mounted.location(),
                        "link_value": link_value.name(),
                        "target": target_key.location(),
                    })
        return shadows

    @staticmethod
    def _walk_key_paths(registry_key, prefix=""):
        path = registry_key.name() if not prefix else \
            prefix + "\\" + registry_key.name()
        yield registry_key, path
        for child in registry_key.subkeys():
            for item in MountView._walk_key_paths(child, path):
                yield item
