"""Filesystem cache for parsed SAML metadata entities.

Cache file names are derived exclusively from a hash of the *normalized*
entityID. Raw entityIDs are never concatenated into paths, which avoids
both path traversal and collisions between casing/port/trailing-slash
variants of the same identifier.
"""

import hashlib
import json
import logging
import os
import tempfile

from saml2.entityid import ENTITY_CACHE_VERSION
from saml2.entityid import MissingEntityID
from saml2.entityid import entity_id_cache_key
from saml2.entityid import normalize_entity_id


logger = logging.getLogger(__name__)

_CACHE_SUFFIX = ".json"


class MetadataCacheError(Exception):
    pass


class FileMetadataCache:
    """Store parsed entity dictionaries in a flat, hash-named directory."""

    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self._invalidate_legacy_entries()

    def _cache_path(self, entity_id):
        key = entity_id_cache_key(entity_id)
        return os.path.join(self.cache_dir, key + _CACHE_SUFFIX)

    def _invalidate_legacy_entries(self):
        """Remove entries not produced by the current cache layout.

        Older pysaml2 versions keyed cache files from raw URL strings or
        prefix lookups. Those files can never satisfy a normalized hash
        lookup, so they are deleted explicitly instead of being left behind
        as untrusted stale data.
        """
        try:
            names = os.listdir(self.cache_dir)
        except FileNotFoundError:
            return

        valid_prefix = ENTITY_CACHE_VERSION + "-"
        for name in names:
            if name.endswith(_CACHE_SUFFIX) and not name.startswith(valid_prefix):
                legacy_path = os.path.join(self.cache_dir, name)
                try:
                    os.remove(legacy_path)
                except OSError:
                    logger.warning("Could not invalidate legacy metadata cache entry %s", legacy_path)

    def get(self, entity_id):
        path = self._cache_path(entity_id)
        try:
            with open(path, "r", encoding="utf-8") as fp:
                payload = json.load(fp)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise MetadataCacheError(f"Unreadable metadata cache entry for {entity_id}") from exc

        stored_key = payload.get("cache_key")
        if stored_key != entity_id_cache_key(entity_id):
            # Refuse entries whose name and content disagree: this both
            # defeats prefix-confusion attacks and migrates corrupted files.
            try:
                os.remove(path)
            except OSError:
                pass
            return None
        return payload.get("entity")

    def set(self, entity_id, entity):
        normalized = normalize_entity_id(entity_id)
        cache_key = entity_id_cache_key(normalized)
        payload = {
            "cache_version": ENTITY_CACHE_VERSION,
            "cache_key": cache_key,
            "entity_id": normalized,
            "entity": entity,
        }
        target = os.path.join(self.cache_dir, cache_key + _CACHE_SUFFIX)
        fd, temporary = tempfile.mkstemp(prefix=".metadata-", dir=self.cache_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp)
            os.replace(temporary, target)
        except OSError as exc:
            try:
                os.remove(temporary)
            except OSError:
                pass
            raise MetadataCacheError(f"Could not cache metadata for {entity_id}") from exc

    def delete(self, entity_id):
        try:
            os.remove(self._cache_path(entity_id))
        except FileNotFoundError:
            return False
        return True

    def clear(self):
        for name in os.listdir(self.cache_dir):
            if name.startswith(ENTITY_CACHE_VERSION + "-") and name.endswith(_CACHE_SUFFIX):
                os.remove(os.path.join(self.cache_dir, name))

    def __contains__(self, entity_id):
        return os.path.isfile(self._cache_path(entity_id))

    def __len__(self):
        return len(
            [
                name
                for name in os.listdir(self.cache_dir)
                if name.startswith(ENTITY_CACHE_VERSION + "-") and name.endswith(_CACHE_SUFFIX)
            ]
        )

    @staticmethod
    def hash_entity_id(entity_id):
        """Expose the normalized hash used for cache keys."""
        try:
            normalized = normalize_entity_id(entity_id)
        except MissingEntityID:
            normalized = entity_id
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
