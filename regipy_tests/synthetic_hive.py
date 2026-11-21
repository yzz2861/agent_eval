"""Tiny in-memory registry trees for tests and the attribution demo.

They implement only the read surface used by regipy.uninstall_attribution.
They never touch the live registry or a hive file, keeping the missing-hive
demonstration deterministic.
"""

from types import SimpleNamespace

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException


class SyntheticValue:
    def __init__(self, name, value, value_type="REG_SZ"):
        self.name = name
        self.value = value
        self.value_type = value_type
        self.is_corrupted = False


class SyntheticKey:
    def __init__(self, name, timestamp=132000000000000000):
        self.name = name
        self.header = SimpleNamespace(last_modified=timestamp)
        self._subkeys = {}
        self._values = {}

    @property
    def subkey_count(self):
        return len(self._subkeys)

    @property
    def values_count(self):
        return len(self._values)

    def add_subkey(self, name):
        key = self._subkeys.get(name.casefold())
        if key is None:
            key = SyntheticKey(name, timestamp=self.header.last_modified)
            self._subkeys[name.casefold()] = key
        return key

    def set_value(self, name, value, value_type="REG_SZ"):
        self._values[name] = SyntheticValue(name, value, value_type=value_type)

    def get_subkey(self, name, raise_on_missing=True):
        key = self._subkeys.get(name.casefold())
        if key is None and raise_on_missing:
            raise NoRegistrySubkeysException(name)
        return key

    def iter_subkeys(self):
        if not self._subkeys:
            return None
        return iter(self._subkeys.values())

    def iter_values(self, as_json=False, trim_values=True):
        yield from self._values.values()

    def get_value(self, name, as_json=False, raise_on_missing=False, case_sensitive=True):
        for value in self.iter_values(as_json=as_json):
            candidate = value.name if case_sensitive else value.name.casefold()
            target = name if case_sensitive else name.casefold()
            if candidate == target:
                return value.value
        if raise_on_missing:
            raise RegistryKeyNotFoundException(name)
        return None

    def get_values(self, as_json=False, trim_values=False):
        return list(self.iter_values(as_json=as_json, trim_values=trim_values))


class SyntheticHive:
    def __init__(self, hive_type, name="SYNTHETIC", timestamp=132000000000000000):
        self.hive_type = hive_type
        self.name = name
        self.partial_hive_path = None
        self.root = SyntheticKey("ROOT", timestamp=timestamp)

    def get_key(self, key_path):
        if key_path in ("", "\\"):
            return self.root
        if "\\" not in key_path:
            parts = [key_path]
        else:
            parts = [part for part in key_path.split("\\") if part]
        key = self.root
        for part in parts:
            key = key.get_subkey(part, raise_on_missing=False)
            if key is None:
                raise RegistryKeyNotFoundException(key_path)
        return key


def build_hive(hive_type, entries, name="SYNTHETIC", timestamp=132000000000000000):
    """Build a hive from {path: {value_name: value}} entries."""

    hive = SyntheticHive(hive_type, name=name, timestamp=timestamp)
    for path, values in entries.items():
        if path in ("", "\\"):
            key = hive.root
        else:
            parts = [part for part in path.split("\\") if part]
            key = hive.root
            for part in parts:
                key = key.add_subkey(part)
        for value_name, value in values.items():
            key.set_value(value_name, value)
    return hive
