#    This file is part of python-registry.
#
#   Explicit, audited name lookup view for forensic use.
#
#   The legacy RegistryKey.subkey()/value() helpers de-duplicate names with a
#   plain lower() and silently return the first hit.  That behavior is
#   preserved unchanged for backwards compatibility; the view exposed here
#   instead reports every candidate of an equivalence class together with its
#   on-disk offset, and never guesses when the Windows collation is unknown.
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
from __future__ import unicode_literals

from . import NameAudit


class AmbiguousNameException(Exception):
    """
    Raised when a single-result lookup reaches an equivalence class with more
    than one stored candidate.  The full LookupResult is attached so that no
    evidence is discarded.
    """
    def __init__(self, result):
        self.result = result
        super(AmbiguousNameException, self).__init__(
            "name %r matches %d distinct records at offsets %s"
            % (result.query(), len(result.candidates()),
               ["0x%x" % offset for offset in result.offsets()]))


class UnknownCollationException(Exception):
    """
    Raised when a non-ASCII name cannot be resolved because the Windows
    collation behavior is not reproducible and only exact code-point identity
    is available.
    """
    def __init__(self, result):
        self.result = result
        super(UnknownCollationException, self).__init__(
            "lookup of %r requires an unknown Windows collation rule"
            % (result.query(),))


class KeyNameView(object):
    """
    Audited view of the subkeys of one RegistryKey.

    It wraps the parsed NK records without mutating them; the underlying
    buffer stays read-only.
    """
    def __init__(self, nkrecord):
        self._nkrecord = nkrecord

    def _candidates(self):
        if self._nkrecord.subkey_number() == 0:
            return []
        candidates = []
        for record in self._nkrecord.subkey_list().keys():
            candidates.append(NameAudit.NameCandidate(
                record.name_identity(), record.offset(), record))
        return candidates

    def identities(self):
        """
        All subkey names as NameIdentity objects, in on-disk order.  Distinct
        raw identities are never collapsed.
        """
        return [candidate.identity() for candidate in self._candidates()]

    def lookup(self, name):
        """
        Resolve a subkey name without silently choosing a candidate.

        @type name: str
        @rtype: NameAudit.LookupResult
        """
        return NameAudit.query_identity(name, self._candidates())

    def require(self, name):
        """
        Return the unique RegistryKey for name, or raise.

        AmbiguousNameException is raised for multi-candidate equivalence
        classes; UnknownCollationException when the Windows rule cannot be
        applied.  The caller can inspect the attached LookupResult instead of
        losing evidence.
        """
        from .Registry import RegistryKey, RegistryKeyNotFoundException
        result = self.lookup(name)
        if result.is_ambiguous():
            raise AmbiguousNameException(result)
        if result.outcome() == NameAudit.LookupOutcome.UNKNOWN_RULE:
            raise UnknownCollationException(result)
        if not result.is_match():
            raise RegistryKeyNotFoundException(
                self._nkrecord.path() + "\\" + name)
        return RegistryKey(result.single_candidate().record())


class ValueNameView(object):
    """
    Audited view of the values of one RegistryKey.
    """
    def __init__(self, nkrecord):
        self._nkrecord = nkrecord

    def _candidates(self):
        try:
            records = list(self._nkrecord.values_list().values())
        except Exception:
            return []
        candidates = []
        for record in records:
            candidates.append(NameAudit.NameCandidate(
                record.name_identity(), record.offset(), record))
        return candidates

    def identities(self):
        return [candidate.identity() for candidate in self._candidates()]

    def lookup(self, name):
        """
        @type name: str.  The legacy alias "(default)" maps to the empty name.
        @rtype: NameAudit.LookupResult
        """
        if name == "(default)":
            name = ""
        return NameAudit.query_identity(name, self._candidates())

    def require(self, name):
        from .Registry import RegistryValue, RegistryValueNotFoundException
        result = self.lookup(name)
        if result.is_ambiguous():
            raise AmbiguousNameException(result)
        if result.outcome() == NameAudit.LookupOutcome.UNKNOWN_RULE:
            raise UnknownCollationException(result)
        if not result.is_match():
            raise RegistryValueNotFoundException(
                self._nkrecord.path() + " : " + name)
        return RegistryValue(result.single_candidate().record())
