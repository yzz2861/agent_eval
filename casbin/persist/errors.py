# Copyright 2026 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Exceptions raised by the transactional policy change machinery.

Validation errors are raised *before* anything is written, so a caller catching
:class:`PolicyValidationError` knows the enforcer and the adapter were never touched.
A failure coming from the adapter itself is always re-raised after the in-memory state
has been restored; :class:`PolicyRollbackError` only appears when that restoration could
not be completed, which means the enforcer can no longer promise in-memory/storage
consistency.
"""


class PolicyError(Exception):
    """base class for every error raised by the batch policy machinery."""


# how a batch should treat rules that are already present (add) / absent (remove).
# one mode per batch call: either the whole batch fails or the offending rules are
# skipped, there is no per-rule mixed outcome.
ON_DUPLICATE_FAIL = "fail"
ON_DUPLICATE_IGNORE = "ignore"

_ON_DUPLICATE_MODES = (ON_DUPLICATE_FAIL, ON_DUPLICATE_IGNORE)


class PolicyValidationError(PolicyError, ValueError):
    """a batch request is malformed (bad rule shape, unknown ptype, empty or
    duplicated rules). Nothing has been written when this is raised."""


class PolicyRollbackError(PolicyError):
    """the adapter rejected a change, and undoing the partial writes failed too.

    The original adapter failure is preserved as ``__cause__`` (the ``raise ... from``
    chain), and the rules that could not be undone are listed in ``failed_rules``.
    """

    def __init__(self, message, failed_rules=None, cause=None):
        super().__init__(message)
        self.failed_rules = [list(rule) for rule in (failed_rules or [])]
        if cause is not None:
            self.__cause__ = cause
