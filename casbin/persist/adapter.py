# Copyright 2021 The casbin Authors. All Rights Reserved.
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

import re

_INTERESTING_TOKENS_RE = re.compile(r"[,\[\]\(\)]")


class PolicyLoadError(Exception):
    """raised when a policy line cannot be loaded into the model.

    Carries the 1-based line number (when known) and the reason for the
    failure, so operators can locate the offending rule in the source file.
    """

    def __init__(self, reason, line_no=None, line=None):
        self.reason = reason
        self.line_no = line_no
        self.line = line
        message = "failed to load policy"
        if line_no is not None:
            message += " at line {}".format(line_no)
        message += ": {}".format(reason)
        if line is not None:
            message += " (line: {!r})".format(line)
        super().__init__(message)


def _extract_tokens(line):
    """Return the list of 'tokens' from the line, or None if this line has none"""

    if line == "":
        return None

    if line[:1] == "#":
        return None

    stack = []
    tokens = []

    # The tokens are separated by commas, but we support nesting so a naive `line.split(",")` is
    # wrong. E.g. `abc(def, ghi), jkl` is two tokens: `abc(def, ghi)` and `jkl`. We do this by
    # iterating over the locations of any tokens of interest, and either:
    #
    # - [](): adjust the nesting depth
    # - ,: slice the line to save the token, if the , is at the top-level, outside all []()
    #
    # `start_idx` represents the start of the current token, that we haven't seen a `,` for yet.
    start_idx = 0
    for match in _INTERESTING_TOKENS_RE.finditer(line):
        c = match.group()
        if c == "[" or c == "(":
            stack.append(c)
        elif c == "]" or c == ")":
            stack.pop()
        elif not stack:
            # must be a comma outside of any nesting: we've found the end of a top level token so
            # save that and start a new one
            tokens.append(line[start_idx : match.start()].strip())
            start_idx = match.end()

    # trailing token after the last ,
    tokens.append(line[start_idx:].strip())

    return tokens


def load_policy_line(line, model, line_no=None):
    """loads a text line as a policy rule to model.

    Raises PolicyLoadError if the line names an unknown policy type or the
    rule fails the model's validation (column count, empty fields, duplicates,
    incomplete grouping rules).
    """

    tokens = _extract_tokens(line)
    if tokens is None:
        return

    key = tokens[0]
    sec = key[:1]

    if not sec or sec not in model.model.keys() or key not in model.model[sec].keys():
        raise PolicyLoadError("unknown policy type {!r}".format(key), line_no=line_no, line=line)

    rule = tokens[1:]
    reason = model.validate_load_rule(sec, key, rule)
    if reason is not None:
        raise PolicyLoadError(reason, line_no=line_no, line=line)

    model.model[sec][key].policy.append(rule)


class Adapter:
    """the interface for Casbin adapters."""

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        pass

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
