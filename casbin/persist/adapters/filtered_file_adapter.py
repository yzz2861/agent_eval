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

import os

from casbin import persist

from .file_adapter import FileAdapter
from ..adapter_filtered import FilteredAdapter

DOMAIN_TOKEN_NAMES = frozenset(("dom", "domain", "tenant", "workspace"))


class Filter:
    # P,G are string []
    def __init__(self):
        self.P = []
        self.G = []


class FilteredFileAdapter(FileAdapter, FilteredAdapter):
    filtered = False
    _file_path = ""
    filter = Filter()

    # new_filtered_adapter is the constructor for FilteredAdapter.
    def __init__(self, file_path):
        self.filtered = True
        self._file_path = file_path

    def load_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")
        self.filtered = False
        self._load_policy_file(model)

    # load_filtered_policy loads only policy rules that match the filter.
    def load_filtered_policy(self, model, filter):
        if filter == None:
            return self.load_policy(model)

        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        try:
            filter_value = [filter.__dict__["P"]] + [filter.__dict__["G"]]
            is_empty_filter = all(not f for f in filter_value) or all(
                all(not x.strip() for x in f) if f else True for f in filter_value
            )
            if is_empty_filter:
                return self.load_policy(model)
        except:
            raise RuntimeError("invalid filter type")

        self.load_filtered_policy_file(model, filter_value, persist.load_policy_line)
        self.filtered = True

    def load_filtered_policy_file(self, model, filter, handler):
        with open(self._file_path, "rb") as file:
            for line in file:
                line = line.decode().strip()
                if not line or line == "\n":
                    continue

                if filter_line(line, filter, model):
                    continue

                handler(line, model)

    # is_filtered returns true if the loaded policy has been filtered.
    def is_filtered(self):
        return self.filtered

    def save_policy(self, model):
        if self.filtered:
            raise RuntimeError("cannot save a filtered policy")

        self._save_policy_file(model)


def _domain_filter_index(model, key):
    """Return the filter position of a policy/role domain field.

    The filter arrays are positional and start at the first policy field
    (the line's section key is not part of them). ``None`` means that the
    section has no domain field.
    """
    if model is None or not key:
        return None

    sec = key[0]
    if sec not in model.keys():
        return None
    assertion = (model[sec] or {}).get(key)
    if assertion is None:
        return None

    if sec == "g":
        # Role definitions are positional: g = user, role, domain, ...
        return 2 if len(assertion.tokens) > 2 else None

    if sec == "p":
        tokens = assertion.tokens
        for index, token in enumerate(tokens):
            token_name = token.split("_", 1)[1] if "_" in token else token
            if token_name in DOMAIN_TOKEN_NAMES:
                return index

        # Custom domain token names are conventionally the second field and
        # are matched against the request definition's second token.
        request = (model["r"] or {}).get("r") if "r" in model.keys() else None
        if request is not None and len(request.tokens) > 1 and len(tokens) > 1:
            request_name = request.tokens[1].split("_", 1)[1]
            if request_name in DOMAIN_TOKEN_NAMES and tokens[1].split("_", 1)[1] == request_name:
                return 1

    return None


def filter_line(line, filter, model=None):
    if filter == None:
        return False

    p = line.split(",")
    if len(p) == 0:
        return True
    filter_slice = []
    domain_index = None
    key = p[0].strip()

    if key.startswith("g"):
        if not filter[1] or all(not x.strip() for x in filter[1]):
            return False
        filter_slice = filter[1]
        domain_index = _domain_filter_index(model, key)
    elif key.startswith("p"):
        filter_slice = filter[0]
        domain_index = _domain_filter_index(model, key)

    return filter_words(p, filter_slice, domain_index)


def filter_words(line, filter, domain_index=None):
    if len(line) < len(filter) + 1:
        return True
    skip_line = False
    for i, v in enumerate(filter):
        value = line[i + 1].strip()
        if not v or not v.strip():
            continue

        # An explicit "*" in the domain position is a global role/policy
        # declaration. Keep it when loading any tenant's subset; the role
        # manager decides which domains it is visible from. Empty domains
        # are intentionally not treated as wildcards.
        if i == domain_index and value == "*":
            continue

        if v.strip() != value:
            skip_line = True
            break

    return skip_line
