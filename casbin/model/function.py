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

from casbin import util


class FunctionMap:
    # Names shipped with pycasbin. They are always available and their results
    # are part of the compatibility contract (keyMatch, ipMatch, timeMatch, ...).
    builtin_functions = (
        "keyMatch",
        "keyMatch2",
        "keyMatch3",
        "keyMatch4",
        "keyMatch5",
        "regexMatch",
        "ipMatch",
        "globMatch",
        "timeMatch",
    )

    def __init__(self):
        self.fm = dict()
        # Tenant functions are only accepted through add_function(). When the
        # whitelist is non-empty, a function whose name is not in it is rejected
        # at registration time instead of becoming reachable from a matcher.
        self.custom_whitelist = set()

    def add_function(self, name, func):
        if name in self.builtin_functions:
            raise ValueError(f"{name!r} is a built-in function and cannot be overridden")
        if self.custom_whitelist and name not in self.custom_whitelist:
            raise ValueError(f"{name!r} is not in the custom function whitelist")
        self.fm[name] = func

    def set_function_whitelist(self, names):
        """restricts which custom function names add_function() may register.

        Built-in names never need to be listed. Passing an empty/falsey container
        removes the restriction (the historical default).
        """
        self.custom_whitelist = set(names) if names else set()

    def is_builtin_function(self, name):
        return name in self.builtin_functions

    def get_custom_functions(self):
        """returns the names registered by the tenant rather than shipped by casbin."""
        return tuple(name for name in self.fm if name not in self.builtin_functions)

    @staticmethod
    def load_function_map():
        fm = FunctionMap()
        # Populated directly: add_function() is the tenant entry point and must
        # refuse to shadow these names.
        fm.fm["keyMatch"] = util.key_match_func
        fm.fm["keyMatch2"] = util.key_match2_func
        fm.fm["keyMatch3"] = util.key_match3_func
        fm.fm["keyMatch4"] = util.key_match4_func
        fm.fm["keyMatch5"] = util.key_match5_func
        fm.fm["regexMatch"] = util.regex_match_func
        fm.fm["ipMatch"] = util.ip_match_func
        fm.fm["globMatch"] = util.glob_match_func
        fm.fm["timeMatch"] = util.time_match_func

        return fm

    def get_functions(self):
        return self.fm
