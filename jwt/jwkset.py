# Copyright 2017 Gehirn Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import UserList
from typing import TYPE_CHECKING

from .exceptions import InvalidJWKSetError
from .jwk import (
    AbstractJWKBase,
    jwk_from_dict,
)

if TYPE_CHECKING:
    UserListBase = UserList[AbstractJWKBase]
else:
    UserListBase = UserList


class JWKSet(UserListBase):

    def filter_keys(self, kid=None, kty=None):
        # When "kid" values are used within a JWK Set, different
        # keys within the JWK Set SHOULD use distinct "kid" values.  (One
        # example in which different keys might use the same "kid" value is if
        # they have different "kty" (key type) values but are considered to be
        # equivalent alternatives by the application using them.)

        if kid is not None and kty is not None:
            return [
                key
                for key in self.data
                if key.get_kty() == kty and key.get_kid() == kid
            ]
        if kid is not None:
            keys = [key for key in self.data if key.get_kid() == kid]
            key_types = {key.get_kty() for key in keys}
            if len(key_types) > 1:
                raise InvalidJWKSetError(
                    f"Multiple key types match kid {kid!r}: "
                    f"{', '.join(sorted(key_types))}; specify kty to select a "
                    "key"
                )
            return keys
        if kty is not None:
            return [key for key in self.data if key.get_kty() == kty]

        return self.data.copy()

    def to_dict(self, public_only=True):
        keys = [key.to_dict(public_only=public_only) for key in self.data]
        return {"keys": keys}

    @classmethod
    def from_dict(cls, dct):
        keys = [jwk_from_dict(key_dct) for key_dct in dct.get("keys", [])]
        seen = set()
        for key in keys:
            kid = key.get_kid()
            if kid is None:
                continue
            identity = (kid, key.get_kty())
            if identity in seen:
                raise InvalidJWKSetError(
                    f"Duplicate kid {kid!r} for key type "
                    f"{key.get_kty()!r} in JWK Set"
                )
            seen.add(identity)
        return cls(keys)
