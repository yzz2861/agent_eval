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

from abc import ABCMeta, abstractmethod

from .batch_adapter import AsyncBatchAdapter


class AsyncTransaction(metaclass=ABCMeta):
    """async counterpart of :class:`casbin.persist.transaction_adapter.Transaction`."""

    @abstractmethod
    async def add_policies(self, sec, ptype, rules):
        """stages rule additions inside the transaction."""
        pass

    @abstractmethod
    async def remove_policies(self, sec, ptype, rules):
        """stages rule removals inside the transaction."""
        pass

    @abstractmethod
    async def commit(self):
        """commits every staged change atomically."""
        pass

    @abstractmethod
    async def rollback(self):
        """discards every staged change."""
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            await self.rollback()
        return False


class AsyncTransactionAdapter(AsyncBatchAdapter):
    """an async batch adapter that supports storage-level transactions."""

    @abstractmethod
    async def begin_transaction(self):
        """returns a fresh :class:`AsyncTransaction`."""
        pass
