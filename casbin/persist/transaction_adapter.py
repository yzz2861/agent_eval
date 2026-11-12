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

from .batch_adapter import BatchAdapter


class Transaction(metaclass=ABCMeta):
    """one unit of work handed out by :class:`TransactionAdapter`.

    Every rule staged on a transaction is buffered in the same underlying storage
    transaction. ``commit`` makes all of it visible together; ``rollback`` discards all
    of it together. Nothing staged on a transaction may be observable through the
    adapter's regular reads before ``commit`` succeeds.
    """

    @abstractmethod
    def add_policies(self, sec, ptype, rules):
        """stages rule additions inside the transaction."""
        pass

    @abstractmethod
    def remove_policies(self, sec, ptype, rules):
        """stages rule removals inside the transaction."""
        pass

    @abstractmethod
    def commit(self):
        """commits every staged change atomically."""
        pass

    @abstractmethod
    def rollback(self):
        """discards every staged change. Must be safe to call after an error,
        including after ``commit`` itself failed."""
        pass

    # context-manager convenience:
    #
    #   with adapter.begin_transaction() as tx:
    #       tx.add_policies(...)
    #       tx.commit()
    #
    # leaving the ``with`` block without a successful commit rolls the transaction back.
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.rollback()
        return False


class TransactionAdapter(BatchAdapter):
    """a batch adapter that can group several rule writes into one storage transaction."""

    @abstractmethod
    def begin_transaction(self):
        """returns a fresh :class:`Transaction`."""
        pass
