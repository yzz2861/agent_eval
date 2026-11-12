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

from casbin.core_enforcer import CoreEnforcer
from casbin.model.policy_op import PolicyOp
from casbin.persist.errors import (
    ON_DUPLICATE_FAIL,
    PolicyRollbackError,
)
from casbin.persist.transaction_adapter import TransactionAdapter


class InternalEnforcer(CoreEnforcer):
    """
    InternalEnforcer = CoreEnforcer + Internal API.
    """

    def _add_policies_transaction(self, sec, ptype, rules, on_duplicate=ON_DUPLICATE_FAIL):
        """applies a batch of additions atomically and returns the rules actually added.

        Either every effective rule lands in both the adapter and the in-memory model, or
        the enforcer (policy, role links, decision cache) is left exactly as it was before
        the call. Validation happens first, so a rejected request never reaches storage.
        """
        with self._batch_lock:
            _, effective = self._validate_batch_request(sec, ptype, rules, on_duplicate)
            if not effective:
                return []

            policy_snapshot = self._snapshot_assertion(sec, ptype)
            role_snapshot = self._snapshot_role_links()
            try:
                self._persist_add_batch(sec, ptype, effective)
                self.model.add_policies(sec, ptype, effective)
                self._apply_role_links(sec, ptype, effective, PolicyOp.Policy_add)
            except Exception as error:
                self._rollback_batch(sec, ptype, policy_snapshot, role_snapshot, error)
                raise  # _rollback_batch always raises; this keeps the control flow explicit

            self._notify_batch(PolicyOp.Policy_add, sec, ptype, effective)
            return [rule[:] for rule in effective]

    def _remove_policies_transaction(self, sec, ptype, rules, on_missing=ON_DUPLICATE_FAIL):
        """applies a batch of removals atomically and returns the rules actually removed.
        See :meth:`_add_policies_transaction` for the guarantees."""
        with self._batch_lock:
            _, effective = self._validate_remove_request(sec, ptype, rules, on_missing)
            if not effective:
                return []

            policy_snapshot = self._snapshot_assertion(sec, ptype)
            role_snapshot = self._snapshot_role_links()
            try:
                self._persist_remove_batch(sec, ptype, effective)
                self.model.remove_policies(sec, ptype, effective)
                self._apply_role_links(sec, ptype, effective, PolicyOp.Policy_remove)
            except Exception as error:
                self._rollback_batch(sec, ptype, policy_snapshot, role_snapshot, error)
                raise  # _rollback_batch always raises; this keeps the control flow explicit

            self._notify_batch(PolicyOp.Policy_remove, sec, ptype, effective)
            return [rule[:] for rule in effective]

    def _persist_add_batch(self, sec, ptype, rules):
        """writes one add batch through the adapter, preferring a real storage
        transaction and falling back to single-rule writes that can be compensated."""
        if not (self.adapter and self.auto_save):
            return

        if isinstance(self.adapter, TransactionAdapter):
            tx = self.adapter.begin_transaction()
            try:
                tx.add_policies(sec, ptype, rules)
                tx.commit()
            except Exception:
                tx.rollback()
                raise
            return

        written = []
        try:
            for rule in rules:
                if self.adapter.add_policy(sec, ptype, rule) is False:
                    raise RuntimeError(f"adapter refused to add rule {rule}")
                written.append(rule)
        except Exception as error:
            self._compensate(
                self.adapter.remove_policy, written, sec, ptype, error, "add"
            )

    def _persist_remove_batch(self, sec, ptype, rules):
        if not (self.adapter and self.auto_save):
            return

        if isinstance(self.adapter, TransactionAdapter):
            tx = self.adapter.begin_transaction()
            try:
                tx.remove_policies(sec, ptype, rules)
                tx.commit()
            except Exception:
                tx.rollback()
                raise
            return

        removed = []
        try:
            for rule in rules:
                if self.adapter.remove_policy(sec, ptype, rule) is False:
                    raise RuntimeError(f"adapter refused to remove rule {rule}")
                removed.append(rule)
        except Exception as error:
            self._compensate(
                self.adapter.add_policy, removed, sec, ptype, error, "remove"
            )

    @staticmethod
    def _compensate(undo_call, done_rules, sec, ptype, original_error, operation):
        """replays the inverse write for every rule already sent to a non-transactional
        adapter. If any inverse write fails, the storage is known to be inconsistent, so
        the original error is wrapped instead of being hidden."""
        compensation_failures = []
        for rule in done_rules:
            try:
                undo_call(sec, ptype, rule)
            except Exception:
                compensation_failures.append(rule)
        if compensation_failures:
            raise PolicyRollbackError(
                f"adapter failed during batch {operation} and compensation failed for "
                f"{len(compensation_failures)} rule(s)",
                failed_rules=compensation_failures,
                cause=original_error,
            ) from original_error
        raise original_error

    def _add_policy(self, sec, ptype, rule):
        """adds a rule to the current policy."""
        if self.model.has_policy(sec, ptype, rule):
            return False

        if self.adapter and self.auto_save:
            if self.adapter.add_policy(sec, ptype, rule) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if callable(getattr(self.watcher, "update_for_add_policy", None)):
                self.watcher.update_for_add_policy(sec, ptype, rule)
            else:
                self.watcher.update()

        rule_added = self.model.add_policy(sec, ptype, rule)

        return rule_added

    def _add_policies(self, sec, ptype, rules):
        """adds rules to the current policy."""
        for rule in rules:
            if self.model.has_policy(sec, ptype, rule):
                return False

        if self.adapter and self.auto_save:
            if hasattr(self.adapter, "add_policies") is False:
                return False

            if self.adapter.add_policies(sec, ptype, rules) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if callable(getattr(self.watcher, "update_for_add_policies", None)):
                self.watcher.update_for_add_policies(sec, ptype, rules)
            else:
                self.watcher.update()

        rules_added = self.model.add_policies(sec, ptype, rules)

        return rules_added

    def _add_policies_ex(self, sec, ptype, rules):
        """adds rules to the current policy."""
        if self.adapter and self.auto_save:
            if hasattr(self.adapter, "add_policies_ex") is False:
                return False

            if self.adapter.add_policies_ex(sec, ptype, rules) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if callable(getattr(self.watcher, "update_for_add_policies_ex", None)):
                self.watcher.update_for_add_policies_ex(sec, ptype, rules)
            else:
                self.watcher.update()

        rules_added = self.model.add_policies_ex(sec, ptype, rules)

        return rules_added

    def _update_policy(self, sec, ptype, old_rule, new_rule):
        """updates a rule from the current policy."""
        rule_updated = self.model.update_policy(sec, ptype, old_rule, new_rule)

        if not rule_updated:
            return rule_updated

        if self.adapter and self.auto_save:
            if self.adapter.update_policy(sec, ptype, old_rule, new_rule) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            self.watcher.update()

        return rule_updated

    def _update_policies(self, sec, ptype, old_rules, new_rules):
        """updates rules from the current policy."""
        rules_updated = self.model.update_policies(sec, ptype, old_rules, new_rules)

        if not rules_updated:
            return rules_updated

        if self.adapter and self.auto_save:
            if self.adapter.update_policies(sec, ptype, old_rules, new_rules) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            self.watcher.update()

        return rules_updated

    def _update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        """_update_filtered_policies deletes old rules and adds new rules."""

        old_rules = self.model.get_filtered_policy(sec, ptype, field_index, *field_values)

        if self.adapter and self.auto_save:
            try:
                old_rules = self.adapter.update_filtered_policies(sec, ptype, new_rules, field_index, *field_values)
            except:
                pass

        if not old_rules:
            return False

        is_rule_changed = self.model.remove_policies(sec, ptype, old_rules)
        self.model.add_policies(sec, ptype, new_rules)
        is_rule_changed = is_rule_changed and len(new_rules) != 0
        if not is_rule_changed:
            return is_rule_changed
        if sec == "g":
            self.build_role_links()
        if self.watcher and self.auto_notify_watcher:
            self.watcher.update()
        return is_rule_changed

    def _remove_policy(self, sec, ptype, rule):
        """removes a rule from the current policy."""
        rule_removed = self.model.remove_policy(sec, ptype, rule)
        if not rule_removed:
            return rule_removed

        if self.adapter and self.auto_save:
            if self.adapter.remove_policy(sec, ptype, rule) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if callable(getattr(self.watcher, "update_for_remove_policy", None)):
                self.watcher.update_for_remove_policy(sec, ptype, rule)
            else:
                self.watcher.update()

        return rule_removed

    def _remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the model."""
        rules_removed = self.model.remove_policies(sec, ptype, rules)
        if not rules_removed:
            return rules_removed

        if self.adapter and self.auto_save:
            if hasattr(self.adapter, "remove_policies") is False:
                return False

            if self.adapter.remove_policies(sec, ptype, rules) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if callable(getattr(self.watcher, "update_for_remove_policies", None)):
                self.watcher.update_for_remove_policies(sec, ptype, rules)
            else:
                self.watcher.update()

        return rules_removed

    def _remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes rules based on field filters from the current policy."""
        rule_removed = self.model.remove_filtered_policy(sec, ptype, field_index, *field_values)
        if not rule_removed:
            return rule_removed

        if self.adapter and self.auto_save:
            if self.adapter.remove_filtered_policy(sec, ptype, field_index, *field_values) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if callable(getattr(self.watcher, "update_for_remove_filtered_policy", None)):
                self.watcher.update_for_remove_filtered_policy(sec, ptype, field_index, *field_values)
            else:
                self.watcher.update()

        return rule_removed

    def _remove_filtered_policy_returns_effects(self, sec, ptype, field_index, *field_values):
        """removes rules based on field filters from the current policy."""
        rule_removed = self.model.remove_filtered_policy_returns_effects(sec, ptype, field_index, *field_values)
        if len(rule_removed) == 0:
            return rule_removed

        if self.adapter and self.auto_save:
            if self.adapter.remove_filtered_policy(sec, ptype, field_index, *field_values) is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            self.watcher.update()

        return rule_removed

    def get_field_index(self, ptype, field):
        """gets the index of the field name."""
        return self.model.get_field_index(ptype, field)

    def set_field_index(self, ptype, field, index):
        """sets the index of the field name."""
        assertion = self.model["p"][ptype]
        assertion.field_index_map[field] = index
