# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Ordered execution of a validated offline release plan.

Content is staged at content-addressed immutable keys with retry; visibility
changes are single-object conditional pointer updates guarded by the etags
captured when the plan was built. No partial byte ever lands at a visible key
and no pointer moves until all content is present and validation passes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from .errors import StaleRootPlanError
from .model import ReleasePlan, ReleaseReport, SwitchPoint, UploadRecord
from .objectstore import ObjectStore, StorageConditionError
from .retry import RetryPolicy
from .validator import validate_plan


class PublishExecutor:
    """Publishes a validated plan with ordering, reuse and retry."""

    def __init__(
        self,
        store: ObjectStore,
        *,
        max_attempts: int = 3,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._store = store
        self._max_attempts = max_attempts
        self._sleep = sleep

    def _policy(self) -> RetryPolicy:
        kwargs = {"max_attempts": self._max_attempts}
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        return RetryPolicy(**kwargs)  # type: ignore[arg-type]

    def _upload_content(self, plan: ReleasePlan) -> list[UploadRecord]:
        policy = self._policy()
        records: list[UploadRecord] = []
        for obj in plan.uploads:
            before = len(policy.attempts)
            if self._store.exists(obj.key):
                records.append(UploadRecord(obj.key, "reused", 1))
                continue
            policy.run(obj.key, lambda key=obj.key, data=obj.data:
                       self._store.put_if_absent(key, data))
            attempts = len(policy.attempts) - before
            records.append(UploadRecord(obj.key, "uploaded", attempts))
        return records

    def _switch(self, point: SwitchPoint, plan: ReleasePlan) -> None:
        try:
            self._store.put_pointer(
                point.pointer_key,
                point.content_key,
                expected_etag=plan.expected_etags.get(point.pointer_key),
            )
        except StorageConditionError as err:
            raise StaleRootPlanError(
                f"refusing switch at {point.name}: {err}. A concurrent "
                "publication changed the live repository; rebuild the plan "
                "from the current root before retrying."
            ) from err

    def execute(
        self,
        plan: ReleasePlan,
        verify_callback: Callable[[ObjectStore, SwitchPoint], None]
        | None = None,
    ) -> ReleaseReport:
        """Validate, stage all content, then switch pointers one at a time.

        ``verify_callback`` runs after every switch with the current store and
        switch point, so an existing client can read the mirror at each
        visibility boundary. Validation happens first, before any write.
        """
        validate_plan(plan, self._store)

        uploads = self._upload_content(plan)

        reached: list[str] = []
        for point in plan.switch_order:
            self._switch(point, plan)
            reached.append(point.name)
            if verify_callback is not None:
                verify_callback(self._store, point)

        retained = sorted(
            key
            for key in self._store.list_keys()
            if key.startswith(("metadata/", "targets/"))
            and not self._is_pointer(key)
        )
        return ReleaseReport(
            plan_id=plan.plan_id,
            uploads=uploads,
            switches=reached,
            retained_keys=retained,
        )

    @staticmethod
    def _is_pointer(key: str) -> bool:
        # Pointers are non-versioned role files such as metadata/timestamp.json.
        if not key.startswith("metadata/") or not key.endswith(".json"):
            return False
        stem = key.removeprefix("metadata/").removesuffix(".json")
        return not stem[:1].isdigit()
