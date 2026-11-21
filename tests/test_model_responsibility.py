# This file is part of CycloneDX Python Library
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
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest import TestCase

from cyclonedx.exception.model import (
    InvalidAuthorizationWindowException,
    UnassignedAssignmentStepException,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import (
    ComponentEvidence,
    Identity,
    IdentityField,
    Occurrence,
)
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.responsibility import (
    AssignmentStatus,
    AssignmentStep,
    AuthorizationGrant,
    ResponsibilityPlan,
    ResponsibilityTeam,
)

NOW = datetime(2026, 11, 22, 0, 0, tzinfo=timezone.utc)
WINDOW_START = NOW - timedelta(days=1)
WINDOW_END = NOW + timedelta(days=1)


def _component(
    *,
    bom_ref: str,
    name: str,
    component_type: ComponentType,
    locations: tuple[str, ...] = (),
    identity_name: str = '',
) -> Component:
    identity = [Identity(
        field=IdentityField.NAME,
        confidence=Decimal('1'),
        concluded_value=identity_name,
    )] if identity_name else []
    return Component(
        bom_ref=bom_ref,
        name=name,
        type=component_type,
        evidence=ComponentEvidence(
            identity=identity,
            occurrences=[Occurrence(location=location) for location in locations],
        ),
    )


def _plan() -> ResponsibilityPlan:
    app = _component(
        bom_ref='app-wrapper',
        name='storefront',
        component_type=ComponentType.APPLICATION,
        locations=('src/main.py',),
        identity_name='storefront',
    )
    runtime = _component(
        bom_ref='shared-runtime',
        name='shared-runtime',
        component_type=ComponentType.LIBRARY,
        identity_name='shared-runtime',
    )
    vendor = _component(
        bom_ref='vendor-image',
        name='vendor-base-image',
        component_type=ComponentType.CONTAINER,
        locations=('layers/base.tar',),
    )
    bom = Bom(
        components=[app, runtime, vendor],
        dependencies=[
            Dependency(ref=app.bom_ref, dependencies=[Dependency(ref=runtime.bom_ref)]),
        ],
    )

    plan = ResponsibilityPlan.from_bom(bom)
    plan.add_team(ResponsibilityTeam(id='app-platform', capabilities=frozenset({'upgrade'})))
    plan.add_team(ResponsibilityTeam(id='runtime-sre', capabilities=frozenset({'upgrade'})))
    plan.add_team(ResponsibilityTeam(id='release-qa', capabilities=frozenset({'accept'})))

    plan.add_step(AssignmentStep(
        id='upgrade-app',
        capability='upgrade',
        component_ref='app-wrapper',
        required_evidence=frozenset({'identity', 'occurrence'}),
    ))
    plan.add_step(AssignmentStep(
        id='accept-runtime',
        capability='accept',
        component_ref='shared-runtime',
        required_evidence=frozenset({'identity'}),
    ))
    plan.add_step(AssignmentStep(
        id='upgrade-vendor',
        capability='upgrade',
        component_ref='vendor-image',
        required_evidence=frozenset({'occurrence'}),
    ))

    for grant_id, team_id, capability in (
        ('grant-app-platform-upgrade', 'app-platform', 'upgrade'),
        ('grant-runtime-sre-upgrade', 'runtime-sre', 'upgrade'),
        ('grant-release-qa-accept', 'release-qa', 'accept'),
    ):
        plan.add_grant(AuthorizationGrant(
            id=grant_id,
            team_id=team_id,
            capability=capability,
            component_ref='app-wrapper',
            valid_from=WINDOW_START,
            valid_until=WINDOW_END,
        ))
    return plan


class TestModelResponsibilityPlan(TestCase):

    def test_three_positions_have_readable_results(self) -> None:
        snapshot = _plan().freeze(at=NOW)

        self.assertListEqual(
            [
                ('upgrade-app', 'assigned', 'app-platform'),
                ('accept-runtime', 'assigned', 'release-qa'),
                ('upgrade-vendor', 'unassigned', None),
            ],
            [
                (row['stepId'], row['status'], row['teamId'])
                for row in snapshot.as_rows()
            ],
        )
        self.assertEqual(1, len(snapshot.unassigned))
        self.assertEqual('upgrade-vendor', snapshot.unassigned[0].step_id)

    def test_two_teams_can_upgrade_but_only_one_can_accept(self) -> None:
        snapshot = _plan().freeze(at=NOW)
        upgrade = snapshot['upgrade-app']
        acceptance = snapshot['accept-runtime']

        self.assertEqual(('app-platform', 'runtime-sre'), upgrade.eligible_teams)
        self.assertEqual('app-platform', upgrade.assignee)
        self.assertEqual(('release-qa',), acceptance.eligible_teams)
        self.assertEqual('release-qa', acceptance.assignee)
        self.assertNotIn('release-qa', upgrade.eligible_teams)
        self.assertNotIn('app-platform', acceptance.eligible_teams)
        self.assertNotIn('runtime-sre', acceptance.eligible_teams)

    def test_result_explains_evidence_and_dependency_edge(self) -> None:
        snapshot = _plan().freeze(at=NOW)
        upgrade = snapshot['upgrade-app']
        acceptance = snapshot['accept-runtime']
        vendor = snapshot['upgrade-vendor']

        self.assertEqual(('identity', 'occurrence'), upgrade.evidence.kinds)
        self.assertIn('direct grant grant-app-platform-upgrade', upgrade.reason)
        self.assertEqual(('app-wrapper', 'shared-runtime'), acceptance.dependency_path)
        self.assertIn('app-wrapper -> shared-runtime', acceptance.reason)
        self.assertIn('identity', acceptance.reason)
        self.assertIn('does not cover', vendor.reason)

    def test_component_without_required_evidence_is_unassigned(self) -> None:
        plan = _plan()
        plan.add_step(AssignmentStep(
            id='app-callstack',
            capability='upgrade',
            component_ref='app-wrapper',
            required_evidence=frozenset({'callstack'}),
        ))

        result = plan.result_for('app-callstack', at=NOW)

        self.assertEqual(AssignmentStatus.UNASSIGNED, result.status)
        self.assertIn('callstack', result.reason)

    def test_revocation_preserves_completed_sign_off(self) -> None:
        plan = _plan()
        sign_off = plan.sign_off(
            'upgrade-app',
            completed_at=NOW,
            note='upgrade verified',
        )

        plan.revoke_grant('grant-app-platform-upgrade', at=NOW + timedelta(hours=1))
        after_one_revocation = plan.freeze(at=NOW + timedelta(hours=2))
        self.assertEqual(AssignmentStatus.SIGNED_OFF, after_one_revocation['upgrade-app'].status)
        self.assertEqual('app-platform', after_one_revocation['upgrade-app'].assignee)
        self.assertEqual(('runtime-sre',), after_one_revocation['upgrade-app'].eligible_teams)

        plan.revoke_grant('grant-runtime-sre-upgrade', at=NOW + timedelta(hours=1))
        after_all_revocations = plan.freeze(at=NOW + timedelta(hours=2))
        result = after_all_revocations['upgrade-app']

        self.assertEqual(AssignmentStatus.SIGNED_OFF, result.status)
        self.assertEqual('app-platform', result.team_id)
        self.assertEqual(sign_off, result.sign_off)
        self.assertEqual('upgrade verified', result.sign_off.note if result.sign_off else None)
        self.assertEqual((), result.eligible_teams)
        self.assertIn('completed sign-off retained', result.reason)

    def test_frozen_snapshot_is_not_changed_by_later_revocation(self) -> None:
        plan = _plan()
        frozen_before = plan.freeze(at=NOW)

        plan.revoke_grant('grant-app-platform-upgrade', at=NOW)
        frozen_after = plan.freeze(at=NOW)

        self.assertEqual('app-platform', frozen_before['upgrade-app'].team_id)
        self.assertEqual(AssignmentStatus.ASSIGNED, frozen_before['upgrade-app'].status)
        self.assertEqual('runtime-sre', frozen_after['upgrade-app'].team_id)
        self.assertIsNone(
            next(
                grant for grant in frozen_before.grants
                if grant.id == 'grant-app-platform-upgrade'
            ).revoked_at
        )

    def test_unassigned_step_cannot_be_signed_off(self) -> None:
        with self.assertRaises(UnassignedAssignmentStepException):
            _plan().sign_off('upgrade-vendor', completed_at=NOW)

    def test_invalid_authorization_window_is_rejected(self) -> None:
        with self.assertRaises(InvalidAuthorizationWindowException):
            AuthorizationGrant(
                team_id='app-platform',
                capability='upgrade',
                component_ref='app-wrapper',
                valid_from=NOW,
                valid_until=NOW,
            )

    def test_snapshot_is_deterministic(self) -> None:
        plan = _plan()
        first = plan.freeze(at=NOW)
        second = plan.freeze(at=NOW)

        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.as_dict()['digest'], second.as_dict()['digest'])
