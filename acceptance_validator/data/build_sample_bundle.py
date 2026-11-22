"""Build the offline sample bundle covering every acceptance scenario."""

import json
import os
import uuid

from stix2 import Bundle, File, Identity, MarkingDefinition, ObservedData, Report

from acceptance_validator.markings import (
    RELEASE_PURPOSE,
    SCOPE_ENTITY_ATTRIBUTE,
    SCOPE_RELATIONSHIP,
    InvestigationAuthorization,
)

UUID_NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")
OUTPUT = os.path.join(os.path.dirname(__file__), "sample_bundle.json")


def marking(marking_id, name, auth_id, purposes, scopes, status):
    return MarkingDefinition(
        id=marking_id,
        name=name,
        definition_type="x-investigation-authorization",
        definition=InvestigationAuthorization(
            x_authorization_id=auth_id,
            x_permitted_purposes=purposes,
            x_scope=scopes,
            x_status=status,
        ),
    )


warrant = marking(
    "marking-definition--aa000000-0000-4000-8000-000000000001",
    "Warrant-42", "WARRANT-42",
    [RELEASE_PURPOSE], [SCOPE_ENTITY_ATTRIBUTE, SCOPE_RELATIONSHIP], "approved",
)
draft_warrant = marking(
    "marking-definition--aa000000-0000-4000-8000-000000000002",
    "Draft warrant (not approved)", "DRAFT-77",
    [RELEASE_PURPOSE], [SCOPE_ENTITY_ATTRIBUTE, SCOPE_RELATIONSHIP], "pending",
)
attr_only = marking(
    "marking-definition--aa000000-0000-4000-8000-000000000003",
    "Entity-attribute only authorization", "ATTR-ONLY-9",
    [RELEASE_PURPOSE], [SCOPE_ENTITY_ATTRIBUTE], "approved",
)


source_a = Identity(id="identity--0a000000-0000-4000-8000-000000000001",
                    name="Observer Org A", identity_class="organization")
source_b = Identity(id="identity--0b000000-0000-4000-8000-000000000002",
                    name="Observer Org B", identity_class="organization")
source_c = Identity(id="identity--0c000000-0000-4000-8000-000000000003",
                    name="Observer Org C", identity_class="organization")

objects = [warrant, draft_warrant, attr_only, source_a, source_b, source_c]


def observation(obs_id, source, material, markings, index):
    file_id = "file--" + str(uuid.uuid5(UUID_NAMESPACE, "file-%d" % index))
    sco = File(id=file_id, name="artifact-%s.bin" % material,
               allow_custom=True)
    observed = ObservedData(
        id=obs_id,
        created_by_ref=source.id,
        first_observed="2026-10-01T00:00:00Z",
        last_observed="2026-10-01T01:00:00Z",
        number_observed=1,
        object_refs=[sco.id],
        object_marking_refs=[m.id for m in markings],
        x_raw_material_id=material,
        allow_custom=True,
    )
    objects.append(sco)
    objects.append(observed)
    return observed


def conclusion(report_id, name, scope, observations, markings):
    report = Report(
        id=report_id,
        name=name,
        report_types=["threat-report"],
        published="2026-11-05T00:00:00Z",
        object_refs=[item.id for item in observations],
        object_marking_refs=[m.id for m in markings],
        x_conclusion_scope=scope,
        x_review_cell=scope,
        allow_custom=True,
    )
    objects.append(report)
    return report


# Scenario 1: two independent sources/materials, both under the full warrant -> RELEASE
o1 = observation("observed-data--c1000000-0000-4000-8000-000000000001",
                 source_a, "MAT-001", [warrant], 1)
o2 = observation("observed-data--c1000000-0000-4000-8000-000000000002",
                 source_b, "MAT-002", [warrant], 2)
conclusion("report--c1000000-0000-4000-8000-000000000001",
           "C1 entity attributes corroborated by two units",
           SCOPE_ENTITY_ATTRIBUTE, [o1, o2], [warrant])

# Scenario 2: long evidence list, but every ref reuses one material from one source -> HOLD
shared = []
for suffix in range(3, 9):
    shared.append(observation(
        "observed-data--c2000000-0000-4000-8000-%012d" % suffix,
        source_a, "MAT-SHARED", [warrant], suffix))
conclusion("report--c2000000-0000-4000-8000-000000000002",
           "C2 six references all quoting one authorized source",
           SCOPE_ENTITY_ATTRIBUTE, shared, [warrant])


# Scenario 3: two independent observations, but the only authorization is a pending draft -> HOLD
o3 = observation("observed-data--c3000000-0000-4000-8000-000000000001",
                 source_a, "MAT-003", [draft_warrant], 10)
o4 = observation("observed-data--c3000000-0000-4000-8000-000000000002",
                 source_b, "MAT-004", [draft_warrant], 11)
conclusion("report--c3000000-0000-4000-8000-000000000003",
           "C3 relationship inference under an unapproved warrant",
           SCOPE_RELATIONSHIP, [o3, o4], [draft_warrant])

# Scenario 4: relationship conclusion whose authorization only covers entity attributes -> HOLD
o5 = observation("observed-data--c4000000-0000-4000-8000-000000000001",
                 source_a, "MAT-005", [attr_only], 12)
o6 = observation("observed-data--c4000000-0000-4000-8000-000000000002",
                 source_b, "MAT-006", [attr_only], 13)
conclusion("report--c4000000-0000-4000-8000-000000000004",
           "C4 derived link released beyond the authorization scope",
           SCOPE_RELATIONSHIP, [o5, o6], [attr_only])


# Scenario 5: two reports share one material, each also has its own independent observation
# -> each report independently has two (source, material) pairs and is releasable;
#    the shared material is preserved via x_raw_material_id but counted only once per report.
o7 = observation("observed-data--c5000000-0000-4000-8000-000000000001",
                 source_a, "MAT-SHARED-5", [warrant], 14)
o8 = observation("observed-data--c5000000-0000-4000-8000-000000000002",
                 source_b, "MAT-008", [warrant], 15)
o9 = observation("observed-data--c5000000-0000-4000-8000-000000000003",
                 source_c, "MAT-009", [warrant], 16)
conclusion("report--c5000000-0000-4000-8000-000000000005",
           "C5 report alpha reusing shared material",
           SCOPE_ENTITY_ATTRIBUTE, [o7, o8], [warrant])
conclusion("report--c5000000-0000-4000-8000-000000000006",
           "C5 report beta reusing the same shared material",
           SCOPE_ENTITY_ATTRIBUTE, [o7, o9], [warrant])

bundle = Bundle(objects=objects, allow_custom=True)
with open(OUTPUT, "w", encoding="utf-8") as handle:
    json.dump(json.loads(bundle.serialize()), handle, ensure_ascii=False, indent=2)
print("wrote %d objects to %s" % (len(bundle.objects), OUTPUT))
