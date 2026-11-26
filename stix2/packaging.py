"""Deterministic planning for independently verifiable STIX packages."""

from collections import namedtuple
from itertools import combinations


ProofRequirement = namedtuple(
    "ProofRequirement", ["assertion_id", "object_ids", "possible_senders"],
)
PlannedPackage = namedtuple(
    "PlannedPackage", [
        "package_id", "sender", "assertion_ids", "object_ids",
    ],
)
DeliveryPlan = namedtuple(
    "DeliveryPlan", ["plan_id", "package_ids", "senders"],
)
PackagePlanningResult = namedtuple(
    "PackagePlanningResult", [
        "proof_requirements",
        "minimum_proof_sets",
        "packages",
        "mandatory_assertion_groups",
        "minimum_complete_plans",
        "minimum_single_sender_plans",
        "minimum_joint_receipt_plans",
        "single_sender_packages",
    ],
)


def plan_stix_packages(
    assertions, dependencies, sender_permissions, forbidden_together=(),
):
    """Plan minimum sets of STIX objects needed to verify assertions.

    Args:
        assertions: mapping or list of assertions. A mapping has assertion
            identifiers and the object identifiers directly needed by each
            assertion. A list item may be a ``(assertion_id, object_ids)``
            pair, a mapping with ``id`` and ``object_ids`` keys, or a STIX
            relationship object.
        dependencies: mapping from an object identifier to the object
            identifiers required to verify it.
        sender_permissions: mapping from a sender to the object identifiers
            that sender is allowed to distribute.
        forbidden_together: iterable of object identifier sets. No planned
            package may contain all members of one set.

    Returns:
        PackagePlanningResult containing deterministic package candidates and
        all minimum complete delivery plans.

    Raises:
        ValueError: if the input is invalid or no legal delivery is possible.
    """
    assertion_order, assertion_objects = _normalize_assertions(assertions)
    dependency_graph = _normalize_dependencies(dependencies)
    sender_order, permissions = _normalize_permissions(sender_permissions)
    forbidden_sets = _normalize_forbidden_sets(
        forbidden_together, dependency_graph, assertion_objects, permissions,
    )
    _validate_known_objects(
        assertion_order, assertion_objects, dependency_graph, permissions,
    )

    proof_objects = {
        assertion_id: _dependency_closure(
            assertion_objects[assertion_id], dependency_graph,
        )
        for assertion_id in assertion_order
    }
    proof_requirements = {}
    for assertion_id in assertion_order:
        required_objects = frozenset(proof_objects[assertion_id])
        possible_senders = tuple(
            sender_id for sender_id in sender_order
            if required_objects <= permissions[sender_id]
        )
        if not possible_senders:
            raise ValueError(
                "No sender can provide the complete proof for assertion %r"
                % assertion_id,
            )
        if not _is_allowed(required_objects, forbidden_sets):
            raise ValueError(
                "The proof for assertion %r contains a forbidden object set"
                % assertion_id,
            )
        proof_requirements[assertion_id] = ProofRequirement(
            assertion_id,
            tuple(proof_objects[assertion_id]),
            possible_senders,
        )

    packages = _build_packages(
        assertion_order, proof_objects, permissions, forbidden_sets,
    )
    minimum_plans = _minimum_complete_plans(assertion_order, packages)
    single_sender_plans = tuple(
        plan for plan in minimum_plans if len(plan.senders) == 1
    )
    joint_receipt_plans = tuple(
        plan for plan in minimum_plans if len(plan.senders) > 1
    )
    single_sender_packages = {
        sender_id: tuple(
            package.package_id for package in packages
            if package.sender == sender_id
        )
        for sender_id in sender_order
    }

    return PackagePlanningResult(
        proof_requirements=tuple(
            proof_requirements[assertion_id]
            for assertion_id in assertion_order
        ),
        minimum_proof_sets=tuple(
            proof_requirements[assertion_id].object_ids
            for assertion_id in assertion_order
        ),
        packages=tuple(packages),
        mandatory_assertion_groups=_mandatory_groups(minimum_plans, packages),
        minimum_complete_plans=minimum_plans,
        minimum_single_sender_plans=single_sender_plans,
        minimum_joint_receipt_plans=joint_receipt_plans,
        single_sender_packages=single_sender_packages,
    )


def _normalize_assertions(assertions):
    if isinstance(assertions, dict):
        assertion_items = list(assertions.items())
    else:
        assertion_items = [_assertion_from_mapping(item) for item in assertions]

    if not assertion_items:
        return [], {}

    normalized = {}
    for assertion_id, object_ids in assertion_items:
        assertion_id = str(assertion_id)
        if assertion_id in normalized:
            raise ValueError("Duplicate assertion %r" % assertion_id)
        objects = frozenset(str(object_id) for object_id in object_ids)
        if not objects:
            raise ValueError(
                "Assertion %r requires at least one object" % assertion_id,
            )
        normalized[assertion_id] = objects

    return sorted(normalized), normalized


def _assertion_from_mapping(item):
    if isinstance(item, dict):
        assertion_id = item.get("id")
        object_ids = item.get("object_ids", item.get("objects"))
        if object_ids is None and item.get("type") == "relationship":
            object_ids = (
                item["id"], item["source_ref"], item["target_ref"],
            )
        if assertion_id is None or object_ids is None:
            raise ValueError("Assertion mappings require id and object_ids")
        return assertion_id, object_ids

    if isinstance(item, (list, tuple)) and len(item) == 2:
        return item

    raise TypeError("Unsupported assertion representation: %r" % (item,))


def _normalize_dependencies(dependencies):
    return {
        str(object_id): frozenset(
            str(dependency_id) for dependency_id in dependency_ids
        )
        for object_id, dependency_ids in dependencies.items()
    }


def _normalize_permissions(sender_permissions):
    if not sender_permissions:
        raise ValueError("At least one sender is required")

    sender_order = sorted(str(sender_id) for sender_id in sender_permissions)
    permissions = {
        sender_id: frozenset(
            str(object_id)
            for object_id in sender_permissions[sender_id]
        )
        for sender_id in sender_order
    }
    return sender_order, permissions


def _normalize_forbidden_sets(
    forbidden_together, dependency_graph, assertion_objects, permissions,
):
    known_objects = set(dependency_graph)
    for objects in assertion_objects.values():
        known_objects.update(objects)
    for objects in permissions.values():
        known_objects.update(objects)

    normalized = set()
    for object_set in forbidden_together:
        objects = frozenset(str(object_id) for object_id in object_set)
        if len(objects) < 2:
            raise ValueError(
                "Forbidden sets must contain at least two objects",
            )
        unknown = objects - known_objects
        if unknown:
            raise ValueError("Unknown forbidden objects: %s" % sorted(unknown))
        normalized.add(objects)

    return tuple(sorted(normalized, key=lambda objects: sorted(objects)))


def _validate_known_objects(
    assertion_order, assertion_objects, dependency_graph, permissions,
):
    distributable_objects = set()
    for objects in permissions.values():
        distributable_objects.update(objects)

    referenced_objects = set()
    for assertion_id in assertion_order:
        referenced_objects.update(assertion_objects[assertion_id])
    for dependency_ids in dependency_graph.values():
        referenced_objects.update(dependency_ids)
    referenced_objects.update(dependency_graph)

    unknown_objects = referenced_objects - distributable_objects
    if unknown_objects:
        raise ValueError(
            "Objects are not available through any sender: %s"
            % sorted(unknown_objects),
        )


def _dependency_closure(initial_objects, dependency_graph):
    closure = set()
    active = set()

    def visit(object_id):
        if object_id in closure:
            return
        if object_id in active:
            raise ValueError("Dependency cycle detected at %r" % object_id)

        active.add(object_id)
        for dependency_id in dependency_graph.get(object_id, ()):
            visit(dependency_id)
        active.remove(object_id)
        closure.add(object_id)

    for object_id in initial_objects:
        visit(object_id)

    return tuple(sorted(closure))


def _is_allowed(objects, forbidden_sets):
    return not any(
        forbidden_set <= objects for forbidden_set in forbidden_sets
    )


def _build_packages(
    assertion_order, proof_objects, permissions, forbidden_sets,
):
    packages = []
    package_number = 1

    for group_size in range(1, len(assertion_order) + 1):
        for assertion_group in combinations(assertion_order, group_size):
            objects = frozenset(
                object_id
                for assertion_id in assertion_group
                for object_id in proof_objects[assertion_id]
            )
            if not _is_allowed(objects, forbidden_sets):
                continue

            for sender_id in sorted(permissions):
                if objects <= permissions[sender_id]:
                    packages.append(PlannedPackage(
                        package_id="P%04d" % package_number,
                        sender=sender_id,
                        assertion_ids=assertion_group,
                        object_ids=tuple(sorted(objects)),
                    ))
                    package_number += 1

    if not packages:
        raise ValueError("No legal STIX package can be constructed")
    return packages


def _minimum_complete_plans(assertion_order, packages):
    required = frozenset(assertion_order)

    for package_count in range(1, len(assertion_order) + 1):
        plans = []

        def search(covered, selected):
            if len(selected) == package_count:
                if covered == required:
                    plans.append(tuple(selected))
                return

            uncovered = required - covered
            next_assertion = min(uncovered)
            for package in packages:
                package_assertions = frozenset(package.assertion_ids)
                if next_assertion not in package_assertions:
                    continue
                if package_assertions & covered:
                    continue
                search(
                    covered | package_assertions,
                    selected + [package],
                )

        search(frozenset(), [])
        if plans:
            return tuple(
                DeliveryPlan(
                    plan_id="D%04d" % plan_number,
                    package_ids=tuple(package.package_id for package in plan),
                    senders=tuple(sorted({package.sender for package in plan})),
                )
                for plan_number, plan in enumerate(plans, start=1)
            )

    raise ValueError("No complete delivery plan satisfies the constraints")


def _mandatory_groups(plans, packages):
    if not plans:
        return ()

    package_by_id = {package.package_id: package for package in packages}
    common_groups = None
    for plan in plans:
        groups = frozenset(
            package_by_id[package_id].assertion_ids
            for package_id in plan.package_ids
        )
        common_groups = groups if common_groups is None else common_groups & groups

    return tuple(
        tuple(sorted(group))
        for group in sorted(
            (group for group in common_groups if len(group) > 1),
            key=sorted,
        )
    )
