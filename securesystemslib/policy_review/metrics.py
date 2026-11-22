"""Combinatorial metrics over a policy and concrete key ownership.

All functions in this module take a *concrete* ownership mapping of key id to
the set of domains holding it. Candidate ownership is resolved into concrete
mappings by :mod:`securesystemslib.policy_review.review` before calling here.

Two metrics are computed:

* minimum satisfying domains: the smallest set of domains that can produce at
  least one complete legal key combination (a set-cover problem);
* minimum blocking domains: the smallest set whose absence intersects every
  legal combination, so no release can be signed (a hitting-set problem).

Both are solved by exhaustive subset enumeration for the small, offline input
sizes involved. A cap guards against pathological inputs; when the cap is
hit the result is marked non-exhaustive rather than silently approximated.
"""

from __future__ import annotations

from itertools import combinations

from securesystemslib.policy_review.models import Metric, Policy, Witness

# A review with more than this many subsets to inspect is refused as
# non-exhaustive; the documents here are meant to be small and human-auditable.
MAX_SUBSET_CHECKS = 1_000_000


def minimum_satisfying_domains(
    policy: Policy, key_domains: dict[str, frozenset[str]]
) -> Metric:
    """Smallest number of domains that can satisfy some rule together."""
    available_domains = sorted({d for domains in key_domains.values() for d in domains})
    combos = sorted(
        policy.rule_index.keys(),
        key=lambda combo: (len(combo), sorted(combo)),
    )
    checks = 0
    for size in range(1, len(available_domains) + 1):
        for chosen in combinations(available_domains, size):
            checks += 1
            if checks > MAX_SUBSET_CHECKS:
                return Metric(None, None, False, "subset search cap exceeded")
            chosen_set = frozenset(chosen)
            for combo in combos:
                if _combo_covered(combo, chosen_set, key_domains):
                    witness = _satisfying_witness(
                        combo, chosen_set, key_domains, policy
                    )
                    return Metric(size, witness, True)
    return Metric(
        None,
        None,
        True,
        "no set of known domains holds a complete combination",
    )


def minimum_blocking_domains(
    policy: Policy, key_domains: dict[str, frozenset[str]]
) -> Metric:
    """Smallest number of domains whose absence blocks every combination."""
    available_domains = sorted({d for domains in key_domains.values() for d in domains})
    combos = list(policy.rule_index.keys())
    checks = 0
    for size in range(1, len(available_domains) + 1):
        for absent in combinations(available_domains, size):
            checks += 1
            if checks > MAX_SUBSET_CHECKS:
                return Metric(None, None, False, "subset search cap exceeded")
            absent_set = frozenset(absent)
            if all(
                _combo_hit(combo, absent_set, key_domains) for combo in combos
            ):
                relevant = _relevant_blocking_domains(combos, absent_set, key_domains)
                witness = _blocking_witness(
                    combos, frozenset(relevant), key_domains, policy
                )
                return Metric(len(relevant), witness, True)
    return Metric(
        None,
        None,
        True,
        "even removing every known domain does not block all combinations",
    )


def _combo_covered(
    combo: frozenset[str], chosen: frozenset[str], key_domains: dict[str,
        frozenset[str]]
) -> bool:
    for keyid in combo:
        if not (key_domains.get(keyid, frozenset()) & chosen):
            return False
    return True


def _combo_hit(
    combo: frozenset[str], absent: frozenset[str], key_domains: dict[str,
        frozenset[str]]
) -> bool:
    # A combination is blocked when at least one required key has every one of
    # its holding domains absent: that key cannot be supplied, so the whole
    # combination cannot be signed even if other keys remain available.
    for keyid in combo:
        holders = key_domains.get(keyid, frozenset())
        if not (holders - absent):
            return True
    return False


def _satisfying_witness(
    combo: frozenset[str],
    chosen: frozenset[str],
    key_domains: dict[str, frozenset[str]],
    policy: Policy,
) -> Witness:
    rule_ids = policy.rule_index[combo]
    covers: dict[str, dict[str, tuple[str, ...]]] = {}
    for rule_id in rule_ids:
        per_key: dict[str, tuple[str, ...]] = {}
        for keyid in sorted(combo):
            per_key[keyid] = tuple(sorted(key_domains.get(keyid, frozenset()) & chosen))
        covers[rule_id] = per_key
    key_to_domains = {
        keyid: tuple(sorted(key_domains.get(keyid,
            frozenset()) & chosen)) for keyid in sorted(combo)
    }
    return Witness(domains=chosen, covers=covers, key_to_domains=key_to_domains)


def _relevant_blocking_domains(
    combos: list[frozenset[str]],
    absent: frozenset[str],
    key_domains: dict[str, frozenset[str]],
) -> list[str]:
    # Drop an absent domain if removing it still leaves every combination
    # blocked: such a domain is redundant for the witness and would overstate
    # how many domains must genuinely be unavailable.
    relevant = set(absent)
    for domain in sorted(absent):
        trial = relevant - {domain}
        if all(_combo_hit(combo, frozenset(trial), key_domains) for combo in combos):
            relevant.remove(domain)
    return sorted(relevant)


def _blocking_witness(
    combos: list[frozenset[str]],
    absent: frozenset[str],
    key_domains: dict[str, frozenset[str]],
    policy: Policy,
) -> Witness:
    covers: dict[str, dict[str, tuple[str, ...]]] = {}
    relevant: set[str] = set()
    for combo in combos:
        for rule_id in policy.rule_index[combo]:
            per_key: dict[str, tuple[str, ...]] = {}
            for keyid in sorted(combo):
                removed = tuple(sorted(key_domains.get(keyid, frozenset()) & absent))
                if removed:
                    per_key[keyid] = removed
                    relevant.add(keyid)
            covers[rule_id] = per_key
    key_to_domains = {
        keyid: tuple(sorted(key_domains.get(keyid, frozenset()) & absent))
        for keyid in sorted(relevant)
    }
    return Witness(domains=absent, covers=covers, key_to_domains=key_to_domains)
