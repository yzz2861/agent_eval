"""
   Explicit policy rule composition.

   This module implements the building blocks for composing algorithm rules
   from multiple policies (built-in policies, custom policies, and command
   line overrides) into a single, deterministic rule set:

   - Every rule has a source (the policy it came from), a scope
     (client/server), a severity (info/warn/fail), and well-defined override
     relations.
   - Algorithm aliases and version ranges are normalized to one canonical id
     so that a rule hits every spelling of the same algorithm.
   - Merging semantics (documented in README.md):
       * Two rules for the same canonical target from the same precedence
         tier with different severities are a hard conflict (error).
       * Rules from different tiers resolve to the strictest severity.
       * Custom policies may only tighten inherited rules, unless the custom
         policy explicitly declares "allow_relaxation = true".
       * Command line rules are always explicit and take final precedence.
   - Invalid input (unknown algorithms, duplicate rules, illegal severities,
     contradictory fail/warn rules) is reported via PolicyValidationError
     before any scanning takes place.
"""
from typing import Dict, List, Optional, Tuple

from ssh_audit.algorithm import Algorithm
from ssh_audit.ssh2_kexdb import SSH2_KexDB


# Legal severities, ordered from most lenient to most strict.
SEVERITIES: Tuple[str, ...] = ('info', 'warn', 'fail')
SEVERITY_RANKS: Dict[str, int] = {'info': 1, 'warn': 2, 'fail': 3}

# Rule scopes.
SCOPES: Tuple[str, ...] = ('server', 'client')

# Algorithm types a rule may target.
ALG_TYPES: Tuple[str, ...] = ('kex', 'key', 'enc', 'mac')

# Precedence tiers.  Rules from higher tiers override lower tiers (subject to
# the tightening-only restriction for custom policies).
TIER_BUILTIN = 0
TIER_CUSTOM = 1
TIER_CLI = 2

# Maps normalized product tokens (usable in version constraints) to the
# Product.* display strings used by the Software class.
_PRODUCT_TOKENS: Dict[str, str] = {
    'openssh': 'OpenSSH',
    'dropbear': 'Dropbear SSH',
    'libssh': 'libssh',
    'tinyssh': 'TinySSH',
}

_CONSTRAINT_OPS: Tuple[str, ...] = ('<=', '>=', '==', '!=', '<', '>')


class PolicyValidationError(ValueError):
    '''Raised when a policy or rule is invalid (unknown algorithm, duplicate rule, illegal severity, contradictory fail/warn rules, etc.).  Detected before any scanning occurs.'''


class PolicyConflictError(PolicyValidationError):
    '''Raised when two policies at the same precedence tier define conflicting rules for the same canonical target.'''


class VersionConstraint:
    '''A normalized version constraint such as "openssh>=7.3,<9.0".  Normalization ensures that different spellings of the same range map to the same canonical id.'''

    def __init__(self, product: str, clauses: List[Tuple[str, str]]) -> None:
        self._product = product  # Product.* display string.
        self._clauses = sorted(clauses)  # Sorted so that the canonical form is stable.

    @staticmethod
    def parse(text: str) -> 'VersionConstraint':
        '''Parses a constraint string like "OpenSSH>=7.3,<9.0".  Raises PolicyValidationError on invalid input.'''
        product_token = ''
        rest = ''
        for op in _CONSTRAINT_OPS:
            if op in text:
                product_token, rest = text.split(op, 1)
                rest = op + rest
                break
        product_token = product_token.strip().lower()
        if product_token not in _PRODUCT_TOKENS:
            raise PolicyValidationError("invalid product in version constraint: %s (valid products: %s)" % (text, ', '.join(sorted(_PRODUCT_TOKENS.keys()))))

        clauses = []
        for clause in rest.split(','):
            clause = clause.strip()
            op = ''
            version = ''
            for candidate in _CONSTRAINT_OPS:
                if clause.startswith(candidate):
                    op = candidate
                    version = clause[len(candidate):].strip()
                    break
            if len(op) == 0 or len(version) == 0:
                raise PolicyValidationError("invalid version constraint clause: %s" % clause)
            clauses.append((op, version))

        if len(clauses) == 0:
            raise PolicyValidationError("invalid version constraint: %s" % text)
        return VersionConstraint(_PRODUCT_TOKENS[product_token], clauses)

    @property
    def canonical(self) -> str:
        '''Returns the normalized id for this constraint (i.e.: "openssh:<7.3,>=7.0").'''
        return "%s:%s" % (self._product.lower(), ','.join("%s%s" % (op, version) for op, version in self._clauses))

    def matches(self, software: Optional[object]) -> bool:
        '''Returns True if the given Software object matches this constraint.  Unknown software never matches.'''
        if software is None:
            return False
        if getattr(software, 'product', None) != self._product:
            return False
        for op, version in self._clauses:
            comparison = software.compare_version(version)  # type: ignore[attr-defined]
            if op == '<' and not comparison < 0:
                return False
            if op == '<=' and not comparison <= 0:
                return False
            if op == '>' and not comparison > 0:
                return False
            if op == '>=' and not comparison >= 0:
                return False
            if op == '==' and not comparison == 0:
                return False
            if op == '!=' and not comparison != 0:
                return False
        return True

    def __str__(self) -> str:
        return self.canonical


class PolicyRule:
    '''One algorithm rule with full provenance: source policy, scope, severity, and precedence tier.'''

    def __init__(self, severity: str, scope: str, alg_type: Optional[str], algorithm: str, version_constraint: Optional[VersionConstraint], source: str, tier: int, spec: str) -> None:
        if severity not in SEVERITY_RANKS:
            raise PolicyValidationError("invalid severity: %s (valid severities: %s)" % (severity, ', '.join(SEVERITIES)))
        if scope not in SCOPES:
            raise PolicyValidationError("invalid scope: %s (valid scopes: %s)" % (scope, ', '.join(SCOPES)))
        if alg_type is not None and alg_type not in ALG_TYPES:
            raise PolicyValidationError("invalid algorithm type: %s (valid types: %s)" % (alg_type, ', '.join(ALG_TYPES)))
        self.severity = severity
        self.scope = scope
        self.alg_type = alg_type  # May be None until resolved against the algorithm database.
        self.algorithm = algorithm  # Canonical algorithm id.
        self.version_constraint = version_constraint
        self.source = source
        self.tier = tier
        self.spec = spec  # The original rule text, for output provenance.
        self.contributors: List[str] = [source]  # All policies that contributed to the final severity.

    @property
    def key(self) -> Tuple[str, Optional[str], str, Optional[str]]:
        '''The canonical identity of this rule's target.  Two rules with the same key refer to the same target, regardless of spelling.'''
        constraint = self.version_constraint.canonical if self.version_constraint is not None else None
        return (self.scope, self.alg_type, self.algorithm, constraint)

    def __str__(self) -> str:
        return "%s (source: %s)" % (self.spec, self.source)


def _split_rule_spec(spec: str) -> Tuple[Optional[str], Optional[str], Optional[str], str, Optional[VersionConstraint]]:
    '''Splits a rule spec of the form "[severity:][scope:][type:]algorithm[@constraint]" into its components.'''

    severity = None
    scope = None
    alg_type = None

    remainder = spec.strip()
    if len(remainder) == 0:
        raise PolicyValidationError("empty rule specification")

    # Peel off any leading severity/scope/type tokens.
    tokens = remainder.split(':')
    consumed = 0
    for token in tokens[:-1]:
        normalized = token.strip().lower()
        if normalized in SEVERITY_RANKS and severity is None and scope is None and alg_type is None:
            severity = normalized
        elif normalized in SCOPES and scope is None and alg_type is None:
            scope = normalized
        elif normalized in ALG_TYPES and alg_type is None:
            alg_type = normalized
        else:
            break
        consumed += 1
    remainder = ':'.join(tokens[consumed:]).strip()
    if len(remainder) == 0:
        raise PolicyValidationError("rule specification is missing an algorithm: %s" % spec)

    # Algorithm names never contain ':', so any remaining colon means an unrecognized leading token (i.e.: a misspelled severity, scope, or type).
    if ':' in remainder:
        bad_token = remainder.split(':', 1)[0].strip()
        raise PolicyValidationError("invalid token '%s' in rule specification: %s (valid severities: %s; valid scopes: %s; valid types: %s)" % (bad_token, spec, ', '.join(SEVERITIES), ', '.join(SCOPES), ', '.join(ALG_TYPES)))

    # Split off an optional version constraint.  Note that algorithm names
    # themselves may contain '@' (i.e.: "sntrup761x25519-sha512@openssh.com"),
    # so the text after the '@' is only treated as a version constraint when
    # it contains a comparison operator.
    version_constraint = None
    algorithm = remainder
    if '@' in remainder:
        algorithm_part, constraint_text = remainder.split('@', 1)
        if any(op in constraint_text for op in ('<', '>', '=')):
            algorithm = algorithm_part.strip()
            version_constraint = VersionConstraint.parse(constraint_text.strip())

    if len(algorithm) == 0:
        raise PolicyValidationError("rule specification is missing an algorithm: %s" % spec)

    return severity, scope, alg_type, algorithm, version_constraint


def parse_algorithm_rules(value: str, severity: Optional[str], source: str, tier: int, default_scope: str) -> List[PolicyRule]:
    '''Parses a comma-separated list of rule specifications into fully-resolved PolicyRule objects.  Validates severities, scopes, types, and algorithm names (against the algorithm database) and resolves aliases to canonical ids.  Raises PolicyValidationError on any invalid input.'''

    if severity is not None and severity not in SEVERITY_RANKS:
        raise PolicyValidationError("invalid severity: %s (valid severities: %s)" % (severity, ', '.join(SEVERITIES)))

    alg_db = SSH2_KexDB.get_db()
    rules: List[PolicyRule] = []
    for spec in value.split(','):
        spec = spec.strip()
        if len(spec) == 0:
            continue

        parsed_severity, parsed_scope, parsed_type, algorithm, version_constraint = _split_rule_spec(spec)

        rule_severity = severity if severity is not None else parsed_severity
        if rule_severity is None:
            raise PolicyValidationError("rule is missing a severity (use a fail:/warn:/info: prefix): %s" % spec)
        if severity is not None and parsed_severity is not None and parsed_severity != severity:
            raise PolicyValidationError("rule severity (%s) does not match its directive (%s): %s" % (parsed_severity, severity, spec))

        rule_scope = parsed_scope if parsed_scope is not None else default_scope
        canonical = Algorithm.canonical_id(algorithm)

        # Resolve the algorithm type(s) when not explicitly given.
        resolved_types: List[str] = []
        if parsed_type is not None:
            resolved_types = [parsed_type]
        else:
            resolved_types = [alg_type for alg_type in ALG_TYPES if canonical in alg_db[alg_type]]

        # Validate the algorithm against the database (post-canonicalization).
        for alg_type in resolved_types:
            if canonical not in alg_db[alg_type]:
                raise PolicyValidationError("unknown %s algorithm in rule: %s" % (alg_type, algorithm))
        if len(resolved_types) == 0:
            raise PolicyValidationError("unknown algorithm in rule: %s" % algorithm)

        for alg_type in resolved_types:
            rules.append(PolicyRule(rule_severity, rule_scope, alg_type, canonical, version_constraint, source, tier, spec))

    return rules


def validate_rules(rules: List[PolicyRule], source: str) -> None:
    '''Validates one policy's rules as a set: duplicate rules and contradictory fail/warn rules (same canonical target) are errors.  Raises PolicyValidationError.'''

    seen: Dict[Tuple[str, Optional[str], str, Optional[str]], PolicyRule] = {}
    for rule in rules:
        if rule.key in seen:
            existing = seen[rule.key]
            if existing.severity == rule.severity:
                raise PolicyValidationError("duplicate rule in policy %s: %s conflicts with %s" % (source, rule.spec, existing.spec))
            raise PolicyValidationError("contradictory rules in policy %s: '%s' (%s) conflicts with '%s' (%s)" % (source, rule.spec, rule.severity, existing.spec, existing.severity))
        seen[rule.key] = rule


def compose_rule_sets(sources: List[Tuple[int, str, List[PolicyRule], bool]]) -> Dict[Tuple[str, Optional[str], str, Optional[str]], PolicyRule]:
    '''Merges rule sets from multiple policies into one deterministic rule set.

    Each entry in `sources` is a tuple of (tier, source name, rules, allow_relaxation), ordered from the lowest precedence tier to the highest.

    Merge semantics:
      - Same tier, same canonical target, different severities: PolicyConflictError.
      - Different tiers: the strictest severity wins (documented behavior).
      - A custom policy may only tighten inherited rules; weakening a rule inherited from a lower tier requires the custom policy to declare allow_relaxation.
      - Command line rules (TIER_CLI) are explicit user intent and always win.

    The returned rules carry full provenance (source policy and original rule text, plus all contributing sources).'''

    merged: Dict[Tuple[str, Optional[str], str, Optional[str]], PolicyRule] = {}
    for tier, source, rules, allow_relax in sources:
        for rule in rules:
            rule.source = source
            rule.tier = tier
            rule.contributors = [source]

            if rule.key not in merged:
                merged[rule.key] = rule
                continue

            existing = merged[rule.key]

            # Same tier: identical severities merge provenance; differing severities are a hard conflict.
            if existing.tier == rule.tier:
                if existing.severity != rule.severity:
                    raise PolicyConflictError("conflicting rules at the same precedence level: '%s' (%s, from %s) vs '%s' (%s, from %s)" % (existing.spec, existing.severity, existing.source, rule.spec, rule.severity, rule.source))
                if rule.source not in existing.contributors:
                    existing.contributors.append(rule.source)
                continue

            # Command line rules are explicit and always win.
            if rule.tier == TIER_CLI:
                merged[rule.key] = rule
                continue
            if existing.tier == TIER_CLI:
                continue

            # A higher-tier rule from a policy that explicitly allows relaxation wins outright.
            if allow_relax and rule.tier > existing.tier:
                merged[rule.key] = rule
                continue

            # Otherwise the strictest severity wins, regardless of tier.
            if SEVERITY_RANKS[rule.severity] > SEVERITY_RANKS[existing.severity]:
                merged[rule.key] = rule
            else:
                if rule.source not in existing.contributors:
                    existing.contributors.append(rule.source)

    return merged
