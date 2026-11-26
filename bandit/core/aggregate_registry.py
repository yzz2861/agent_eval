#
# SPDX-License-Identifier: Apache-2.0
"""Default registry for aggregate objects with identity-bearing caches.

The lifecycle test is intentionally opt-in and conservative.  Aggregates are
often shared between functions, so guessing from a single assignment is not
enough: a type has to be registered either here, in the repository's Bandit
configuration, or in a module level registry in the scanned file.

Each entry may be a plain class name or a mapping with ``type`` and optional
``identity_fields``/``release_methods``/``publish_methods`` overrides.  Plain
names are matched against both the short class name and a qualified name.
"""

DEFAULT_AGGREGATE_OBJECTS = (
    {
        "type": "AggregationBuffer",
        "identity_fields": (
            "identity",
            "identities",
            "identity_cache",
            "_identity_cache",
            "subject",
            "subjects",
        ),
    },
    {
        "type": "AggregateBuffer",
    },
    {
        "type": "AggregateStats",
    },
    {
        "type": "AggregationStats",
    },
    {
        "type": "StatsAggregator",
    },
    {
        "type": "Aggregate",
    },
    {
        "type": "Aggregator",
    },
)


REGISTRY_CONSTANT_NAMES = frozenset(
    {
        "AGGREGATE_OBJECTS",
        "AGGREGATE_TYPES",
        "REGISTERED_AGGREGATES",
        "BANDIT_AGGREGATE_OBJECTS",
    }
)


DEFAULT_IDENTITY_FIELD_NAMES = frozenset(
    {
        "identity",
        "identities",
        "identity_cache",
        "_identity_cache",
        "_identity",
        "principal",
        "principals",
        "subject",
        "subjects",
        "user",
        "users",
        "user_id",
        "_user_id",
        "account",
        "accounts",
        "account_id",
        "_account_id",
        "tenant",
        "tenant_id",
        "_tenant_id",
        "member",
        "members",
        "customer",
        "customers",
        "email",
        "emails",
        "phone",
        "phone_number",
        "ssn",
        "token",
        "tokens",
        "secret",
        "secrets",
        "credential",
        "credentials",
    }
)


DEFAULT_RELEASE_METHODS = frozenset(
    {
        "clear",
        "clear_cache",
        "clear_identity",
        "clear_identity_cache",
        "clear_identities",
        "scrub",
        "purge",
        "release",
        "reset",
        "reset_cache",
        "reset_identity",
    }
)


DEFAULT_PUBLISH_METHODS = frozenset(
    {
        "publish",
        "publish_result",
        "publish_results",
        "emit",
        "export",
        "flush",
        "report",
    }
)
