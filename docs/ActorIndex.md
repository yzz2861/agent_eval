# Actor Index (optional whitelist index protocol)

When a feature's actor whitelist is very large, loading the whole set on
every check is wasteful. The actor index protocol lets you front the exact
set with a cheap, version-bound Bloom filter that answers one question:
"is this actor **definitely not** in the set?"

## Components

- `Flipper::ActorIndex::Bloom` — local, in-memory index. One Bloom filter
  per feature, bound to the version of the authoritative set it was built
  from.
- `Flipper::ActorMembership` — resolver that combines any index with the
  authoritative set and counts every decision path.

## Decision rules

1. Index says `:absent` → the actor is disabled, **no exact query**.
2. Index says `:maybe` → an exact query against the authoritative set
   decides. **A Bloom filter hit never enables a feature by itself** —
   false positives are filtered out by the exact query.
3. Index says `:stale` (index version ≠ set version) → explicit fallback:
   the exact set decides, then the index is rebuilt via `sync` so later
   checks are cheap again.

## Adds and removes

- `track_add` folds the new member into the filter when it chains onto the
  indexed version (adds are Bloom-filter-safe).
- `track_remove` invalidates the feature's filter — Bloom filters cannot
  unset bits — so the next check falls back to an exact query and the
  index is rebuilt from the authoritative set. Removals are therefore
  always exact, never approximate.

## Memory and false positive rate

Each indexed feature costs `size / 8` bytes. The expected false positive
rate is approximately `(1 - e^(-k*n/m))^k`, where `m` = `size` (bits),
`k` = `hashes`, and `n` = member count. Use `Bloom.optimal` to derive both
parameters:

    index = Flipper::ActorIndex::Bloom.optimal(expected_members: 1_000_000, fpr: 0.01)
    index.size              # => 9_585_059 bits (~1.14 MB per feature)
    index.hashes            # => 7
    index.bytes_per_feature # => 1_198_133

Rule of thumb: ~9.6 bits per member buys a 1% false positive rate; ~14.4
bits buys 0.1%. False positives only cost one exact query — they never
change the final decision.

## Usage

    index    = Flipper::ActorIndex::Bloom.optimal(expected_members: 1_000_000, fpr: 0.01)
    versions = Hash.new(0) # bump on every actor enable/disable
    stats    = Hash.new(0)

    checker = Flipper::ActorMembership.new(
      index: index,
      loader: ->(feature_key) { Flipper::GateValues.new(adapter.get(feature)).actors },
      versioner: ->(feature_key) { versions[feature_key] },
      stats: stats,
    )

    checker.enabled?("new_ui", "user;42")
    stats # => { checks: 1, index_absent: 1, ... } — countable savings

See `spec/flipper/actor_index_spec.rb` and
`spec/flipper/actor_membership_spec.rb` for countable examples, including
forced false positives proving the exact set remains the final authority.
