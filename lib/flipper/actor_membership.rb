module Flipper
  # Public: Resolves actor membership for a feature by combining an
  # optional actor index (see Flipper::ActorIndex) with exact queries
  # against the authoritative set.
  #
  # Decision rules:
  #
  #   :absent -> false, no exact query. The index only ever excludes.
  #   :maybe  -> exact query decides. An index hit NEVER enables a feature
  #              by itself; Bloom filter false positives are filtered out
  #              here.
  #   :stale  -> fallback: exact query decides, then the index is rebuilt
  #              from the authoritative set via sync so subsequent checks
  #              are cheap again.
  #
  # Every branch is countable through the stats hash, so callers can
  # verify the index is actually saving exact queries.
  #
  #   index     = Flipper::ActorIndex::Bloom.optimal(expected_members: 1_000_000, fpr: 0.01)
  #   versions  = Hash.new(0)
  #   stats     = Hash.new(0)
  #   checker   = Flipper::ActorMembership.new(
  #     index: index,
  #     loader: ->(feature_key) { adapter.get(feature).actors },
  #     versioner: ->(feature_key) { versions[feature_key] },
  #     stats: stats,
  #   )
  #   checker.enabled?("new_ui", "user;42")
  #
  class ActorMembership
    # Public: Stats keys incremented during resolution.
    COUNTERS = [
      :checks,         # total enabled? calls
      :index_absent,   # resolved as definitely-not-a-member by the index
      :index_maybe,    # index could not rule out; exact query required
      :index_stale,    # index version mismatch; fallback path taken
      :exact_queries,  # authoritative set loads (maybe + stale)
      :syncs,          # index rebuilds after a stale fallback
    ].freeze

    def initialize(index:, loader:, versioner:, stats: nil)
      @index = index
      @loader = loader
      @versioner = versioner
      @stats = stats
    end

    # Public: Returns true only when actor_value is an exact member of the
    # authoritative set for feature_key.
    def enabled?(feature_key, actor_value)
      increment(:checks)
      version = @versioner.call(feature_key)

      case @index.check(feature_key, actor_value, set_version: version)
      when :absent
        increment(:index_absent)
        false
      when :maybe
        increment(:index_maybe)
        exact_members(feature_key).include?(actor_value)
      else # :stale
        increment(:index_stale)
        members = exact_members(feature_key)
        @index.sync(feature_key, members, version)
        increment(:syncs)
        members.include?(actor_value)
      end
    end

    private

    def exact_members(feature_key)
      increment(:exact_queries)
      @loader.call(feature_key)
    end

    def increment(key)
      @stats[key] += 1 if @stats
    end
  end
end
