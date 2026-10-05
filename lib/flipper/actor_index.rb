module Flipper
  # Public: Optional allowlist index protocol for the actor gate.
  #
  # Features with very large actor allowlists are expensive to check when the
  # entire set has to be pulled on every enabled? call. An actor index avoids
  # that with a two-phase lookup:
  #
  #   1. A version-bound probabilistic index (e.g. a Bloom filter) answers
  #      "definitely not on the list" for most actors, so they are excluded
  #      without touching the precise list.
  #   2. Actors that might be on the list are confirmed with a precise
  #      membership query against the authoritative list.
  #
  # A positive index answer NEVER enables a feature by itself; it only
  # triggers a precise query, and the precise answer is the final decision.
  #
  # The protocol
  # ------------
  # The index object must respond to:
  #
  #   index_version                  -> value comparable with ==, changes
  #                                     whenever the index is rebuilt
  #   might_include?(actor_value)    -> false means definitely not listed,
  #                                     true means maybe listed
  #
  # The precise list object must respond to:
  #
  #   list_version                   -> value comparable with ==, changes
  #                                     whenever the list changes
  #   include?(actor_value)          -> authoritative membership check
  #
  # Fallback strategy
  # -----------------
  # The index is only trusted while index_version == list_version. When the
  # versions differ (the index is stale, e.g. it has not observed a recent
  # enable/disable), every check falls back to a precise query against the
  # authoritative list. The fallback always produces the correct answer; it
  # merely loses the filtering optimization until the index is rebuilt.
  #
  # Counting
  # --------
  # precise_queries, bloom_exclusions and fallbacks count how often each
  # branch ran since the last reset_counts, so behavior can be asserted in
  # tests and monitored in production.
  #
  # Examples
  #
  #   index = Flipper::ActorIndexes::Bloom.new(capacity: 100_000)
  #   checker = Flipper::ActorIndex.new(index)
  #   checker.include?("User;1") # => false, without any precise query
  #
  class ActorIndex
    # Public: The index object used for cheap exclusion.
    attr_reader :index

    # Public: The authoritative list object used for precise queries.
    attr_reader :list

    # Public: Number of precise membership queries performed.
    attr_reader :precise_queries

    # Public: Number of actors excluded by the index without a precise query.
    attr_reader :bloom_exclusions

    # Public: Number of checks that fell back to precise-only because the
    # index and list versions did not match.
    attr_reader :fallbacks

    # Public: Initializes a checker.
    #
    # index - Object responding to index_version and might_include?.
    # list  - Object responding to list_version and include?. Defaults to the
    #         index itself, for implementations like ActorIndexes::Bloom that
    #         keep the precise set and the index together.
    def initialize(index, list: index)
      @index = index
      @list = list
      reset_counts
    end

    # Public: The final, authoritative answer for whether the actor value is
    # on the allowlist. Uses the index to avoid precise queries when it is
    # safe to do so.
    #
    # Returns true if the actor is precisely on the list, false otherwise.
    def include?(actor_value)
      if stale?
        @fallbacks += 1
        return precise_include?(actor_value)
      end

      unless index.might_include?(actor_value)
        @bloom_exclusions += 1
        return false
      end

      precise_include?(actor_value)
    end

    # Public: Returns true when the index version does not match the precise
    # list version and checks will fall back to precise-only queries.
    def stale?
      index.index_version != list.list_version
    end

    # Public: Resets all counters to zero.
    def reset_counts
      @precise_queries = 0
      @bloom_exclusions = 0
      @fallbacks = 0
    end

    # Public: Forwards a new actor value to the underlying index/list so a
    # Feature can keep them in sync on enable. No-op when neither side
    # supports mutation (read-only indexes simply go stale and fall back).
    def add(actor_value)
      mutate(:add, actor_value)
    end

    # Public: Forwards a removed actor value to the underlying index/list.
    # See add.
    def delete(actor_value)
      mutate(:delete, actor_value)
    end

    # Public: Forwards a full clear to the underlying index/list. See add.
    def clear
      mutate(:clear)
    end

    private

    def precise_include?(actor_value)
      @precise_queries += 1
      list.include?(actor_value)
    end

    def mutate(operation, *args)
      [index, list].uniq.each do |target|
        target.public_send(operation, *args) if target.respond_to?(operation)
      end
      nil
    end
  end
end
