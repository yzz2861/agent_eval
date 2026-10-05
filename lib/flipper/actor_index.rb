require "digest"

module Flipper
  # Public: Optional protocol for indexing large actor whitelists.
  #
  # When a feature's actor set is huge, loading the entire set for every
  # check is wasteful. An actor index answers the cheaper question "is this
  # actor definitely NOT in the set?" so the exact set only needs to be
  # loaded for actors that might be members.
  #
  # An index is only ever a negative filter: a positive index result MUST
  # NOT enable a feature by itself. See Flipper::ActorMembership for the
  # resolver that combines an index with exact lookups and a fallback
  # strategy.
  #
  # Protocol
  #
  # An actor index responds to:
  #
  #   check(feature_key, actor_value, set_version:) -> Symbol
  #     Returns one of:
  #       :absent - the actor is definitely not in the set. Authoritative;
  #                 no exact query is needed.
  #       :maybe  - the actor might be in the set (true member or false
  #                 positive). An exact query against the authoritative
  #                 set is required before enabling anything.
  #       :stale  - the index was built against a different set version
  #                 than +set_version+. The caller must fall back to an
  #                 exact query and should re-sync the index.
  #
  #   track_add(feature_key, actor_value, set_version)
  #     Records that actor_value was added to the set whose new version is
  #     set_version.
  #
  #   track_remove(feature_key, actor_value, set_version)
  #     Records that actor_value was removed from the set whose new version
  #     is set_version.
  #
  #   sync(feature_key, members, set_version)
  #     Rebuilds the index for feature_key from the authoritative member
  #     list at the given version.
  #
  module ActorIndex
    # Public: Local, in-memory actor index backed by a version-bound
    # Bloom filter per feature.
    #
    # Memory and accuracy are controlled by two parameters:
    #
    #   size   - number of bits in each per-feature filter. Memory usage is
    #            size / 8 bytes per indexed feature.
    #   hashes - number of hash functions (k). More hashes lower the false
    #            positive rate up to the optimum k = (size / n) * ln(2),
    #            where n is the number of indexed members.
    #
    # The expected false positive rate is approximately:
    #
    #   (1 - e^(-k*n/m))^k
    #
    # Use Bloom.optimal to derive both parameters from an expected member
    # count and target false positive rate.
    #
    # Removal strategy: Bloom filters cannot unset bits, so track_remove
    # invalidates the feature's filter. The next check returns :stale and
    # the resolver falls back to an exact query, then rebuilds via sync.
    class Bloom
      # Internal: A single Bloom filter over actor values.
      class Filter
        attr_reader :size, :hashes

        def initialize(size:, hashes:)
          @size = Integer(size)
          @hashes = Integer(hashes)
          raise ArgumentError, "size must be positive" if @size < 1
          raise ArgumentError, "hashes must be positive" if @hashes < 1
          @bits = 0
        end

        def add(value)
          positions(value).each { |position| @bits |= (1 << position) }
          true
        end

        def maybe_include?(value)
          positions(value).all? { |position| (@bits & (1 << position)) != 0 }
        end

        private

        # Internal: Double hashing (Kirsch-Mitzenmacher) derived from one
        # SHA-256 digest, yielding +hashes+ positions in [0, size).
        def positions(value)
          digest = Digest::SHA256.digest(value.to_s)
          h1 = digest.byteslice(0, 8).unpack1("Q>")
          h2 = digest.byteslice(8, 8).unpack1("Q>")
          Array.new(@hashes) { |i| (h1 + i * h2) % @size }
        end
      end

      # Public: Build an index whose per-feature filters are sized for the
      # expected number of members and a target false positive rate.
      #
      #   Bloom.optimal(expected_members: 1_000_000, fpr: 0.01)
      #   # => ~9.6 bits per member, ~1.2 MB per feature at 1% FPR
      def self.optimal(expected_members:, fpr:)
        n = [Integer(expected_members), 1].max
        p = Float(fpr)
        raise ArgumentError, "fpr must be in (0, 1)" unless p > 0 && p < 1
        size = (-n * Math.log(p) / (Math.log(2)**2)).ceil
        hashes = [(size.to_f / n * Math.log(2)).round, 1].max
        new(size: size, hashes: hashes)
      end

      attr_reader :size, :hashes

      def initialize(size:, hashes:)
        @size = Integer(size)
        @hashes = Integer(hashes)
        @filters = {}
        @versions = {}
      end

      # Public: Approximate memory footprint in bytes of one indexed
      # feature's filter (size bits, packed).
      def bytes_per_feature
        (size / 8.0).ceil
      end

      def check(feature_key, actor_value, set_version:)
        filter = @filters[feature_key]
        return :stale if filter.nil?
        return :stale unless @versions[feature_key] == set_version

        filter.maybe_include?(actor_value) ? :maybe : :absent
      end

      def track_add(feature_key, actor_value, set_version)
        filter = @filters[feature_key]
        indexed_version = @versions[feature_key]
        if filter.nil? || (indexed_version != set_version && indexed_version != set_version - 1)
          # The index has no filter for the version this add builds on;
          # start a fresh filter containing only this member. Members added
          # before the index existed are picked up by the next sync.
          filter = (@filters[feature_key] = build_filter)
        end
        filter.add(actor_value)
        @versions[feature_key] = set_version
        true
      end

      def track_remove(feature_key, actor_value, set_version)
        # Bloom filters cannot unset bits. Invalidate the feature's filter
        # so the next check is :stale and the resolver falls back to an
        # exact query, then rebuilds from the authoritative set via sync.
        @filters.delete(feature_key)
        @versions.delete(feature_key)
        true
      end

      def sync(feature_key, members, set_version)
        filter = build_filter
        members.each { |member| filter.add(member) }
        @filters[feature_key] = filter
        @versions[feature_key] = set_version
        true
      end

      # Internal: The version the index currently holds for a feature, or
      # nil when the feature is not indexed. Exposed for tests and
      # diagnostics.
      def version_for(feature_key)
        @versions[feature_key]
      end

      private

      def build_filter
        Filter.new(size: size, hashes: hashes)
      end
    end
  end
end
