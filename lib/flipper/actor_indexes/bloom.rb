require 'set'
require 'flipper/bloom_filter'

module Flipper
  module ActorIndexes
    # Public: Local, in-memory implementation of the Flipper::ActorIndex
    # protocol. It keeps the precise allowlist (a Set) and a version-bound
    # Bloom filter over the same values in one process, so it can play both
    # the index and the precise list roles:
    #
    #   index = Flipper::ActorIndexes::Bloom.new(capacity: 100_000,
    #                                            false_positive_rate: 0.01)
    #   checker = Flipper::ActorIndex.new(index)
    #
    # Versions
    # --------
    # Every add/delete bumps a single version shared by index_version and
    # list_version, so the two sides are always consistent within this
    # process. If you snapshot the filter (or rebuild it in another process)
    # and the list keeps changing, the versions diverge and
    # Flipper::ActorIndex falls back to precise-only queries.
    #
    # Adds and deletes
    # ----------------
    # add inserts into both the precise set and the filter. Standard Bloom
    # filters cannot remove elements, so delete removes from the precise set
    # and rebuilds the filter from the remaining members; a deleted actor can
    # therefore never linger as a false positive in the new filter version.
    #
    # Memory and false positive rate
    # ------------------------------
    # The filter is sized for capacity elements at false_positive_rate using
    # the formulas documented on Flipper::BloomFilter (e.g. 0.01 costs
    # ~9.6 bits per actor, ~1.2 MB per 1M actors). If the list grows past
    # capacity, the filter is rebuilt with double the capacity so the target
    # false positive rate keeps holding. The precise Set dominates memory for
    # large lists; the filter itself stays tiny.
    class Bloom
      # Public: The current version. Bumped on every add/delete. Both
      # index_version and list_version read this same value.
      attr_reader :version

      # Public: The Bloom filter over the current members.
      attr_reader :filter

      # Public: Initializes an empty index.
      #
      # capacity            - Integer expected maximum number of actors.
      # false_positive_rate - Float target false positive rate for the filter.
      def initialize(capacity: 1_000, false_positive_rate: 0.01)
        @capacity = capacity
        @false_positive_rate = false_positive_rate
        @members = Set.new
        @filter = BloomFilter.build(capacity: @capacity, false_positive_rate: @false_positive_rate)
        @version = 0
      end

      # Public: Adds an actor value to the precise list and the filter, and
      # bumps the version. Grows (and rebuilds) the filter if the list
      # outgrows the capacity it was sized for.
      #
      # Returns true if the value was added, false if already present.
      def add(actor_value)
        value = actor_value.to_s
        return false if @members.include?(value)

        @members << value
        if @members.size > @capacity
          @capacity *= 2
          rebuild_filter
        else
          @filter.add(value)
        end
        bump_version
        true
      end

      # Public: Removes an actor value from the precise list and rebuilds the
      # filter without it (Bloom filters cannot delete), then bumps the
      # version.
      #
      # Returns true if the value was removed, false if it was not present.
      def delete(actor_value)
        value = actor_value.to_s
        return false unless @members.delete?(value)

        rebuild_filter
        bump_version
        true
      end

      # Public: The version of the probabilistic index (protocol method).
      def index_version
        @version
      end

      # Public: The version of the precise list (protocol method).
      def list_version
        @version
      end

      # Public: False means the actor is definitely not on the list; true
      # means it might be and must be confirmed precisely (protocol method).
      def might_include?(actor_value)
        @filter.include?(actor_value.to_s)
      end

      # Public: Authoritative membership check against the precise set
      # (protocol method).
      def include?(actor_value)
        @members.include?(actor_value.to_s)
      end

      # Public: The number of actors on the precise list.
      def size
        @members.size
      end

      # Public: Removes all actors, rebuilds the (now empty) filter and
      # bumps the version. Mirrors Feature#clear.
      #
      # Returns true.
      def clear
        @members.clear
        rebuild_filter
        bump_version
        true
      end

      # Public: Bytes of memory used by the Bloom filter bit storage.
      def memory_bytes
        @filter.memory_bytes
      end

      private

      def rebuild_filter
        @filter = BloomFilter.build(capacity: @capacity, false_positive_rate: @false_positive_rate)
        @members.each { |member| @filter.add(member) }
      end

      def bump_version
        @version += 1
      end
    end
  end
end
