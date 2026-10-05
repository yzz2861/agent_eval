require 'digest'

module Flipper
  # Public: A Bloom filter: a space-efficient probabilistic set membership
  # structure. It can tell you that a value is DEFINITELY NOT in the set, or
  # that it MIGHT BE in the set. It never produces false negatives for values
  # that were added, but it can produce false positives for values that were
  # not. A positive answer must therefore always be confirmed against the
  # authoritative set before acting on it.
  #
  # Memory vs. false positive rate
  # ------------------------------
  # For a target capacity n and false positive rate p, the optimal bit array
  # size m and hash count k are:
  #
  #   m = -n * ln(p) / (ln 2)^2   bits  (~1.44 * log2(1/p) bits per element)
  #   k = (m / n) * ln 2                 (~log2(1/p) hash functions)
  #
  # Common operating points (bits per element / hash count):
  #
  #   p = 0.05   ->  6.2 bits/element, k = 4
  #   p = 0.01   ->  9.6 bits/element, k = 7   (1.2 MB per 1M actors)
  #   p = 0.001  -> 14.4 bits/element, k = 10  (1.8 MB per 1M actors)
  #   p = 0.0001 -> 19.2 bits/element, k = 13
  #
  # The false positive rate only holds while the number of added elements
  # stays at or below the capacity the filter was built for. Standard Bloom
  # filters also cannot delete elements; rebuild the filter from the
  # authoritative set when elements are removed (see
  # Flipper::ActorIndexes::Bloom, which does this for you).
  #
  # Examples
  #
  #   filter = Flipper::BloomFilter.build(capacity: 100_000, false_positive_rate: 0.01)
  #   filter.add("User;1")
  #   filter.include?("User;1") # => true
  #   filter.include?("User;2") # => false (almost certainly)
  #   filter.memory_bytes       # => 119892 (bytes of bit storage)
  #
  class BloomFilter
    LN2 = Math.log(2)
    LN2_SQUARED = LN2**2

    # Public: The number of bits in the filter.
    attr_reader :size

    # Public: The number of hash functions applied per value.
    attr_reader :hash_count

    # Public: Builds a filter sized for the given capacity and target false
    # positive rate using the optimal formulas documented above.
    #
    # capacity            - Integer maximum number of elements the target
    #                       false positive rate holds for.
    # false_positive_rate - Float between 0 and 1 (exclusive).
    #
    # Returns a Flipper::BloomFilter.
    def self.build(capacity:, false_positive_rate:)
      unless capacity.is_a?(Integer) && capacity >= 1
        raise ArgumentError, "capacity must be an Integer >= 1"
      end

      unless false_positive_rate.is_a?(Numeric) &&
             false_positive_rate > 0 && false_positive_rate < 1
        raise ArgumentError, "false_positive_rate must be between 0 and 1 (exclusive)"
      end

      size = (-capacity * Math.log(false_positive_rate) / LN2_SQUARED).ceil
      hash_count = (size / capacity.to_f * LN2).round
      new(size: size, hash_count: [hash_count, 1].max)
    end

    # Public: Initializes a filter with an explicit bit size and hash count.
    # Prefer .build unless you know exactly what you are doing.
    def initialize(size:, hash_count:)
      unless size.is_a?(Integer) && size >= 1
        raise ArgumentError, "size must be an Integer >= 1"
      end

      unless hash_count.is_a?(Integer) && hash_count >= 1
        raise ArgumentError, "hash_count must be an Integer >= 1"
      end

      @size = size
      @hash_count = hash_count
      @bits = 0
    end

    # Public: Adds a value to the filter. Values are stringified, matching how
    # Flipper stores actor identifiers.
    #
    # Returns self.
    def add(value)
      indexes(value).each { |index| @bits |= (1 << index) }
      self
    end

    # Public: Returns false if the value is definitely not in the set, true if
    # it might be. A true result is only a hint and must be confirmed against
    # the authoritative set.
    def include?(value)
      indexes(value).all? { |index| @bits[index] == 1 }
    end

    # Public: The number of bytes of memory used by the bit storage.
    def memory_bytes
      (size / 8.0).ceil
    end

    private

    # Internal: Maps a value to hash_count bit positions using double hashing
    # (Kirsch-Mitzenmacher) over two 64-bit halves of a SHA-256 digest, which
    # is statistically equivalent to using k independent hash functions.
    def indexes(value)
      first, second = Digest::SHA256.digest(value.to_s).unpack('Q>2')
      indexes = []
      hash_count.times do |i|
        indexes << (first + i * second) % size
      end
      indexes
    end
  end
end
