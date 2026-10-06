require "hamster/immutable"
require "hamster/enumerable"
require "hamster/trie"
require "hamster/undefined"
require "hamster/set"

module Hamster
  # `Hamster::Multiset` is an unordered collection which records the number of
  # times each distinct value occurs. Values are compared using `#hash` and
  # `#eql?`, just as with {Set}.
  #
  # All counts are non-negative integers. Reducing a count to zero removes the
  # value from the multiset; {#difference} truncates subtraction at zero rather
  # than producing negative multiplicities.
  #
  # {#size} counts every occurrence, while {#distinct_size} counts only distinct
  # values. Internal storage keeps one entry per distinct value, so a value can
  # have a very large count without allocating that many elements. Occurrences
  # are yielded individually only by {#each} or another expanded enumeration.
  #
  # @example
  #   multiset = Hamster::Multiset.new([1, 1, 2])
  #   multiset.count(1)        # => 2
  #   multiset.size            # => 3
  #   multiset.distinct_size   # => 2
  #
  class Multiset
    include Immutable
    include Enumerable

    class << self
      # Create a new `Multiset` from items, where duplicate items increase
      # counts. A Ruby `Hash` is interpreted as an explicit map of values to
      # counts.
      # @return [Multiset]
      def [](*items)
        return empty if items.empty?
        return new(items.first) if items.size == 1 && count_map?(items.first)
        new(items)
      end

      # Create a new `Multiset` from an `Enumerable` of `[value, count]` pairs.
      # Zero counts are omitted, and pairs with the same value are summed.
      # @return [Multiset]
      def from_counts(pairs)
        alloc(build_trie(pairs))
      end

      # Return an empty `Multiset`. If used on a subclass, returns an empty
      # instance of that class.
      # @return [Multiset]
      def empty
        @empty ||= alloc(EmptyTrie)
      end

      # @private
      def alloc(trie = EmptyTrie)
        allocate.tap do |multiset|
          multiset.instance_variable_set(:@trie, trie)
          multiset.instance_variable_set(:@total_size, trie.reduce(0) { |sum, (_, count)| sum + count })
          multiset.send(:immutable!)
        end
      end

      private

      def count_map?(object)
        object.is_a?(::Hash) || (defined?(Hamster::Hash) && object.is_a?(Hamster::Hash))
      end

      def validate_count(count)
        unless count.is_a?(::Integer) && count >= 0
          raise ArgumentError, "count must be a non-negative Integer"
        end
        count
      end

      def build_trie(pairs)
        trie = Trie.new(0)
        pairs.each do |value, count|
          count = validate_count(count)
          next if count.zero?
          entry = trie.get(value)
          trie.put!(value, entry ? entry[1] + count : count)
        end
        trie
      end
    end

    def initialize(items = [])
      @trie = Trie.new(0)
      @total_size = 0

      if self.class.send(:count_map?, items)
        items.each_pair { |item, count| add_count!(item, count) }
      else
        items.each { |item| add_count!(item, 1) }
      end
    end

    # Return `true` if this multiset contains no occurrences.
    # @return [Boolean]
    def empty?
      @trie.empty?
    end

    # Return the total number of occurrences, including duplicates.
    # @return [Integer]
    def size
      @total_size
    end
    alias :length :size

    # Without an argument, return the total number of occurrences. With an
    # item, return its multiplicity. With a block, count expanded occurrences.
    # @return [Integer]
    def count(item = Undefined, &block)
      return multiplicity(item) unless item.equal?(Undefined)
      block ? super(&block) : size
    end

    # Return the number of distinct values with positive counts.
    # @return [Integer]
    def distinct_size
      @trie.size
    end

    # Return the multiplicity of `item`, or zero when it is absent.
    # @return [Integer]
    def multiplicity(item)
      entry = @trie.get(item)
      entry ? entry[1] : 0
    end
    alias :count_for :multiplicity

    # Return a new `Multiset` with the multiplicity of `item` increased by
    # `amount`.
    #
    # @param item [Object] The value to add
    # @param amount [Integer] A non-negative number of occurrences
    # @return [Multiset]
    def add(item, amount = 1)
      amount = validate_count(amount)
      return self if amount.zero?
      update_count(item, multiplicity(item) + amount)
    end
    alias :<< :add
    alias :increment :add

    # Return a new `Multiset` with the multiplicity of `item` decreased by
    # `amount`. Counts cannot become negative, so a decrease larger than the
    # current multiplicity removes the item.
    #
    # @param item [Object] The value to remove occurrences of
    # @param amount [Integer] A non-negative number of occurrences
    # @return [Multiset]
    def decrement(item, amount = 1)
      amount = validate_count(amount)
      current = multiplicity(item)
      return self if amount.zero? || current.zero?
      update_count(item, current > amount ? current - amount : 0)
    end
    alias :remove :decrement

    # Set the multiplicity of `item` to `count`. A count of zero removes it.
    #
    # @param item [Object] The value whose count should be set
    # @param count [Integer] A non-negative integer
    # @return [Multiset]
    def put(item, count)
      count = validate_count(count)
      return self if multiplicity(item) == count
      update_count(item, count)
    end
    alias :set_count :put

    # Return a new `Multiset` with every occurrence of `item` removed.
    # @return [Multiset]
    def delete(item)
      return self unless include?(item)
      new_trie(@trie.delete(item), -multiplicity(item))
    end

    # Yield each distinct value once, regardless of its multiplicity.
    # @return [self, Enumerator]
    def each_distinct
      return enum_for(:each_distinct) unless block_given?
      @trie.each { |item, _| yield(item) }
      self
    end
    alias :each_unique :each_distinct

    # Yield each `[value, count]` pair once.
    # @return [self, Enumerator]
    def each_pair
      return enum_for(:each_pair) unless block_given?
      @trie.each { |pair| yield(pair) }
      self
    end
    alias :each_with_count :each_pair

    # Yield each occurrence. A value with count *n* is yielded *n* times. This
    # is the only common operation that performs work proportional to the
    # total multiplicity; it does not allocate the occurrences up front.
    # @return [self, Enumerator]
    def each
      return to_enum(:each) unless block_given?
      @trie.each do |item, count|
        count.times { yield(item) }
      end
      self
    end

    # Like {#each}, but in the reverse order used for distinct values.
    # @return [self, Enumerator]
    def reverse_each
      return enum_for(:reverse_each) unless block_given?
      @trie.reverse_each do |item, count|
        count.times { yield(item) }
      end
      self
    end

    # Return a new `Multiset` containing distinct values for which the block
    # returns true, retaining their multiplicities.
    # @return [Multiset]
    def select
      return enum_for(:select) unless block_given?
      pairs = []
      @trie.each do |item, count|
        pairs << [item, count] if yield(item)
      end
      self.class.from_counts(pairs)
    end
    alias :find_all :select

    # Map distinct values once. The resulting multiset retains the original
    # multiplicity of each mapped value, merging duplicates.
    # @return [Multiset]
    def map
      return enum_for(:map) unless block_given?
      pairs = []
      @trie.each { |item, count| pairs << [yield(item), count] }
      self.class.from_counts(pairs)
    end
    alias :collect :map

    # Return `true` if `item` has a positive multiplicity.
    # @return [Boolean]
    def include?(item)
      @trie.key?(item)
    end
    alias :member? :include?

    # Return the first distinct value yielded by {#each_distinct}.
    # @return [Object, nil]
    def first
      entry = @trie.at(0)
      entry && entry[0]
    end

    # Add multiplicities. For every value the result count is the sum of the
    # counts from both collections.
    # @return [Multiset]
    def add_multiset(other)
      combine(coerce(other)) { |left, right| left + right }
    end

    # Multiset sum: add the multiplicities from both collections.
    # @return [Multiset]
    def +(other)
      add_multiset(other)
    end
    alias :merge :+

    # Multiset union: the result count for each value is the larger of its
    # counts in the two collections.
    # @return [Multiset]
    def union(other)
      combine(coerce(other)) { |left, right| [left, right].max }
    end
    alias :| :union

    # Multiset intersection: the result count for each value is the smaller of
    # its counts in the two collections. Values absent from either collection
    # are omitted.
    # @return [Multiset]
    def intersection(other)
      other = coerce(other)
      small, large = ordered_by_distinct_size(other)
      pairs = []
      small.each_pair do |item, count|
        other_count = large.multiplicity(item)
        pairs << [item, [count, other_count].min] if other_count > 0
      end
      self.class.from_counts(pairs)
    end
    alias :& :intersection

    # Truncated multiset difference: the result count is this multiset's count
    # minus `other`'s count, clamped at zero. Negative counts are never made.
    # @return [Multiset]
    def difference(other)
      other = coerce(other)
      pairs = []
      @trie.each do |item, count|
        remaining = count - other.multiplicity(item)
        pairs << [item, remaining] if remaining > 0
      end
      self.class.from_counts(pairs)
    end
    alias :- :difference
    alias :subtract :difference
    alias :truncated_difference :difference

    # Return a copy of the distinct values as a Ruby `Set`.
    # @return [Set]
    def to_set
      Set.new(each_distinct)
    end

    # Return a Ruby `Hash` mapping each distinct value to its count.
    # @return [Hash]
    def to_counts
      result = {}
      @trie.each { |item, count| result[item] = count }
      result
    end
    alias :to_h :to_counts

    # Return an empty multiset of the same class.
    # @return [Multiset]
    def clear
      self.class.empty
    end

    # Return true if `other` has the same type and multiplicities.
    # @return [Boolean]
    def eql?(other)
      return true if equal?(other)
      return false unless instance_of?(other.class)
      @trie.eql?(other.instance_variable_get(:@trie))
    end
    alias :== :eql?

    # See `Object#hash`.
    # @return [Integer]
    def hash
      each_pair.reduce(0) do |value, (item, count)|
        (value << 32) - value + item.hash + count.hash
      end
    end

    undef :"<=>"
    undef :each_index

    # @return [String]
    def inspect
      "#{self.class}[#{to_counts.inspect[1...-1]}]"
    end

    # @private
    def pretty_print(pp)
      pp.group(1, "#{self.class}[", "]") do
        pp.breakable ''
        pp.seplist(each_pair, nil, -> { pp.text(', ') }) do |item, count|
          pp.pp(item)
          pp.text(' => ')
          pp.pp(count)
        end
      end
    end

    # @private
    def marshal_dump
      to_counts
    end

    # @private
    def marshal_load(counts)
      @trie = self.class.send(:build_trie, counts)
      @total_size = @trie.reduce(0) { |sum, (_, count)| sum + count }
      immutable!
    end

    private

    def validate_count(count)
      self.class.send(:validate_count, count)
    end

    def add_count!(item, count)
      count = validate_count(count)
      return if count.zero?
      @trie.put!(item, multiplicity(item) + count)
      @total_size += count
    end

    def update_count(item, count)
      trie = count.zero? ? @trie.delete(item) : @trie.put(item, count)
      new_trie(trie, count - multiplicity(item))
    end

    def new_trie(trie, size_delta)
      if trie.empty?
        self.class.empty
      elsif trie.equal?(@trie) || size_delta.zero?
        self
      else
        self.class.alloc(trie)
      end
    end

    def coerce(other)
      return other if other.is_a?(Multiset)
      self.class.new(other)
    end

    def ordered_by_distinct_size(other)
      if distinct_size <= other.distinct_size
        [self, other]
      else
        [other, self]
      end
    end

    def combine(other)
      small, large = ordered_by_distinct_size(other)
      trie = large.instance_variable_get(:@trie)
      small.each_pair do |item, count|
        entry = trie.get(item)
        new_count = entry ? yield(entry[1], count) : count
        trie = new_count.zero? ? trie.delete(item) : trie.put(item, new_count)
      end
      self.class.alloc(trie)
    end
  end

  EmptyMultiset = Hamster::Multiset.empty
end
