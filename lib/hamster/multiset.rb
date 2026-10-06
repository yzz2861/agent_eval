require "hamster/immutable"
require "hamster/undefined"
require "hamster/enumerable"
require "hamster/hash"
require "hamster/set"

module Hamster

  # +Hamster::Multiset+ (also known as a "bag") is an unordered collection of
  # values in which each value may appear any number of times. Where
  # {Hamster::Set} merges duplicates into a single member, a +Multiset+ tracks
  # the *multiplicity* (occurrence count) of every distinct value. This makes
  # it suitable for tasks such as computing the difference between two batches
  # of line items, where how many times each value occurs matters.
  #
  # A +Multiset+ is persistent and immutable: every "modifying" method returns
  # a new +Multiset+ which structurally shares its internal count table with
  # the original, so deriving many versions is cheap and never disturbs
  # existing ones.
  #
  # Multiplicities are always positive Integers. Values whose count drops to
  # zero are removed entirely, and negative or non-Integer counts are rejected
  # with an +ArgumentError+, so they can never leak into a result.
  #
  # Two size metrics are distinguished:
  #
  # - {#size} (aliased {#total_count}) is the total number of elements,
  #   counting each occurrence: the sum of all multiplicities.
  # - {#distinct_count} is the number of different values, ignoring
  #   multiplicities.
  #
  # Counts are stored as plain Integers keyed by value, so a value occurring a
  # billion times is still just one hash entry -- no billion-element structure
  # is ever allocated. Only explicit enumeration ({#each}, {#to_a}, and other
  # +Enumerable+ methods) expands multiplicities and yields values one by one.
  #
  # The bulk operations follow these multiplicity rules:
  #
  # - {#sum} (the + operator): multiplicities are added.
  # - {#union} (the | operator): the multiplicity of each value is the
  #   *maximum* of the two operands' multiplicities.
  # - {#intersection} (the & operator): the multiplicity of each value is the
  #   *minimum* of the two operands' multiplicities; values absent from either
  #   operand are absent from the result.
  # - {#difference} (the - operator): the other multiset's multiplicities are
  #   subtracted from this one's, truncated at zero (never negative).
  #
  # Each bulk operation accepts another +Multiset+, or a Ruby +Hash+ /
  # +Hamster::Hash+ mapping values to non-negative Integer counts.
  #
  # @example
  #   stock  = Hamster::Multiset.new([:apple, :apple, :pear])
  #   sold   = Hamster::Multiset[:apple, :pear, :pear]
  #   stock - sold                       # => Hamster::Multiset[:apple]
  #   stock.multiplicity(:apple)         # => 2
  #   stock.size                         # => 3
  #   stock.distinct_count               # => 2
  #   stock.add(:apple, 1_000_000_000).size  # => 1000000002
  #
  class Multiset
    include Immutable
    include Enumerable

    class << self
      # Create a new +Multiset+ populated with the given items. Each
      # occurrence of a duplicated item increases its multiplicity.
      #
      # @return [Multiset]
      def [](*items)
        items.empty? ? empty : new(items)
      end

      # Return an empty +Multiset+. If used on a subclass, returns an empty
      # instance of that class.
      #
      # @return [Multiset]
      def empty
        @empty ||= self.new
      end

      # Create a new +Multiset+ from a table of occurrence counts.
      #
      # @param counts [::Hash, Hamster::Hash] maps each value to its
      #   multiplicity. Counts must be non-negative Integers; zero counts are
      #   dropped, anything else raises +ArgumentError+.
      # @return [Multiset]
      def from_counts(counts)
        table = Hamster::Hash.empty
        size = 0
        counts.each do |item, count|
          validate_count!(count)
          next if count.zero?
          table = table.put(item, count)
          size += count
        end
        alloc(table, size)
      end

      # "Raw" allocation of a new +Multiset+. Used internally to create a new
      # instance quickly after obtaining a modified count table.
      #
      # @return [Multiset]
      # @private
      def alloc(counts = Hamster::Hash.empty, size = 0)
        allocate.tap do |multiset|
          multiset.instance_variable_set(:@counts, counts)
          multiset.instance_variable_set(:@size, size)
        end
      end

      # @private
      def validate_count!(count)
        unless count.is_a?(Integer) && count >= 0
          raise ArgumentError, "count must be a non-negative Integer, got #{count.inspect}"
        end
        count
      end

      # @private
      def coerce(other)
        case other
        when Multiset then other
        when ::Hash, Hamster::Hash then from_counts(other)
        else
          raise TypeError, "cannot convert #{other.class} into Hamster::Multiset"
        end
      end
    end

    def initialize(items = [])
      tally = ::Hash.new(0)
      size = 0
      items.each do |item|
        tally[item] += 1
        size += 1
      end
      @counts = Hamster::Hash.new(tally)
      @size = size
    end

    # Return +true+ if this +Multiset+ contains no elements.
    # @return [Boolean]
    def empty?
      @counts.empty?
    end

    # Return the total number of elements in this +Multiset+, counting each
    # occurrence of every value. This is the sum of all multiplicities, not
    # the number of distinct values (see {#distinct_count}).
    #
    # @return [Integer]
    def size
      @size
    end
    alias :length :size
    alias :total_count :size

    # Return the number of distinct values in this +Multiset+, ignoring
    # multiplicities.
    #
    # @return [Integer]
    def distinct_count
      @counts.size
    end

    # Return the number of times +item+ occurs in this +Multiset+ (its
    # multiplicity), or 0 if it is absent.
    #
    # @param item [Object] The value to look up
    # @return [Integer]
    def multiplicity(item)
      @counts.get(item) || 0
    end
    alias :occurrences :multiplicity

    # With an argument, return the multiplicity of +item+ (like
    # {#multiplicity}). Without an argument, return the total number of
    # elements (like {#size}). With a block, count the occurrences for which
    # the block returns true.
    #
    # @return [Integer]
    def count(item = Undefined)
      if item.equal?(Undefined)
        block_given? ? super() : @size
      else
        multiplicity(item)
      end
    end

    # Return +true+ if +item+ occurs at least once in this +Multiset+.
    #
    # @param item [Object] The value to check for
    # @return [Boolean]
    def include?(item)
      @counts.key?(item)
    end
    alias :member? :include?

    # Return a new +Multiset+ with +count+ additional occurrences of +item+.
    #
    # @param item [Object] The value to add
    # @param count [Integer] How many occurrences to add; must be a
    #   non-negative Integer
    # @return [Multiset]
    def add(item, count = 1)
      self.class.validate_count!(count)
      return self if count.zero?
      self.class.alloc(@counts.put(item, multiplicity(item) + count), @size + count)
    end
    alias :<< :add

    # Return a new +Multiset+ with up to +count+ occurrences of +item+
    # removed. The multiplicity is truncated at zero: removing more
    # occurrences than are present simply removes the value entirely. A value
    # whose count reaches zero no longer appears in the result at all.
    #
    # @param item [Object] The value to remove
    # @param count [Integer] How many occurrences to remove; must be a
    #   non-negative Integer
    # @return [Multiset]
    def remove(item, count = 1)
      self.class.validate_count!(count)
      current = multiplicity(item)
      return self if count.zero? || current.zero?
      remaining = current - count
      if remaining > 0
        self.class.alloc(@counts.put(item, remaining), @size - count)
      else
        self.class.alloc(@counts.delete(item), @size - current)
      end
    end

    # Return a new +Multiset+ with all occurrences of +item+ removed.
    #
    # @param item [Object] The value to remove entirely
    # @return [Multiset]
    def delete(item)
      current = multiplicity(item)
      return self if current.zero?
      self.class.alloc(@counts.delete(item), @size - current)
    end

    # Return a new +Multiset+ combining this one with +other+, where the
    # multiplicity of each value is the *sum* of the two multiplicities.
    #
    # @param other [Multiset, ::Hash, Hamster::Hash]
    # @return [Multiset]
    def sum(other)
      other = self.class.coerce(other)
      counts = @counts
      other.each_pair do |item, count|
        counts = counts.put(item, (counts.get(item) || 0) + count)
      end
      self.class.alloc(counts, @size + other.size)
    end
    alias :+ :sum

    # Return a new +Multiset+ combining this one with +other+, where the
    # multiplicity of each value is the *maximum* of the two multiplicities.
    #
    # @param other [Multiset, ::Hash, Hamster::Hash]
    # @return [Multiset]
    def union(other)
      other = self.class.coerce(other)
      counts = @counts
      size = @size
      other.each_pair do |item, count|
        current = counts.get(item) || 0
        if count > current
          counts = counts.put(item, count)
          size += count - current
        end
      end
      self.class.alloc(counts, size)
    end
    alias :| :union

    # Return a new +Multiset+ combining this one with +other+, where the
    # multiplicity of each value is the *minimum* of the two multiplicities.
    # Values absent from either operand are absent from the result.
    #
    # @param other [Multiset, ::Hash, Hamster::Hash]
    # @return [Multiset]
    def intersection(other)
      other = self.class.coerce(other)
      counts = Hamster::Hash.empty
      size = 0
      each_pair do |item, count|
        shared = other.multiplicity(item)
        shared = count if count < shared
        next if shared.zero?
        counts = counts.put(item, shared)
        size += shared
      end
      self.class.alloc(counts, size)
    end
    alias :& :intersection

    # Return a new +Multiset+ with +other+'s multiplicities subtracted from
    # this one's, truncated at zero: each value keeps
    # +max(0, self_count - other_count)+ occurrences, and values whose count
    # reaches zero are removed entirely. The result never contains negative
    # counts.
    #
    # @param other [Multiset, ::Hash, Hamster::Hash]
    # @return [Multiset]
    def difference(other)
      other = self.class.coerce(other)
      counts = Hamster::Hash.empty
      size = 0
      each_pair do |item, count|
        remaining = count - other.multiplicity(item)
        next if remaining <= 0
        counts = counts.put(item, remaining)
        size += remaining
      end
      self.class.alloc(counts, size)
    end
    alias :- :difference

    # Yield each value once for every time it occurs. A value with
    # multiplicity 3 is yielded 3 times. This is the only place where
    # multiplicities are expanded into individual elements; nothing is
    # expanded eagerly anywhere else. Returns an +Enumerator+ if no block is
    # given, so partial traversal (for example +multiset.each.first(5)+)
    # stays lazy even for huge multiplicities.
    #
    # @yield [item] once for each occurrence of each value
    # @return [self, Enumerator]
    def each
      return enum_for(:each) unless block_given?
      @counts.each do |item, count|
        count.times { yield item }
      end
      self
    end

    # Yield each distinct value together with its multiplicity, without
    # expanding occurrences. Returns an +Enumerator+ if no block is given.
    #
    # @yield [item, count] once for each distinct value
    # @return [self, Enumerator]
    def each_pair
      return enum_for(:each_pair) unless block_given?
      @counts.each { |item, count| yield item, count }
      self
    end

    # Return a Ruby +Array+ with every value repeated according to its
    # multiplicity. Unlike the internal storage, this *does* expand
    # multiplicities, so it allocates one array slot per occurrence.
    #
    # @return [Array]
    def to_a
      array = []
      each { |item| array << item }
      array
    end

    # Return a new Ruby +Hash+ mapping each distinct value to its
    # multiplicity.
    #
    # @return [::Hash]
    def to_hash
      hash = {}
      each_pair { |item, count| hash[item] = count }
      hash
    end
    alias :to_h :to_hash

    # Return a {Hamster::Set} of the distinct values in this +Multiset+.
    #
    # @return [Hamster::Set]
    def to_set
      Hamster::Set.new(@counts.each_key)
    end

    # Return +true+ if +other+ has the same type and the same values with the
    # same multiplicities as this +Multiset+.
    #
    # @param other [Object] The object to compare with
    # @return [Boolean]
    def eql?(other)
      return true if other.equal?(self)
      return false unless instance_of?(other.class)
      other_counts = other.instance_variable_get(:@counts)
      return false if @counts.size != other_counts.size
      @counts.each do |item, count|
        return false unless other_counts.get(item) == count
      end
      true
    end
    alias :== :eql?

    # See +Object#hash+.
    # @return [Integer]
    def hash
      @counts.hash
    end

    # @return [String]
    def inspect
      pairs = []
      each_pair { |item, count| pairs << "#{item.inspect} => #{count}" }
      "Hamster::Multiset[#{pairs.join(', ')}]"
    end
    alias :to_s :inspect

    # @private
    def marshal_dump
      to_hash
    end

    # @private
    def marshal_load(dictionary)
      tally = {}
      size = 0
      dictionary.each do |item, count|
        self.class.validate_count!(count)
        next if count.zero?
        tally[item] = count
        size += count
      end
      @counts = Hamster::Hash.new(tally)
      @size = size
    end
  end
end
