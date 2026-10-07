require "hamster/immutable"
require "hamster/hash"
require "hamster/set"
require "hamster/vector"

module Hamster
  # `Hamster::DisjointSet` is a persistent union-find (disjoint-set) data
  # structure. It tracks a collection of elements partitioned into disjoint
  # groups, supporting near-constant-time membership tests between elements
  # ({#connected?}) and merging of groups ({#union}).
  #
  # Like Hamster's other collections, a `DisjointSet` is immutable: every
  # operation which conceptually "modifies" the set returns a new version and
  # leaves the receiver untouched. Successive versions share their internal
  # structure, so keeping many branches (for example, alternative merge
  # histories produced by a background rule-merging process) is cheap, and no
  # branch can ever observe another branch's changes.
  #
  # Equivalency of elements follows the same key semantics as
  # `Hamster::Hash`: two objects which are `#eql?` and have the same
  # `#hash` code are the same element, even if they are not identical
  # objects.
  #
  # Merging is done by partition size (union by rank), which keeps trees
  # shallow. Path compression is never performed behind your back: read-only
  # queries such as {#find} and {#connected?} leave the internal structure
  # exactly as it was. Compression only happens in new versions explicitly
  # returned by {#union} and {#compress}.
  #
  # @example
  #   ds1 = Hamster::DisjointSet.new([:a, :b, :c])
  #   ds2 = ds1.union(:a, :b)
  #   ds2.connected?(:a, :b)  # => true
  #   ds1.connected?(:a, :b)  # => false
  #   ds2.partition_size(:a)  # => 2
  #
  class DisjointSet
    include Immutable
    include ::Enumerable

    class << self
      # Create a new `DisjointSet` populated with the given items, each in
      # its own singleton partition.
      #
      # @return [DisjointSet]
      def [](*items)
        items.empty? ? empty : new(items)
      end

      # Return an empty `DisjointSet`. If used on a subclass, returns an
      # empty instance of that class.
      #
      # @return [DisjointSet]
      def empty
        @empty ||= self.new
      end

      # "Raw" allocation of a new `DisjointSet`. Used internally to create a
      # new version quickly after deriving modified parent/size maps.
      #
      # @return [DisjointSet]
      # @private
      def alloc(parents, sizes, size)
        allocate.tap do |set|
          set.instance_variable_set(:@parents, parents)
          set.instance_variable_set(:@sizes, sizes)
          set.instance_variable_set(:@size, size)
        end
      end
    end

    def initialize(items = [])
      @parents = EmptyHash # element -> parent element (roots are their own parent)
      @sizes   = EmptyHash # root element -> partition size
      @size    = 0
      items.each do |item|
        next if @parents.key?(item)
        @parents = @parents.put(item, item)
        @sizes   = @sizes.put(item, 1)
        @size   += 1
      end
    end

    # Return `true` if this set contains no elements.
    # @return [Boolean]
    def empty?
      @size == 0
    end

    # Return the number of elements in this set.
    # @return [Integer]
    def size
      @size
    end
    alias :length :size

    # Return the number of disjoint partitions the elements are divided into.
    # @return [Integer]
    def partition_count
      @sizes.size
    end

    # Return `true` if `item` is a member of this set.
    #
    # @param item [Object] The object to check for
    # @return [Boolean]
    def include?(item)
      @parents.key?(item)
    end
    alias :member? :include?
    alias :contains? :include?

    # Call the given block once for each element in the set.
    # @yieldparam item [Object]
    # @return [self, Enumerator]
    def each
      return to_enum if not block_given?
      @parents.each { |item, _| yield(item) }
      self
    end

    # Return a new `DisjointSet` with `item` added as a singleton
    # partition. If `item` is already a member, return `self`.
    #
    # @param item [Object] The object to add
    # @return [DisjointSet]
    def add(item)
      return self if include?(item)
      self.class.alloc(@parents.put(item, item), @sizes.put(item, 1), @size + 1)
    end
    alias :<< :add

    # Return the representative (root) element of the partition containing
    # `item`, or `nil` if `item` is not a member of this set.
    #
    # This is a pure query: it never modifies the internal structure, so the
    # receiver and all versions derived from it are unaffected.
    #
    # @param item [Object] The object to look up
    # @return [Object, nil]
    def find(item)
      return nil unless @parents.key?(item)
      find_in(@parents, item).first
    end

    # Return `true` if `item` and `other` are both members of this set
    # and belong to the same partition.
    #
    # @param item [Object]
    # @param other [Object]
    # @return [Boolean]
    def connected?(item, other)
      return false unless include?(item) && include?(other)
      find(item).eql?(find(other))
    end

    # Return a new `DisjointSet` in which the partitions containing `item`
    # and `other` have been merged. Elements which are not yet members are
    # added first. If both elements are already in the same partition, return
    # `self`.
    #
    # The smaller partition is attached below the root of the larger one
    # (union by size), and the search paths of both elements are compressed
    # in the returned version only.
    #
    # @param item [Object]
    # @param other [Object]
    # @return [DisjointSet]
    def union(item, other)
      parents = @parents
      sizes   = @sizes
      size    = @size
      unless parents.key?(item)
        parents = parents.put(item, item)
        sizes   = sizes.put(item, 1)
        size   += 1
      end
      unless parents.key?(other)
        parents = parents.put(other, other)
        sizes   = sizes.put(other, 1)
        size   += 1
      end

      root_item,  path_item  = find_in(parents, item)
      root_other, path_other = find_in(parents, other)
      return self if root_item.eql?(root_other)

      size_item  = sizes.get(root_item)
      size_other = sizes.get(root_other)
      if size_item < size_other
        root_item,  root_other  = root_other, root_item
        size_item,  size_other  = size_other, size_item
        path_item,  path_other  = path_other, path_item
      end

      sizes   = sizes.delete(root_other).put(root_item, size_item + size_other)
      parents = parents.put(root_other, root_item)
      (path_item + path_other).each do |node|
        parents = parents.put(node, root_item)
      end
      self.class.alloc(parents, sizes, size)
    end

    # Return a new `DisjointSet` which results from unioning each of the
    # given `pairs`, in order. Each pair must be a 2-element collection.
    #
    # All pairs are validated before any merging takes place, so an invalid
    # pair raises `ArgumentError` without exposing a partially merged
    # result; the receiver is left untouched either way.
    #
    # @param pairs [Enumerable] An enumerable of 2-element collections
    # @return [DisjointSet]
    # @raise [ArgumentError] if any pair does not contain exactly 2 elements
    def union_all(pairs)
      normalized = pairs.to_a.map do |pair|
        pair = pair.to_a if pair.respond_to?(:to_a)
        unless pair.is_a?(Array) && pair.size == 2
          raise ArgumentError, "expected an enumerable of 2-element pairs, got: #{pair.inspect}"
        end
        pair
      end
      normalized.reduce(self) { |set, (item, other)| set.union(item, other) }
    end

    # Return a new `DisjointSet` in which the search path from `item` to
    # its root has been compressed, so that every element on the path points
    # directly at the root. The partitions themselves are unchanged, and the
    # receiver is not modified. If `item` is not a member, or its path is
    # already fully compressed, return `self`.
    #
    # @param item [Object]
    # @return [DisjointSet]
    def compress(item)
      return self unless include?(item)
      root, path = find_in(@parents, item)
      return self if path.size <= 1
      parents = @parents
      path.each { |node| parents = parents.put(node, root) }
      self.class.alloc(parents, @sizes, @size)
    end

    # Return the number of elements in the partition containing `item`, or
    # 0 if `item` is not a member of this set.
    #
    # @param item [Object]
    # @return [Integer]
    def partition_size(item)
      return 0 unless include?(item)
      @sizes.get(find(item))
    end

    # Return a `Hamster::Set` of the elements sharing a partition with
    # `item`. If `item` is not a member, return an empty `Set`.
    #
    # @param item [Object]
    # @return [Set]
    def partition(item)
      return Set.empty unless include?(item)
      root = find(item)
      members = []
      each { |element| members << element if find(element).eql?(root) }
      Set.new(members)
    end

    # Return a `Vector` of `Set`s, one for each
    # partition of this set.
    #
    # @return [Vector]
    def partitions
      groups = {}
      each do |element|
        root = find(element)
        (groups[root] ||= []) << element
      end
      Vector.new(groups.values.map { |members| Set.new(members) })
    end

    # Return an empty `DisjointSet` instance, of the same class as this one.
    # @return [DisjointSet]
    def clear
      self.class.empty
    end

    # Return true if `other` has the same type, the same elements, and the
    # same partitioning, regardless of internal tree shape or the order in
    # which elements were added and merged.
    #
    # @param other [Object] The object to compare with
    # @return [Boolean]
    def eql?(other)
      return true if other.equal?(self)
      return false if not instance_of?(other.class)
      return false if @size != other.size
      return false if partition_count != other.partition_count
      partition_sets.eql?(other.send(:partition_sets))
    end
    alias :== :eql?

    # See `Object#hash`.
    # @return [Integer]
    def hash
      partition_sets.hash
    end

    # @return [Array]
    def to_a
      ary = []
      each { |item| ary << item }
      ary
    end

    # Return a `Set` containing all elements of this set.
    # @return [Set]
    def to_set
      Set.new(to_a)
    end

    # @return [String]
    def inspect
      "Hamster::DisjointSet[#{partitions.map { |members| members.to_a.inspect }.join(', ')}]"
    end
    alias :to_s :inspect

    private

    # Walk the parent chain from `item` up to its root. Returns the root
    # and the list of nodes strictly below the root which were visited along
    # the way. Pure: never modifies the given map.
    #
    # @return [Array(Object, Array)]
    def find_in(parents, item)
      path = []
      node = item
      until parents.get(node).eql?(node)
        path << node
        node = parents.get(node)
      end
      [node, path]
    end

    # A `Set` of `Set`s of members, one per partition.
    # Two disjoint sets with the same partitioning produce equal results,
    # regardless of internal tree shape.
    #
    # @return [Set]
    def partition_sets
      partitions.reduce(Set.empty) { |set, members| set.add(members) }
    end
  end
end
