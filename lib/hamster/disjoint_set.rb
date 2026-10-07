require "hamster/immutable"
require "hamster/hash"

module Hamster
  # A persistent disjoint-set (union-find). Elements can be added, connected,
  # and grouped, but every mutating operation returns a new `DisjointSet` and
  # leaves the receiver unchanged.
  #
  # Internally, a persistent {Hash} stores parent pointers and another stores
  # the size of every root component. Roots are linked by component size to
  # keep trees shallow. Path compression is applied while building a new
  # version by {#union}; read-only methods never mutate shared nodes.
  #
  # As elsewhere in Hamster, keys are considered identical when they are
  # `#eql?` and have the same `#hash`.
  #
  # @example
  #   sets = Hamster::DisjointSet["a", "b", "c"]
  #   joined_ab = sets.union("a", "b")
  #   joined_ab.connected?("a", "b") # => true
  #   sets.connected?("a", "b")      # => false
  class DisjointSet
    include Immutable
    include ::Enumerable

    class << self
      # Create a new `DisjointSet` containing the given elements.
      # @return [DisjointSet]
      def [](*elements)
        elements.empty? ? empty : new(elements)
      end

      # Return an empty `DisjointSet`. If used on a subclass, returns an empty
      # instance of that class.
      # @return [DisjointSet]
      def empty
        @empty ||= alloc(EmptyHash, EmptyHash)
      end

      # @private
      def alloc(parents, sizes)
        allocate.tap do |set|
          set.instance_variable_set(:@parents, parents)
          set.instance_variable_set(:@sizes, sizes)
          set.freeze
        end
      end
    end

    # @param elements [::Enumerable] Elements with which to initialize the set.
    def initialize(elements = [])
      @parents = EmptyHash
      @sizes = EmptyHash
      elements.each { |element| add!(element) }
    end

    # Return a new `DisjointSet` with `element` in its own component. If an
    # equivalent element is already present, return `self`.
    #
    # @param element [Object] The element to add.
    # @return [DisjointSet]
    def add(element)
      return self if entry_for(@parents, element)
      self.class.alloc(@parents.put(element, element), @sizes.put(element, 1))
    end
    alias :<< :add

    # Return `true` if `element` is a member of this set.
    # @param element [Object] The element to look for.
    # @return [Boolean]
    def include?(element)
      !!entry_for(@parents, element)
    end
    alias :member? :include?

    # Return the representative element of the component containing `element`.
    # This is a read-only lookup and does not compress or otherwise alter this
    # version. Compressed parent pointers are included in the result of a
    # subsequent {#union} that changes the set.
    #
    # @param element [Object] The element whose representative is returned.
    # @return [Object]
    # @raise [KeyError] if `element` is not present.
    def find(element)
      require_key!(element)
      root = element
      root = @parents[root] until @parents[root].eql?(root)
      root
    end
    alias :representative :find

    # Return `true` if both elements belong to the same component.
    #
    # @param first [Object] An element in the set.
    # @param second [Object] An element in the set.
    # @return [Boolean]
    # @raise [KeyError] if either element is not present.
    def connected?(first, second)
      find(first).eql?(find(second))
    end

    # Return a new `DisjointSet` in which the components containing `first` and
    # `second` are joined. If either element is missing, raise `KeyError` and
    # leave this version unchanged. If they are already connected, return
    # `self`.
    #
    # @param first [Object] An element in the set.
    # @param second [Object] An element in the set.
    # @return [DisjointSet]
    def union(first, second)
      require_key!(first)
      require_key!(second)

      parents, first_root = compress_path(@parents, first)
      parents, second_root = compress_path(parents, second)
      return self if first_root.eql?(second_root)

      first_size = @sizes[first_root]
      second_size = @sizes[second_root]

      if first_size < second_size
        first_root, second_root = second_root, first_root
        first_size, second_size = second_size, first_size
      end

      parents = parents.put(second_root, first_root)
      sizes = @sizes.delete(second_root).put(first_root, first_size + second_size)
      self.class.alloc(parents, sizes)
    end

    # Atomically perform several unions. `pairs` may be any enumerable of
    # two-element pairs. If any pair is invalid or contains a missing element,
    # the error is raised and this version is left unchanged.
    #
    # @example
    #   set.union_all([[:a, :b], [:b, :c]])
    #   set.union_all(x: 1, y: 2)
    #
    # @param pairs [::Enumerable] Pairs of elements to connect.
    # @return [DisjointSet]
    def union_all(pairs)
      unless pairs.respond_to?(:each)
        raise ArgumentError, "union_all requires an enumerable of pairs"
      end

      pairs.reduce(self) do |set, pair|
        unless pair.respond_to?(:to_ary)
          raise ArgumentError, "expected a pair, got #{pair.inspect}"
        end
        pair_array = pair.to_ary
        unless pair_array.size == 2
          raise ArgumentError, "expected a pair of two elements, got #{pair_array.inspect}"
        end
        first, second = pair_array
        set.union(first, second)
      end
    end

    # Return the number of elements in this set.
    # @return [Integer]
    def size
      @parents.size
    end
    alias :length :size

    # Return `true` if this set contains no elements.
    # @return [Boolean]
    def empty?
      @parents.empty?
    end

    # Return the number of connected components (partitions).
    # @return [Integer]
    def partition_count
      @sizes.size
    end

    # Return the number of elements in the component containing `element`.
    #
    # @param element [Object] An element in the set.
    # @return [Integer]
    # @raise [KeyError] if `element` is not present.
    def partition_size(element)
      @sizes[find(element)]
    end

    # Call the block once for every element. If no block is given, return an
    # `Enumerator`.
    # @return [DisjointSet, Enumerator]
    def each
      return enum_for(:each) unless block_given?
      @parents.each_key { |element| yield element }
      self
    end

    # Call the block once for each connected component, yielding a {Set} of
    # that component's elements. If no block is given, return an `Enumerator`.
    # @return [DisjointSet, Enumerator]
    def each_partition
      return enum_for(:each_partition) unless block_given?
      partition_sets.each { |group| yield group }
      self
    end
    alias :each_component :each_partition

    # Return all connected components as a {Set} of {Set}s.
    # @return [Set]
    def partitions
      partition_sets.reduce(Hamster::Set.empty) do |partitions, partition|
        partitions.add(partition)
      end
    end
    alias :components :partitions

    # Return true if `other` is a `DisjointSet` with the same elements and
    # same connected components, regardless of internal tree shape.
    # @return [Boolean]
    def eql?(other)
      return true if equal?(other)
      return false unless other.instance_of?(self.class)
      return false unless size == other.size

      partitions.eql?(other.partitions)
    end
    alias :== :eql?

    # See `Object#hash`.
    # @return [Integer]
    def hash
      partitions.hash
    end

    # @return [String]
    def inspect
      "#{self.class}[#{partition_sets.map(&:inspect).join(", ")}]"
    end

    # @private
    def marshal_dump
      {
        parents: @parents.to_hash,
        sizes: @sizes.to_hash
      }
    end

    # @private
    def marshal_load(data)
      @parents = Hamster::Hash.new(data[:parents])
      @sizes = Hamster::Hash.new(data[:sizes])
    end

    private

    def add!(element)
      return if entry_for(@parents, element)
      @parents = @parents.put(element, element)
      @sizes = @sizes.put(element, 1)
    end

    def require_key!(element)
      return if entry_for(@parents, element)
      raise KeyError, "key not found: #{element.inspect}"
    end

    def entry_for(hash, key)
      value = hash.fetch(key) { return nil }
      [key, value]
    end

    def compress_path(parents, element)
      path = []
      current = element

      until parents[current].eql?(current)
        path << current
        current = parents[current]
      end

      path.each do |node|
        parents = parents.put(node, current)
      end

      [parents, current]
    end

    def partition_groups
      each_with_object({}) do |element, groups|
        root = find(element)
        (groups[root] ||= []) << element
      end
    end

    def partition_sets
      partition_groups.values.map do |elements|
        trie = elements.reduce(EmptyTrie) { |set_trie, element| set_trie.put(element, nil) }
        Hamster::Set.alloc(trie).freeze
      end
    end
  end

  EmptyDisjointSet = Hamster::DisjointSet.empty
end
