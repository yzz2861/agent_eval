require "hamster/hash"
require "hamster/trie"
require "hamster/vector"

module Hamster
  # An immutable hash which iterates key/value pairs in insertion order.
  # Updating an existing key replaces only its value; deleting and
  # reinserting a key moves it to the end. During {#merge}, keys already in
  # the receiver keep their receiver position, while new keys are appended in
  # the source's iteration order.
  #
  # Lookup uses the same hash/eql? equivalence rules as Ruby's Hash. A
  # persistent hash trie provides key lookup, while a persistent balanced
  # tree stores only live order entries. Retained versions therefore continue
  # to traverse their own roots after later versions delete or compact their
  # order structure.
  #
  # @example
  #   map = Hamster::OrderedHash[a: 1, b: 2]
  #   map.put(:c, 3).to_a       # => [[:a, 1], [:b, 2], [:c, 3]]
  #   map.put(:a, 9).to_a       # => [[:a, 9], [:b, 2]]
  #   map.delete(:a).put(:a, 9).to_a
  #   # => [[:b, 2], [:a, 9]]
  class OrderedHash < Hash
    Entry = Struct.new(:value, :sequence)
    private_constant :Entry

    class OrderNode
      Empty = Class.new do
        def empty?
          true
        end

        def height
          0
        end

        def size
          0
        end

        def put(key, entry)
          OrderNode.new(key, entry, self, self)
        end

        def delete(key)
          self
        end

        def each(&block)
          nil
        end

        def reverse_each(&block)
          nil
        end
      end.new.freeze

      attr_reader :key, :entry, :left, :right, :height, :size

      def initialize(key, entry, left = Empty, right = Empty)
        @key = key
        @entry = entry
        @left = left
        @right = right
        @height = 1 + [left.height, right.height].max
        @size = 1 + left.size + right.size
        freeze
      end

      def empty?
        false
      end

      def put(new_key, new_entry)
        if new_key < key
          balanced(key, entry, left.put(new_key, new_entry), right)
        elsif new_key > key
          balanced(key, entry, left, right.put(new_key, new_entry))
        else
          self.class.new(key, new_entry, left, right)
        end
      end

      def delete(target)
        if target < key
          return self if left.equal?(Empty)
          new_left = left.delete(target)
          return self if new_left.equal?(left)
          balanced(key, entry, new_left, right)
        elsif target > key
          return self if right.equal?(Empty)
          new_right = right.delete(target)
          return self if new_right.equal?(right)
          balanced(key, entry, left, new_right)
        elsif left.equal?(Empty)
          right
        elsif right.equal?(Empty)
          left
        else
          successor = right.min_node
          balanced(successor.key, successor.entry, left, right.delete(successor.key))
        end
      end

      def each(&block)
        left.each(&block)
        block.call(key, entry)
        right.each(&block)
        nil
      end

      def reverse_each(&block)
        right.reverse_each(&block)
        block.call(key, entry)
        left.reverse_each(&block)
        nil
      end

      protected

      def min_node
        left.equal?(Empty) ? self : left.min_node
      end

      private

      def balanced(key, entry, left, right)
        balance = left.height - right.height
        return self.class.new(key, entry, left, right) if balance.abs <= 1

        if balance > 1
          if left.right.height > left.left.height
            pivot = left.right
            left = self.class.new(pivot.key, pivot.entry,
                                  self.class.new(left.key, left.entry, left.left, pivot.left),
                                  pivot.right)
          end
          pivot = left
          return self.class.new(pivot.key, pivot.entry,
                                pivot.left,
                                self.class.new(key, entry, pivot.right, right))
        elsif balance < -1
          if right.left.height > right.right.height
            pivot = right.left
            right = self.class.new(pivot.key, pivot.entry,
                                   pivot.left,
                                   self.class.new(right.key, right.entry, pivot.right, right.right))
          end
          pivot = right
          return self.class.new(pivot.key, pivot.entry,
                                self.class.new(key, entry, left, pivot.left),
                                pivot.right)
        end

        self.class.new(key, entry, left, right)
      end
    end

    class << self
      def [](pairs = nil)
        pairs.nil? || pairs.empty? ? empty : new(pairs)
      end

      def empty
        @empty ||= new
      end

      def alloc(trie = EmptyTrie, order = OrderNode::Empty, next_sequence = 0, block = nil)
        obj = allocate
        obj.instance_variable_set(:@trie, trie)
        obj.instance_variable_set(:@order, order)
        obj.instance_variable_set(:@next_sequence, next_sequence)
        obj.instance_variable_set(:@default, block)
        obj.freeze
        obj
      end
    end

    def initialize(pairs = nil, &block)
      @trie = Trie.new(0)
      @order = OrderNode::Empty
      @next_sequence = 0
      @default = block
      pairs.each { |key, value| put!(key, value) } if pairs
      freeze
    end

    def put(key, value = yield(get(key)))
      existing = @trie.get(key)

      if existing
        return self if value.equal?(existing[1].value)
        canonical_key = existing[0]
        entry = make_entry(value, existing[1].sequence)
        new_trie = @trie.put(canonical_key, entry)
        return self if new_trie.equal?(@trie)
        new_order = @order.put(entry.sequence, new_trie.get(canonical_key))
        self.class.alloc(new_trie, new_order, @next_sequence, @default)
      else
        entry = make_entry(value, @next_sequence)
        new_trie = @trie.put(key, entry)
        self.class.alloc(new_trie,
                         @order.put(@next_sequence, new_trie.get(key)),
                         @next_sequence + 1, @default)
      end
    end

    def store(key, value)
      put(key, value)
    end

    def delete(key)
      existing = @trie.get(key)
      return self unless existing

      trie = @trie.delete(key)
      return clear if trie.empty?
      self.class.alloc(trie, @order.delete(existing[1].sequence), @next_sequence, @default)
    end

    def get(key)
      entry = @trie.get(key)
      entry ? entry[1].value : super
    end
    alias :[] :get

    def fetch(key, default = Undefined)
      entry = @trie.get(key)
      return entry[1].value if entry
      super
    end

    def each(&block)
      return to_enum unless block_given?
      @order.each { |_, (key, stored)| yield(key, stored.value) }
      self
    end
    alias :each_pair :each

    def reverse_each(&block)
      return enum_for(:reverse_each) unless block_given?
      @order.reverse_each { |_, (key, stored)| yield(key, stored.value) }
      self
    end

    def each_key(&block)
      return enum_for(:each_key) unless block_given?
      @order.each { |_, (key, _)| yield(key) }
      self
    end

    def each_value(&block)
      return enum_for(:each_value) unless block_given?
      @order.each { |_, (_, stored)| yield(stored.value) }
      self
    end

    def map
      return enum_for(:map) unless block_given?
      return self if empty?
      self.class.new(super, &@default)
    end
    alias :collect :map

    def select
      return enum_for(:select) unless block_given?
      selected = []
      each { |key, value| selected << [key, value] if yield(key, value) }
      return self if selected.size == size
      return clear if selected.empty?
      self.class.new(selected, &@default)
    end
    alias :find_all :select
    alias :keep_if :select

    def reject
      return enum_for(:reject) unless block_given?
      select { |key, value| !yield(key, value) }
    end
    alias :delete_if :reject

    def merge(other)
      trie = @trie
      order = @order
      next_sequence = @next_sequence
      changed = false

      other.each do |key, value|
        existing = trie.get(key)
        merged_value = if existing && block_given?
          yield(key, existing[1].value, value)
        else
          value
        end

        if existing
          sequence = existing[1].sequence
          entry = make_entry(merged_value, sequence)
          new_trie = trie.put(existing[0], entry)
          unless new_trie.equal?(trie)
            trie = new_trie
            order = order.put(sequence, trie.get(existing[0]))
            changed = true
          end
        else
          entry = make_entry(merged_value, next_sequence)
          trie = trie.put(key, entry)
          order = order.put(next_sequence, trie.get(key))
          next_sequence += 1
          changed = true
        end
      end

      changed ? self.class.alloc(trie, order, next_sequence, @default) : self
    end

    def slice(*wanted)
      wanted_trie = Trie.new(0)
      wanted.each { |key| wanted_trie.put!(key, true) unless wanted_trie.get(key) }
      selected = []
      each { |key, value| selected << [key, value] if wanted_trie.key?(key) }
      return clear if selected.empty?
      self.class.new(selected, &@default)
    end

    def keys
      Vector.new(each_key.to_a.freeze)
    end

    def values
      Vector.new(each_value.to_a.freeze)
    end

    def invert
      pairs = map { |key, value| [value, key] }.to_a
      self.class.new(pairs, &@default)
    end

    def sample
      return nil if empty?
      target = rand(size)
      node = @order
      loop do
        if target < node.left.size
          node = node.left
        elsif target == node.left.size
          return [node.entry[0], node.entry[1].value]
        else
          target -= node.left.size + 1
          node = node.right
        end
      end
    end

    def clear
      @default ? self.class.alloc(EmptyTrie, OrderNode::Empty, 0, @default) : self.class.empty
    end

    def eql?(other)
      return true if equal?(other)
      instance_of?(other.class) && to_a == other.to_a
    end

    def ==(other)
      return true if equal?(other)
      other.respond_to?(:each_pair) && to_a == other.each_pair.to_a
    end

    def hash
      to_a.hash
    end

    def marshal_dump
      to_hash
    end

    def marshal_load(dictionary)
      initialize(dictionary)
    end

    private

    def make_entry(value, sequence)
      Entry.new(value, sequence).freeze
    end

    def put!(key, value)
      existing = @trie.get(key)

      if existing
        return if value.equal?(existing[1].value)
        entry = make_entry(value, existing[1].sequence)
        canonical_key = existing[0]
        @trie = @trie.put(canonical_key, entry)
        @order = @order.put(existing[1].sequence, @trie.get(canonical_key))
      else
        entry = make_entry(value, @next_sequence)
        @trie = @trie.put(key, entry)
        @order = @order.put(@next_sequence, @trie.get(key))
        @next_sequence += 1
      end
    end
  end

  EmptyOrderedHash = OrderedHash.empty
end
