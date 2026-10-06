require "hamster/hash"
require "hamster/vector"

module Hamster
  # An immutable map which iterates key/value pairs in insertion order.
  # Updating an existing key preserves its position; deleting and reinserting a
  # key moves it to the end. The lookup layer is a hash trie, while a separate
  # persistent ordered tree stores traversal order, so old and new map versions
  # share unchanged paths. Internal rank gaps caused by deletions are compacted
  # by allocating a new balanced tree; retained older versions keep their own
  # trees and therefore their original traversal order.
  class OrderedHash < Hash
    class << self
      def alloc(directory = EmptyTrie, order = nil, block = nil)
        obj = allocate
        obj.instance_variable_set(:@directory, directory)
        obj.instance_variable_set(:@order, order)
        obj.instance_variable_set(:@default, block)
        obj.instance_variable_set(:@next_rank, order ? OrderedSequence.max_key(order) + 1 : 0)
        obj.send(:immutable!)
        obj
      end
    end

    def initialize(pairs = nil, &block)
      @directory = Trie.new(0)
      @order = nil
      @next_rank = 0
      @default = block

      if pairs
        pairs.each do |key, value|
          put!(key, value)
        end
      end
    end

    def size
      @directory.size
    end

    def empty?
      @directory.empty?
    end

    def key?(key)
      !!@directory.get(key)
    end
    alias :has_key? :key?
    alias :include? :key?
    alias :member? :key?

    def get(key)
      entry = @directory.get(key)
      entry ? entry[1][0] : @default && @default.call(key)
    end

    def fetch(key, default = Undefined)
      entry = @directory.get(key)
      if entry
        entry[1][0]
      elsif block_given?
        yield(key)
      elsif default != Undefined
        default
      else
        raise KeyError, "key not found: #{key.inspect}"
      end
    end
    alias :[] :get

    def put(key, value = yield(get(key)))
      entry = @directory.get(key)

      if entry
        old_value, rank = entry[1]
        return self if old_value.equal?(value)

        directory = @directory.put(key, [value, rank])
        stored_key = directory.get(key)[0]
        order = OrderedSequence.update(@order, rank, [stored_key, value].freeze)
      else
        rank = @next_rank
        directory = @directory.put(key, [value, rank])
        stored_key = directory.get(key)[0]
        order = OrderedSequence.insert(@order, rank, [stored_key, value].freeze)
      end

      self.class.alloc(directory, order, @default)
    end
    alias :store :put

    def delete(key)
      entry = @directory.get(key)
      return self unless entry

      rank = entry[1][1]
      directory = @directory.delete(key)
      order = OrderedSequence.delete(@order, rank)

      unless order
        return @default ? self.class.alloc(EmptyTrie, nil, @default) : self.class.empty
      end

      directory, order = compact_structure(directory, order)
      self.class.alloc(directory, order, @default)
    end

    def each(&block)
      return to_enum unless block_given?
      OrderedSequence.each(@order, &block)
      self
    end
    alias :each_pair :each

    def reverse_each(&block)
      return enum_for(:reverse_each) unless block_given?
      OrderedSequence.reverse_each(@order, &block)
      self
    end

    def each_key
      return enum_for(:each_key) unless block_given?
      each { |key, _| yield key }
      self
    end

    def each_value
      return enum_for(:each_value) unless block_given?
      each { |_, value| yield value }
      self
    end

    def select
      return enum_for(:select) unless block_given?
      selected = []
      each do |pair|
        selected << pair if yield(pair)
      end
      return self if selected.size == size
      self.class.new(selected, &@default)
    end
    alias :find_all :select
    alias :keep_if :select

    def merge(other)
      result = self
      other.each do |key, other_value|
        entry = result.instance_variable_get(:@directory).get(key)
        value = if entry
          block_given? ? yield(key, entry[1][0], other_value) : other_value
        else
          other_value
        end
        result = result.put(key, value)
      end
      result
    end

    def slice(*wanted)
      selected = []
      wanted_set = {}
      wanted.each { |key| wanted_set[key] = true }
      each do |key, value|
        selected << [key, value] if wanted_set.key?(key)
      end
      self.class.new(selected, &@default)
    end

    def keys
      Vector.new(each_key.to_a.freeze)
    end

    def values
      Vector.new(each_value.to_a.freeze)
    end

    def sample
      entry = OrderedSequence.at(@order, rand(size))
      entry && entry.dup
    end

    def clear
      @default ? self.class.alloc(EmptyTrie, nil, @default) : self.class.empty
    end

    def eql?(other)
      return true if equal?(other)
      return false unless instance_of?(other.class)
      OrderedSequence.eql?(@order, other.instance_variable_get(:@order))
    end

    def ==(other)
      return true if equal?(other)
      other.respond_to?(:to_hash) && to_hash == other.to_hash
    end

    def hash
      reduce(0) do |digest, (key, value)|
        (digest << 5) - digest + key.hash + value.hash
      end
    end

    def marshal_dump
      to_a
    end

    def marshal_load(pairs)
      initialize(pairs)
      immutable!
    end

    private

    def put!(key, value)
      entry = @directory.get(key)
      if entry
        rank = entry[1][1]
        @directory.put!(key, [value, rank])
        stored_key = @directory.get(key)[0]
        @order = OrderedSequence.update(@order, rank, [stored_key, value].freeze)
      else
        rank = @next_rank
        @next_rank += 1
        @directory.put!(key, [value, rank])
        stored_key = @directory.get(key)[0]
        @order = OrderedSequence.insert(@order, rank, [stored_key, value].freeze)
      end
    end

    def compact_structure(directory, order)
      highest_rank = OrderedSequence.max_key(order)
      return [directory, order] if highest_rank < directory.size * 2 + 32

      pairs = []
      OrderedSequence.each(order) { |pair| pairs << pair }
      compacted_directory = Trie.new(0)
      pairs.each_with_index do |(key, value), rank|
        compacted_directory.put!(key, [value, rank])
      end
      [compacted_directory, OrderedSequence.from_pairs(pairs)]
    end

    # Persistent, balanced sequence indexed by immutable integer ranks. The
    # ranks are not visible to map users. Deleted nodes are omitted by a new
    # path, while old map versions retain their original nodes.
    class OrderedSequence
      Node = Struct.new(:key, :value, :left, :right, :height, :size) do
        def initialize(key, value, left, right)
          super(key, value, left, right,
                1 + [OrderedSequence.height(left), OrderedSequence.height(right)].max,
                1 + OrderedSequence.size(left) + OrderedSequence.size(right))
          freeze
        end
      end

      class << self
        def insert(node, key, value)
          return Node.new(key, value, nil, nil) unless node

          if key < node.key
            balance(Node.new(node.key, node.value, insert(node.left, key, value), node.right))
          elsif key > node.key
            balance(Node.new(node.key, node.value, node.left, insert(node.right, key, value)))
          else
            Node.new(key, value, node.left, node.right)
          end
        end

        def update(node, key, value)
          insert(node, key, value)
        end

        def delete(node, key)
          return nil unless node

          if key < node.key
            balance(Node.new(node.key, node.value, delete(node.left, key), node.right))
          elsif key > node.key
            balance(Node.new(node.key, node.value, node.left, delete(node.right, key)))
          else
            merge_nodes(node.left, node.right)
          end
        end

        def each(node, &block)
          return nil unless node
          each(node.left, &block)
          block.call(node.value)
          each(node.right, &block)
        end

        def reverse_each(node, &block)
          return nil unless node
          reverse_each(node.right, &block)
          block.call(node.value)
          reverse_each(node.left, &block)
        end

        def at(node, index)
          return nil unless node
          left_size = size(node.left)
          if index < left_size
            at(node.left, index)
          elsif index == left_size
            node.value
          else
            at(node.right, index - left_size - 1)
          end
        end

        def max_key(node)
          node.right ? max_key(node.right) : node.key
        end

        def from_pairs(pairs)
          ranked = pairs.each_with_index.map { |pair, rank| [rank, pair] }
          build_balanced(ranked)
        end

        def eql?(left, right)
          return true if left.equal?(right)
          return false unless size(left) == size(right)

          left_pairs = each_pair(left)
          each_pair(right).each_with_index do |right_pair, index|
            left_pair = left_pairs[index]
            return false unless left_pair[0].eql?(right_pair[0])
            return false unless left_pair[1].eql?(right_pair[1])
          end
          true
        end

        def height(node)
          node ? node.height : 0
        end

        def size(node)
          node ? node.size : 0
        end

        def balance(node)
          balance_factor = height(node.left) - height(node.right)
          if balance_factor > 1
            if height(node.left.left) >= height(node.left.right)
              rotate_right(node)
            else
              left = rotate_left(node.left)
              rotate_right(Node.new(node.key, node.value, left, node.right))
            end
          elsif balance_factor < -1
            if height(node.right.right) >= height(node.right.left)
              rotate_left(node)
            else
              right = rotate_right(node.right)
              rotate_left(Node.new(node.key, node.value, node.left, right))
            end
          else
            node
          end
        end

        def rotate_right(node)
          left = node.left
          Node.new(left.key, left.value, left.left,
                    Node.new(node.key, node.value, left.right, node.right))
        end

        def rotate_left(node)
          right = node.right
          Node.new(right.key, right.value,
                    Node.new(node.key, node.value, node.left, right.left),
                    right.right)
        end

        def merge_nodes(left, right)
          return right unless left
          return left unless right
          if left.height > right.height
            balance(Node.new(left.key, left.value, left.left, merge_nodes(left.right, right)))
          else
            balance(Node.new(right.key, right.value, merge_nodes(left, right.left), right.right))
          end
        end

        def build_balanced(pairs)
          return nil if pairs.empty?
          middle = pairs.size / 2
          rank, value = pairs[middle]
          Node.new(rank, value,
                   build_balanced(pairs[0...middle]),
                   build_balanced(pairs[(middle + 1)..-1]))
        end

        def each_pair(node)
          result = []
          each(node) { |pair| result << pair }
          result
        end
      end
    end
  end

  EmptyOrderedHash = Hamster::OrderedHash.empty
end
