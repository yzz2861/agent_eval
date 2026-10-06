require "hamster/immutable"
require "hamster/hash"

module Hamster
  # A persistent minimum priority queue.
  #
  # Each insertion returns both a new queue and an opaque handle. Handles are
  # stable across priority changes, but a handle is only valid for versions in
  # which its entry is present. Removing an entry invalidates its handle; entry
  # IDs are never reused, so stale handles cannot identify later inserts.
  #
  # Comparators receive two priorities and return -1, 0, or 1, in the same way
  # as the block accepted by Enumerable#sort. A one-argument block may also be
  # supplied; it derives a sort key from a priority. Forked queues share the
  # same comparator and may be merged; independently constructed queues with
  # different comparator objects cannot.
  #
  # Equal priorities retain FIFO order by original insertion time. Priority
  # changes retain that original insertion position among equal priorities.
  # Distinct entries in a merged queue are ordered by priority, then original
  # insertion time. If both queues contain the same handle, the newer priority
  # adjustment wins; unchanged copies are treated as one entry.
  class PriorityQueue
    include Immutable
    include Enumerable

    class InvalidHandleError < ArgumentError; end

    DEFAULT_COMPARATOR = lambda { |a, b| a <=> b }

    @token_mutex = Mutex.new
    @next_token = 0

    class << self
      # Create a queue from [item, priority] pairs.
      def [](*entries)
        new(entries)
      end

      def empty(&comparator)
        if comparator
          new([], &comparator)
        else
          @empty ||= alloc(Node::EMPTY, Hamster::Hash.empty, DEFAULT_COMPARATOR)
        end
      end

      # @private
      def alloc(heap, entries, comparator)
        allocate.tap do |queue|
          queue.instance_variable_set(:@heap, heap)
          queue.instance_variable_set(:@entries, entries)
          queue.instance_variable_set(:@comparator, comparator)
          queue.freeze
        end
      end

      # @private
      def next_token
        PriorityQueue.instance_variable_get(:@token_mutex).synchronize do
          PriorityQueue.instance_variable_set(
            :@next_token,
            PriorityQueue.instance_variable_get(:@next_token) + 1
          )
          PriorityQueue.instance_variable_get(:@next_token)
        end
      end
    end

    def initialize(entries = [], &comparator)
      block = comparator || DEFAULT_COMPARATOR
      if block.arity == 1 || block.arity == -1 || block.arity == -2
        @comparator = lambda { |a, b| block.call(a) <=> block.call(b) }
      else
        @comparator = block
      end

      @heap = Node::EMPTY
      @entries = Hamster::Hash.empty
      entries.each { |entry| add_initial_entry(entry) }
    end

    def empty?
      @entries.empty?
    end

    def size
      @entries.size
    end
    alias :length :size

    # Return [new_queue, handle].
    def insert(item, priority)
      sequence = self.class.next_token
      entry = Entry.new(item, priority, sequence, sequence)
      handle = Handle.new(sequence)
      node = Node.new(entry, Node::EMPTY, Node::EMPTY)
      queue = self.class.alloc(
        @heap.meld(node, @comparator),
        @entries.put(sequence, entry),
        @comparator
      )
      [queue, handle]
    end
    alias :push :insert
    alias :enqueue :insert
    alias :add :insert

    def min
      active_root(@heap, @entries, {}).entry.item
    end
    alias :peek :min

    def min_priority
      active_root(@heap, @entries, {}).entry.priority
    end

    def min_handle
      Handle.new(active_root(@heap, @entries, {}).entry.sequence)
    end

    # Remove and return [item, new_queue]. An empty queue returns [nil, self].
    def pop
      root = active_root(@heap, @entries, seen = {})
      return [nil, self] if root.empty?

      entries = @entries.delete(root.entry.sequence)
      heap = root.left.meld(root.right, @comparator)
      heap = active_root(heap, entries, seen)
      queue = self.class.alloc(heap, entries, @comparator)
      [root.entry.item, queue]
    end
    alias :shift :pop
    alias :dequeue :pop

    def update_priority(handle, priority)
      entry = entry_for(handle)
      return self if @comparator.call(priority, entry.priority) == 0

      updated = entry.with_priority(priority, self.class.next_token)
      node = Node.new(updated, Node::EMPTY, Node::EMPTY)
      heap = @heap.meld(node, @comparator)
      self.class.alloc(heap, @entries.put(entry.sequence, updated), @comparator)
    end
    alias :adjust_priority :update_priority
    alias :change_priority :update_priority

    def priority_for(handle)
      entry_for(handle).priority
    end

    def handle?(handle)
      handle.is_a?(Handle) && !!@entries.get(handle.id)
    end
    alias :include_handle? :handle?

    # Return the union of two queues. Shared handles retain one entry, never two.
    def merge(other)
      return self if other.equal?(self)
      unless other.is_a?(self.class)
        raise TypeError, "can only merge #{self.class} with #{self.class}"
      end
      unless @comparator.equal?(other.comparator)
        raise ArgumentError, "cannot merge priority queues with different comparators"
      end
      return other if empty?
      return self if other.empty?

      entries = merged_entries(other)
      heap = @heap.meld(other.heap, @comparator)
      self.class.alloc(heap, entries, @comparator)
    end
    alias :union :merge
    alias :| :merge
    alias :+ :merge

    def clear
      self.class.alloc(Node::EMPTY, Hamster::Hash.empty, @comparator)
    end

    def each
      return enum_for(:each) unless block_given?

      heap = @heap
      seen = {}
      until heap.empty?
        root = active_root(heap, @entries, seen)
        break if root.empty?
        yield root.entry.item
        heap = root.left.meld(root.right, @comparator)
      end
      self
    end

    def each_pair
      return enum_for(:each_pair) unless block_given?

      heap = @heap
      seen = {}
      until heap.empty?
        root = active_root(heap, @entries, seen)
        break if root.empty?
        yield [root.entry.item, root.entry.priority]
        heap = root.left.meld(root.right, @comparator)
      end
      self
    end

    def to_a
      each.to_a
    end
    alias :entries :to_a
    alias :to_ary :to_a

    def pairs
      each_pair.to_a
    end

    def eql?(other)
      other.is_a?(self.class) && pairs.eql?(other.pairs)
    end
    alias :== :eql?

    def inspect
      represented = pairs.map { |item, priority| "#{item.inspect} => #{priority.inspect}" }
      "#{self.class}[#{represented.join(", ")}]"
    end

    protected

    attr_reader :heap, :entries, :comparator

    private

    def add_initial_entry(value)
      unless value.is_a?(Array) && value.length == 2
        raise ArgumentError, "priority queue entries must be [item, priority] pairs"
      end
      queue, _handle = insert(value[0], value[1])
      @heap = queue.heap
      @entries = queue.entries
    end

    def entry_for(handle)
      unless handle.is_a?(Handle)
        raise InvalidHandleError, "priority queue handle required"
      end
      @entries.get(handle.id) or
        raise InvalidHandleError, "handle is not valid for this priority queue"
    end

    def merged_entries(other)
      other.entries.reduce(@entries) do |result, (sequence, other_entry)|
        current = result.get(sequence)
        if current.nil? || other_entry.revision > current.revision
          result.put(sequence, other_entry)
        else
          result
        end
      end
    end

    def active_root(heap, active_entries, seen)
      until heap.empty?
        entry = active_entries.get(heap.entry.sequence)
        next_sequence = heap.entry.sequence
        if entry && entry.revision == heap.entry.revision && !seen.key?(next_sequence)
          seen[next_sequence] = true
          return heap
        end
        heap = heap.left.meld(heap.right, @comparator)
      end
      heap
    end

    # @private
    class Entry
      attr_reader :item, :priority, :sequence, :revision

      def initialize(item, priority, sequence, revision)
        @item = item
        @priority = priority
        @sequence = sequence
        @revision = revision
        freeze
      end

      def with_priority(priority, revision)
        Entry.new(@item, priority, @sequence, revision)
      end
    end

    # @private
    class Handle
      attr_reader :id

      def initialize(id)
        @id = id
        freeze
      end

      def dup
        self
      end
      alias :clone :dup

      def eql?(other)
        other.is_a?(Handle) && @id.eql?(other.id)
      end
      alias :== :eql?

      def hash
        @id.hash
      end

      def inspect
        "#<#{self.class} #{@id}>"
      end
    end

    # @private
    class Node
      attr_reader :entry, :left, :right, :rank

      def initialize(entry, left, right)
        @entry = entry
        if left.rank >= right.rank
          @left = left
          @right = right
        else
          @left = right
          @right = left
        end
        @rank = @right.rank + 1
        freeze
      end

      def empty?
        false
      end

      def meld(other, comparator)
        return self if other.empty?
        first, second = ordered_nodes(self, other, comparator)
        merged_right = first.right.meld(second, comparator)

        if first.left.rank >= merged_right.rank
          Node.new(first.entry, first.left, merged_right)
        else
          Node.new(first.entry, merged_right, first.left)
        end
      end

      def self.compare(first, second, comparator)
        priority_comparison = comparator.call(first.priority, second.priority)
        return priority_comparison unless priority_comparison == 0
        sequence_comparison = first.sequence <=> second.sequence
        return sequence_comparison unless sequence_comparison == 0
        first.revision <=> second.revision
      end

      def ordered_nodes(first, second, comparator)
        comparison = Node.compare(first.entry, second.entry, comparator)
        comparison <= 0 ? [first, second] : [second, first]
      end

      class Empty
        def entry
          nil
        end

        def left
          self
        end

        def right
          self
        end

        def rank
          0
        end

        def empty?
          true
        end

        def meld(other, _comparator)
          other
        end
      end

      EMPTY = Empty.new.freeze
    end
  end

  EmptyPriorityQueue = PriorityQueue.empty
end
