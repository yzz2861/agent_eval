require "hamster/immutable"
require "hamster/hash"

module Hamster

  # A `PriorityQueue` is an immutable, persistent collection of
  # `[priority, value]` pairs which can always return (and remove) the pair
  # with the smallest priority in amortized logarithmic time. It is
  # implemented as a pairing heap with full structural sharing, so every
  # "modifying" operation returns a new queue and leaves the receiver
  # untouched, without copying the stored elements.
  #
  # Priorities are compared with a caller-supplied comparator: a callable
  # (or block) taking two priorities and returning a negative number, zero,
  # or a positive number, like `#<=>`. If none is given, `#<=>` is used.
  # Because the queue is fully immutable, a comparator which raises (or
  # returns something invalid) can never corrupt an existing queue: the
  # exception simply propagates and the receiver is left as it was.
  #
  # The queue is *stable*: elements whose priorities compare equal come out
  # in the order they were inserted. Each element carries a ticket number
  # from a per-queue counter to make this work.
  #
  # Two queues can be combined with {#merge}, which is a constant time
  # operation. The ordering rule for the merged queue is fully determined:
  # elements are ordered by priority, then by ticket, and `a.merge(b)`
  # shifts all of `b`'s tickets above any ticket ever issued by `a`.
  # Consequently, at equal priority, every element of `a` comes out before
  # every element of `b`, while the original insertion order *within* each
  # side is preserved. The shift is applied lazily (it is pushed down the
  # heap as elements are removed), so merging does not walk or copy either
  # queue.
  #
  # {#push} returns a {Handle} alongside the new queue. The handle can later
  # be passed to {#adjust} (on the same queue or any version derived from
  # it, including merges) to change that element's priority. Handles are
  # safe: each element has a process-wide unique id, so a stale handle
  # (whose element was already popped) or a foreign handle (issued by an
  # unrelated queue) can never accidentally match a different element --
  # {#adjust} raises `KeyError` instead. Adjusting an element makes it
  # count as newly arrived at its new priority: among elements with equal
  # priority it is ordered after everything inserted or adjusted earlier.
  #
  # @example
  #   queue = Hamster::PriorityQueue.new
  #   queue, handle = queue.push(2, :later)
  #   queue, _      = queue.push(1, :soon)
  #   queue         = queue.adjust(handle, 0)
  #   queue.peek                       # => [0, :later]
  #   queue, pair = queue.pop          # => pair == [0, :later]
  #
  class PriorityQueue
    include Immutable
    include Enumerable

    DEFAULT_COMPARATOR = ->(a, b) { a <=> b }

    # A reference to one specific element of a {PriorityQueue}, returned by
    # {PriorityQueue#push} and accepted by {PriorityQueue#adjust}. Handles
    # remain valid across versions of the queue they were issued from
    # (including merges) until their element is popped.
    class Handle
      # @private
      attr_reader :id

      # @private
      def initialize(id)
        @id = id
        freeze
      end

      def ==(other)
        other.is_a?(Handle) && other.id == id
      end
      alias_method :eql?, :==

      def hash
        id.hash
      end

      def inspect
        "#<Hamster::PriorityQueue::Handle id=#{id}>"
      end
    end

    # One element stored in the queue. The `ticket` orders elements whose
    # priorities compare equal. The `stamp` is a process-wide unique number
    # identifying this exact version of the element: every {#push} and
    # every {#adjust} mints a fresh one, so a heap node is current if and
    # only if its stamp matches the one registered in the queue's entry
    # index, and superseded nodes can be recognised and skipped.
    #
    # @private
    class Entry
      attr_reader :id, :ticket, :stamp, :priority, :value

      def initialize(id, ticket, stamp, priority, value)
        @id       = id
        @ticket   = ticket
        @stamp    = stamp
        @priority = priority
        @value    = value
        freeze
      end

      def with_ticket(ticket)
        Entry.new(id, ticket, stamp, priority, value)
      end
    end

    # A pairing heap node. `entry` always carries its absolute ticket;
    # `shift` is a pending ticket offset which applies to everything in
    # `children` and is pushed down lazily by {#materialize}.
    #
    # @private
    class Node
      attr_reader :entry, :children, :shift

      def initialize(entry, children, shift)
        @entry    = entry
        @children = children.freeze
        @shift    = shift
        freeze
      end

      # Return a copy of this subtree with every ticket increased by
      # `delta`. Only the root entry is updated eagerly; the offset is
      # accumulated into `shift` and applied to children lazily.
      def add_shift(delta)
        return self if delta == 0
        Node.new(entry.with_ticket(entry.ticket + delta), children, shift + delta)
      end

      # Push any pending shift down into the children, so that this node's
      # `shift` becomes zero.
      def materialize
        return self if shift == 0
        Node.new(entry, children.map { |child| child.add_shift(shift) }, 0)
      end

      # Link two trees, keeping the smaller entry on top. The winner is
      # materialized first so that its pending shift cannot leak onto the
      # loser, which becomes a new child. O(1) unless the winner has a
      # pending shift to push down.
      def link(other, comparator)
        if Node.compare_entries(entry, other.entry, comparator) <= 0
          Node.new(entry, [other] + materialize.children, 0)
        else
          Node.new(other.entry, [self] + other.materialize.children, 0)
        end
      end

      # Merge a list of trees in two passes (pairwise left-to-right, then
      # folding right-to-left), as in a classic pairing heap.
      def self.merge_pairs(nodes, comparator)
        case nodes.size
        when 0 then nil
        when 1 then nodes[0]
        else
          pairs = []
          index = 0
          while index + 1 < nodes.size
            pairs << nodes[index].link(nodes[index + 1], comparator)
            index += 2
          end
          pairs << nodes[index] if index < nodes.size
          pairs.reverse.reduce { |acc, node| acc.link(node, comparator) }
        end
      end

      # Total order on entries: by priority (using the comparator), then by
      # ticket so that equal priorities come out in insertion order.
      def self.compare_entries(entry_a, entry_b, comparator)
        result = comparator.call(entry_a.priority, entry_b.priority)
        unless result.is_a?(Numeric)
          raise ArgumentError, "priority comparator must return a numeric like #<=> does, got: #{result.inspect}"
        end
        if result < 0 then -1
        elsif result > 0 then 1
        else entry_a.ticket <=> entry_b.ticket
        end
      end
    end

    @next_id = 0
    @id_mutex = Mutex.new

    class << self
      # Return an empty `PriorityQueue` using the default (`#<=>`) comparator.
      # @return [PriorityQueue]
      def empty
        @empty ||= self.new
      end

      # Process-wide unique element ids. Because ids are never reused, a
      # handle can never accidentally match an element it was not issued
      # for, no matter which queue it is presented to.
      #
      # @private
      def next_id
        @id_mutex.synchronize { @next_id += 1 }
      end

      # "Raw" allocation of a new PriorityQueue. Used internally to build
      # new versions quickly.
      #
      # @private
      def alloc(root, entries, counter, comparator)
        result = allocate
        result.instance_variable_set(:@root, root)
        result.instance_variable_set(:@entries, entries)
        result.instance_variable_set(:@counter, counter)
        result.instance_variable_set(:@comparator, comparator)
        result.freeze
      end
    end

    # Return an empty `PriorityQueue`. An optional callable (or block) may
    # be supplied to compare two priorities; it must return a negative
    # number, zero, or a positive number, like `#<=>`.
    #
    # @param comparator [#call] optional priority comparator
    # @return [PriorityQueue]
    def initialize(comparator = nil, &block)
      @comparator = block || comparator || DEFAULT_COMPARATOR
      unless @comparator.respond_to?(:call)
        raise ArgumentError, "comparator must be callable"
      end
      @root     = nil
      @entries  = Hamster::Hash.empty
      @counter  = 0
    end

    # Return `true` if this queue contains no elements.
    # @return [Boolean]
    def empty?
      @entries.empty?
    end

    # The number of elements in this queue.
    # @return [Integer]
    def size
      @entries.size
    end

    # Return a new queue with `value` added at the given `priority`, along
    # with a {Handle} which can later be used to {#adjust} the element's
    # priority.
    #
    # @param priority the priority to file `value` under
    # @param value the element to store
    # @return [Array(PriorityQueue, Handle)] the new queue and a handle to
    #   the newly inserted element
    def push(priority, value)
      id    = PriorityQueue.next_id
      entry = Entry.new(id, @counter, id, priority, value)
      root  = insert_node(Node.new(entry, [], 0))
      queue = self.class.alloc(root, @entries.put(entry.id, entry), @counter + 1, @comparator)
      [queue, Handle.new(entry.id)]
    end

    # Return the `[priority, value]` pair with the smallest priority, or
    # `nil` if the queue is empty. Ties are broken by insertion order.
    # @return [Array, nil]
    def peek
      root    = @root
      entries = @entries
      while root
        entry = root.entry
        return [entry.priority, entry.value] if live?(entries, entry)
        root = delete_min_node(root)
      end
      nil
    end

    # Remove the smallest element and return it together with the new
    # queue. Returns `[self, nil]` if the queue is empty.
    #
    # @return [Array(PriorityQueue, Array)] the new queue and the removed
    #   `[priority, value]` pair
    def pop
      root    = @root
      entries = @entries
      while root
        entry = root.entry
        if live?(entries, entry)
          queue = self.class.alloc(delete_min_node(root), entries.delete(entry.id), @counter, @comparator)
          return [queue, [entry.priority, entry.value]]
        end
        root = delete_min_node(root)
      end
      [self, nil]
    end

    # Return a new queue in which the element referenced by `handle` has
    # `new_priority`. The handle remains valid for the returned queue, so
    # repeated adjustments are possible. The element counts as newly
    # arrived at its new priority: among elements with equal priority it
    # comes out after everything inserted or adjusted earlier.
    #
    # @param handle [Handle] a handle previously returned by {#push}
    # @param new_priority the element's new priority
    # @return [PriorityQueue]
    # @raise [TypeError] if `handle` is not a {Handle}
    # @raise [KeyError] if the handle is stale (its element was already
    #   popped) or was issued by an unrelated queue
    def adjust(handle, new_priority)
      unless handle.is_a?(Handle)
        raise TypeError, "expected a Hamster::PriorityQueue::Handle, got: #{handle.inspect}"
      end
      entry = @entries.get(handle.id)
      if entry.nil?
        raise KeyError, "handle does not refer to an element of this queue (stale or foreign handle)"
      end
      new_entry = Entry.new(entry.id, @counter, PriorityQueue.next_id, new_priority, entry.value)
      root = insert_node(Node.new(new_entry, [], 0))
      self.class.alloc(root, @entries.put(entry.id, new_entry), @counter + 1, @comparator)
    end

    # Return a new queue containing the elements of this queue and of
    # `other`. This is a constant time operation; neither queue is
    # modified, and both remain usable afterwards.
    #
    # The merged queue orders elements by priority, then by arrival. All
    # of `other`'s arrival tickets are shifted above any ticket ever
    # issued by this queue, so at equal priority every element of this
    # queue comes out before every element of `other`, while the original
    # insertion order within each side is preserved.
    #
    # If both queues contain versions of the same element -- which happens
    # when they were both derived from a common ancestor version -- the
    # element appears only once in the merged queue, and this queue's
    # version of it wins.
    #
    # The merged queue uses this queue's comparator; both queues should
    # therefore use equivalent comparators. Handles issued by either queue
    # remain valid for the merged queue.
    #
    # @param other [PriorityQueue] the queue to merge with
    # @return [PriorityQueue]
    def merge(other)
      unless other.is_a?(PriorityQueue)
        raise TypeError, "can only merge another Hamster::PriorityQueue, got: #{other.inspect}"
      end
      return self if other.empty?
      shifted = other.root.add_shift(@counter)
      root    = @root ? @root.link(shifted, @comparator) : shifted
      entries =
        if @entries.empty?
          other.entries
        else
          # Elements are identified by id, so elements shared by both queues
          # (e.g. from a common ancestor version) appear only once; on
          # conflict this queue's version wins. The losing side's heap nodes
          # are simply skipped as stale when they reach the top.
          @entries.merge(other.entries) { |_id, mine, _theirs| mine }
        end
      self.class.alloc(root, entries, @counter + other.counter, @comparator)
    end

    # Yield each `[priority, value]` pair, smallest priority first, without
    # modifying the queue. Returns an `Enumerator` if no block is given.
    # @yield [priority, value]
    # @return [self, Enumerator]
    def each
      return enum_for(:each) unless block_given?
      root    = @root
      entries = @entries
      while root
        entry = root.entry
        if live?(entries, entry)
          yield [entry.priority, entry.value]
          entries = entries.delete(entry.id)
        end
        root = delete_min_node(root)
      end
      self
    end

    # Return an empty queue using the same comparator as this one.
    # @return [PriorityQueue]
    def clear
      self.class.alloc(nil, Hamster::Hash.empty, 0, @comparator)
    end

    def inspect
      "Hamster::PriorityQueue[size=#{size}]"
    end
    alias_method :to_s, :inspect

    protected

    attr_reader :root, :entries, :counter

    private

    # A heap node is current iff the entry index still holds this exact
    # version (identified by its unique stamp) of the element.
    def live?(entries, entry)
      current = entries.get(entry.id)
      !current.nil? && current.stamp == entry.stamp
    end

    def insert_node(node)
      @root ? @root.link(node, @comparator) : node
    end

    # Remove `node`'s entry and merge its children back together.
    def delete_min_node(node)
      Node.merge_pairs(node.materialize.children, @comparator)
    end
  end
end
