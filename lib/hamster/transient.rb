module Hamster
  # Error raised when a transient editor (yielded by {Hash#mutate} or
  # {Vector#mutate}) is used after its editing block has exited, or from a
  # thread other than the one where it was created.
  class TransientError < StandardError; end

  # A transient, mutable "editor" for a {Hamster::Hash}, yielded by
  # {Hash#mutate}. It starts out with the same contents as the hash it was
  # created from, and applies updates in place, reusing the nodes which are
  # private to the editing session instead of copying the update path on
  # every change. Nodes shared with the original (immutable) hash are never
  # modified.
  #
  # The editor is only valid inside the block passed to {Hash#mutate}, and
  # only on the thread where {Hash#mutate} was called. Using it afterwards
  # (for example through a saved reference) or from another thread raises
  # {TransientError}.
  #
  # @private
  class TransientHash
    def initialize(hash)
      @trie    = hash.instance_variable_get(:@trie)
      @default = hash.default_proc
      @class   = hash.class
      @owned   = {}.compare_by_identity
      @thread  = Thread.current
      @valid   = true
    end

    # Return the number of key/value pairs currently in the editor.
    # @return [Integer]
    def size
      ensure_valid!
      @trie.size
    end
    alias :length :size

    # Return `true` if the editor currently contains no key/value pairs.
    # @return [Boolean]
    def empty?
      ensure_valid!
      @trie.empty?
    end

    # Return `true` if the given key is currently present.
    # @return [Boolean]
    def key?(key)
      ensure_valid!
      @trie.key?(key)
    end
    alias :has_key? :key?
    alias :include? :key?
    alias :member? :key?

    # Return the value currently associated with the given key. If the key is
    # not present, return the result of the default proc (if the hash this
    # editor was created from has one), or `nil`.
    # @return [Object]
    def get(key)
      ensure_valid!
      entry = @trie.get(key)
      if entry
        entry[1]
      elsif @default
        @default.call(key)
      end
    end
    alias :[] :get

    # Associate the given key with the given value, replacing any existing
    # association. Like {Hash#put}, a block can be used to compute the new
    # value from the current one.
    #
    # @return [self]
    def put(key, value = yield(get(key)))
      ensure_valid!
      @trie = @trie.editable_copy(@owned)
      @trie.transient_put!(key, value, @owned)
      self
    end

    # Associate the given key with the given value. Does not support
    # {#put}'s block form.
    #
    # @return [Object] the stored value
    def store(key, value)
      put(key, value)
      value
    end
    alias :[]= :store

    # Remove the given key and its associated value, if present.
    #
    # @return [Object] the previously associated value, or `nil` if the key
    #   was not present
    def delete(key)
      ensure_valid!
      entry = @trie.get(key)
      if entry
        @trie = @trie.editable_copy(@owned)
        @trie.transient_delete!(key, @owned)
        entry[1]
      end
    end

    # @private
    def persist!
      @class.alloc(@trie, @default)
    end

    # @private
    def invalidate!
      @valid = false
    end

    private

    def ensure_valid!
      if !@valid
        raise TransientError, "transient editor is no longer valid: the Hash#mutate block has exited"
      elsif !Thread.current.equal?(@thread)
        raise TransientError, "transient editor may only be used on the thread where Hash#mutate was called"
      end
    end
  end

  # A transient, mutable "editor" for a {Hamster::Vector}, yielded by
  # {Vector#mutate}. It starts out with the same contents as the vector it
  # was created from, and applies updates in place, reusing the nodes which
  # are private to the editing session instead of copying the update path on
  # every change. Nodes shared with the original (immutable) vector are
  # never modified.
  #
  # The editor is only valid inside the block passed to {Vector#mutate}, and
  # only on the thread where {Vector#mutate} was called. Using it afterwards
  # (for example through a saved reference) or from another thread raises
  # {TransientError}.
  #
  # @private
  class TransientVector
    def initialize(vector)
      @root   = vector.instance_variable_get(:@root)
      @size   = vector.size
      @levels = vector.instance_variable_get(:@levels)
      @class  = vector.class
      @owned  = {}.compare_by_identity
      @thread = Thread.current
      @valid  = true
    end

    # Return the number of items currently in the editor.
    # @return [Integer]
    def size
      ensure_valid!
      @size
    end
    alias :length :size

    # Return `true` if the editor currently contains no items.
    # @return [Boolean]
    def empty?
      ensure_valid!
      @size == 0
    end

    # Return the item currently at the given index. Negative indexes count
    # back from the end. Returns `nil` if the index is out of bounds.
    # @return [Object]
    def get(index)
      ensure_valid!
      return nil if @size == 0
      index += @size if index < 0
      return nil if index >= @size || index < 0
      node = @root
      bitshift = @levels * Vector::BITS_PER_LEVEL
      while bitshift > 0
        node = node[(index >> bitshift) & Vector::INDEX_MASK]
        bitshift -= Vector::BITS_PER_LEVEL
      end
      node[index & Vector::INDEX_MASK]
    end
    alias :[] :get
    alias :at :get

    # Replace the item at the given index. Negative indexes count back from
    # the end. Like {Vector#put}, indexes past the current end fill the gap
    # with `nil`s.
    #
    # @return [Object] the stored item
    # @raise [IndexError] if the index is out of bounds
    def set(index, item)
      ensure_valid!
      raise IndexError, "index #{index} outside of vector bounds" if index < -@size
      index += @size if index < 0
      if index >= @size
        push(nil) while @size < index
        push(item)
      else
        own_root!
        node = @root
        bitshift = @levels * Vector::BITS_PER_LEVEL
        while bitshift > 0
          slot = (index >> bitshift) & Vector::INDEX_MASK
          child = own_node(node[slot])
          node[slot] = child
          node = child
          bitshift -= Vector::BITS_PER_LEVEL
        end
        node[index & Vector::INDEX_MASK] = item
      end
      item
    end
    alias :[]= :set

    # Add an item to the end.
    #
    # @return [self]
    def push(item)
      ensure_valid!
      while @size >= (1 << (Vector::BITS_PER_LEVEL * (@levels + 1)))
        @root = register([@root])
        @levels += 1
      end
      own_root!
      node = @root
      bitshift = @levels * Vector::BITS_PER_LEVEL
      while bitshift > 0
        slot = (@size >> bitshift) & Vector::INDEX_MASK
        child = node[slot]
        node[slot] = child = child.nil? ? register([]) : own_node(child)
        node = child
        bitshift -= Vector::BITS_PER_LEVEL
      end
      node[@size & Vector::INDEX_MASK] = item
      @size += 1
      self
    end
    alias :<< :push
    alias :add :push
    alias :append :push

    # Remove the last item.
    #
    # @return [Object] the removed item, or `nil` if the editor is empty
    def pop
      ensure_valid!
      return nil if @size == 0
      own_root!
      index = @size - 1
      node = @root
      parents = []
      bitshift = @levels * Vector::BITS_PER_LEVEL
      while bitshift > 0
        slot = (index >> bitshift) & Vector::INDEX_MASK
        child = own_node(node[slot])
        node[slot] = child
        parents << node
        node = child
        bitshift -= Vector::BITS_PER_LEVEL
      end
      item = node.pop
      @size -= 1
      # prune nodes left empty, from the leaf up to (but excluding) the root
      while node.empty? && !parents.empty?
        node = parents.pop
        node.pop
      end
      # collapse the root while it has a single child
      while @levels > 0 && @root.size == 1
        @root = @root[0]
        @levels -= 1
      end
      item
    end

    # @private
    def persist!
      @owned.each_key { |node| node.freeze }
      @class.alloc(@root, @size, @levels)
    end

    # @private
    def invalidate!
      @valid = false
    end

    private

    def ensure_valid!
      if !@valid
        raise TransientError, "transient editor is no longer valid: the Vector#mutate block has exited"
      elsif !Thread.current.equal?(@thread)
        raise TransientError, "transient editor may only be used on the thread where Vector#mutate was called"
      end
    end

    def register(node)
      @owned[node] = true
      node
    end

    def own_node(node)
      if @owned.key?(node)
        node
      else
        register(node.dup)
      end
    end

    def own_root!
      @root = own_node(@root)
    end
  end
end
