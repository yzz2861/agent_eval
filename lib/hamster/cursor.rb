require "hamster/immutable"
require "hamster/hash"
require "hamster/vector"

module Hamster
  # A "zipper"-style editing cursor for nested {Hamster::Hash} and
  # {Hamster::Vector} structures.
  #
  # A `Cursor` points at a *focus* node somewhere inside a (possibly deeply
  # nested) data structure, and remembers the path of crumbs leading back to
  # the root. You can descend into children ({#down}), climb back to the
  # parent ({#up}), {#replace} the focus, and edit a focused collection in
  # place ({#put}, {#insert}, {#delete}, {#delete_at}). {#to_root} folds the
  # cursor back up to a brand new root, rebuilding only the ancestors along
  # the path; every untouched sibling subtree is shared structurally with the
  # original structure.
  #
  # Cursors are immutable: every operation returns a new `Cursor` and leaves
  # the receiver untouched, so any number of cursors can fork from the same
  # position and evolve independently.
  #
  # Hash keys and Vector positions are deliberately *not* unified into one
  # addressing scheme:
  #
  # - {#down} dispatches on the type of the focus. On a {Hamster::Hash} the
  #   argument is a key; on a {Hamster::Vector} it must be an `Integer`
  #   index (negative indices count from the end).
  # - {#delete} removes a key from a focused {Hamster::Hash}, while
  #   {#delete_at} removes an index from a focused {Hamster::Vector}. Each
  #   raises {Cursor::Error} on the other collection type.
  # - {#remove} deletes the focus itself from its parent and moves the focus
  #   *up* to the parent. For a {Hamster::Vector} parent the element at the
  #   recorded index is removed and all later siblings shift down by one
  #   position, so descending with the same index again yields the former
  #   right sibling. For a {Hamster::Hash} parent the key is simply gone.
  #
  # @example
  #   root = Hamster::Hash["a" => Hamster::Vector[1, 2, 3], "b" => 4]
  #   cursor = Hamster::Cursor.new(root).down("a").down(1)
  #   cursor.focus              # => 2
  #   cursor.replace(99).to_root
  #   # => Hamster::Hash["a" => Hamster::Vector[1, 99, 3], "b" => 4]
  #
  class Cursor
    include Immutable

    # Raised on invalid navigation or when an edit does not match the type of
    # the focused collection.
    Error = Class.new(StandardError)

    # @private
    class Crumb
      include Immutable

      attr_reader :parent, :location

      def initialize(parent, location)
        @parent = parent
        @location = location
      end
    end

    # @private
    class HashCrumb < Crumb
      def rebuild(node)
        parent.put(location, node)
      end

      def remove
        parent.delete(location)
      end
    end

    # @private
    class VectorCrumb < Crumb
      def rebuild(node)
        parent.put(location, node)
      end

      def remove
        parent.delete_at(location)
      end
    end

    private_constant :Crumb, :HashCrumb, :VectorCrumb

    # The node the cursor currently points at.
    attr_reader :focus

    # Create a cursor focused on `node`. Normally `node` is the root of a
    # nested structure and the cursor starts with an empty path.
    #
    # @param node [Object] the node to focus on
    # @return [Cursor]
    def initialize(node, crumbs = EmptyVector)
      @focus = node
      @crumbs = crumbs
    end

    # @return [Boolean] true if the cursor is at the root of the structure
    def root?
      @crumbs.empty?
    end

    # @return [Integer] how many steps below the root the focus is
    def depth
      @crumbs.size
    end

    # The sequence of hash keys and vector indices leading from the root to
    # the focus.
    #
    # @return [Vector]
    def path
      @crumbs.map(&:location)
    end

    # Descend into a child of the focus. On a {Hamster::Hash} focus,
    # `location` is a key; on a {Hamster::Vector} focus it must be an
    # `Integer` index (negative indices count from the end).
    #
    # @param location [Object] hash key or vector index to descend into
    # @return [Cursor]
    # @raise [KeyError] if the focus is a {Hamster::Hash} without the key
    # @raise [IndexError] if the focus is a {Hamster::Vector} and the index
    #   is out of bounds
    # @raise [TypeError] if the focus is a {Hamster::Vector} and `location`
    #   is not an `Integer`
    # @raise [Error] if the focus is not a {Hamster::Hash} or {Hamster::Vector}
    def down(location)
      case @focus
      when Hamster::Hash
        raise KeyError, "key not found: #{location.inspect}" unless @focus.key?(location)
        descend(HashCrumb.new(@focus, location), @focus.get(location))
      when Hamster::Vector
        index = normalize_index(location)
        descend(VectorCrumb.new(@focus, index), @focus.get(index))
      else
        raise Error, "cannot descend into #{@focus.class}"
      end
    end

    # Climb back to the parent, rebuilding it with the (possibly replaced)
    # focus in place.
    #
    # @return [Cursor]
    # @raise [Error] if the cursor is already at the root
    def up
      raise Error, "cannot go up from the root" if root?
      self.class.new(@crumbs.last.rebuild(@focus), @crumbs.pop)
    end

    # Fold the cursor all the way back up and return the rebuilt root node.
    # Only the ancestors along the cursor's path are rebuilt; every other
    # subtree is shared with the original structure.
    #
    # @return [Object] the root node
    def to_root
      cursor = self
      cursor = cursor.up until cursor.root?
      cursor.focus
    end

    # @param node [Object] the new focus
    # @return [Cursor] a cursor at the same position, focused on `node`
    def replace(node)
      self.class.new(node, @crumbs)
    end

    # Replace the focus with the result of yielding it to the block.
    #
    # @yield [focus] the current focus
    # @yieldreturn [Object] the new focus
    # @return [Cursor]
    def modify
      replace(yield(@focus))
    end

    # Store `value` under `key` in the focused {Hamster::Hash}. The focus
    # stays on the updated hash.
    #
    # @return [Cursor]
    # @raise [Error] if the focus is not a {Hamster::Hash}
    def put(key, *args, &block)
      ensure_focus(Hamster::Hash, :put)
      replace(@focus.put(key, *args, &block))
    end

    # Insert `items` into the focused {Hamster::Vector} at `index`. The
    # focus stays on the updated vector.
    #
    # @return [Cursor]
    # @raise [Error] if the focus is not a {Hamster::Vector}
    def insert(index, *items)
      ensure_focus(Hamster::Vector, :insert)
      replace(@focus.insert(index, *items))
    end

    # Remove `key` from the focused {Hamster::Hash}. The focus stays on the
    # updated hash.
    #
    # @return [Cursor]
    # @raise [Error] if the focus is not a {Hamster::Hash}
    def delete(key)
      ensure_focus(Hamster::Hash, :delete)
      replace(@focus.delete(key))
    end

    # Remove the element at `index` from the focused {Hamster::Vector}. The
    # focus stays on the updated vector.
    #
    # @return [Cursor]
    # @raise [Error] if the focus is not a {Hamster::Vector}
    def delete_at(index)
      ensure_focus(Hamster::Vector, :delete_at)
      replace(@focus.delete_at(index))
    end

    # Remove the focus itself from its parent and move the focus up to the
    # parent. For a {Hamster::Hash} parent the key is deleted; for a
    # {Hamster::Vector} parent the element at the recorded index is deleted
    # and later siblings shift down by one position.
    #
    # @return [Cursor]
    # @raise [Error] if the cursor is at the root
    def remove
      raise Error, "cannot remove the root" if root?
      self.class.new(@crumbs.last.remove, @crumbs.pop)
    end

    private

    def descend(crumb, node)
      self.class.new(node, @crumbs.add(crumb))
    end

    def normalize_index(location)
      unless location.is_a?(Integer)
        raise TypeError, "vector index must be an Integer, got #{location.class}"
      end
      index = location < 0 ? location + @focus.size : location
      if index < 0 || index >= @focus.size
        raise IndexError, "index #{location} outside of vector bounds"
      end
      index
    end

    def ensure_focus(type, operation)
      unless @focus.is_a?(type)
        raise Error, "##{operation} requires a #{type} focus, but the focus is #{@focus.class}"
      end
    end
  end
end
