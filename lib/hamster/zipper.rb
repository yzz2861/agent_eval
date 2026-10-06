require "hamster/hash"
require "hamster/vector"
require "hamster/list"
require "hamster/immutable"

module Hamster
  # A 'Zipper' is an immutable editing cursor into nested {Hamster::Hash} and
  # {Hamster::Vector} structures. It remembers the path from the root to the
  # current focus, so you can descend, edit, and move to siblings without
  # rebuilding the full path at every step.
  #
  # Every operation returns a new 'Zipper'; the receiver is never modified.
  # This means a single zipper can be "forked": two independent edits can be
  # derived from the same position and both will see consistent, unmodified
  # data.
  #
  # Locators are interpreted according to the collection being navigated,
  # never by a single unified rule:
  #
  # - For a {Hamster::Hash}, a locator is a key (any object), looked up with
  #   'key?'/'get'.
  # - For a {Hamster::Vector}, a locator is a zero-based 'Integer' index,
  #   bounds-checked against the vector's size.
  #
  # The same distinction applies to deletion: removing the focus from a
  # 'Vector' parent moves the focus *positionally* (to the element which slid
  # into the vacated index), while removing it from a 'Hash' parent moves the
  # focus back to the parent hash itself, since hash keys have no inherent
  # position.
  #
  # Rebuilding the root with {#root} only reconstructs the ancestors along
  # the path from the root to the focus; all untouched sibling subtrees are
  # shared structurally with the original structure.
  #
  # @example
  #   root = Hamster::Hash[:a => Hamster::Vector[1, 2, 3], :b => "keep"]
  #   z = Hamster::Zipper.new(root).down(:a).down(1).replace(99)
  #   z.root # => Hamster::Hash[:a => Hamster::Vector[1, 99, 3], :b => "keep"]
  #   z.root[:b].equal?(root[:b]) # => true (structural sharing)
  class Zipper
    include Immutable

    # Raised for invalid zipper navigation or editing operations, such as
    # moving up from the root or deleting the root.
    class Error < StandardError; end

    # @private
    # One step of the path from the root: the parent collection and the
    # locator (hash key or vector index) used to descend from it.
    class Crumb
      include Immutable

      attr_reader :parent, :locator

      def initialize(parent, locator)
        @parent = parent
        @locator = locator
      end
    end

    # The node currently in focus.
    attr_reader :focus

    # Create a zipper focused on 'root'. The optional second argument is
    # used internally to derive new zippers.
    def initialize(root, crumbs = EmptyList)
      @focus = root
      @crumbs = crumbs
    end

    # @return [Boolean] true if the focus is the root of the structure
    def root?
      @crumbs.empty?
    end

    # The locators (hash keys and vector indices) leading from the root to
    # the current focus.
    #
    # @return [Hamster::Vector]
    def path
      Vector.new(@crumbs.map(&:locator).reverse)
    end

    # Descend into a child of the focused collection.
    #
    # @param locator [Object] a key if the focus is a {Hamster::Hash}, or a
    #   zero-based 'Integer' index if it is a {Hamster::Vector}
    # @raise [KeyError] if the focus is a hash without the given key
    # @raise [IndexError] if the focus is a vector and the index is out of bounds
    # @raise [Error] if the focus is not a navigable collection
    # @return [Zipper]
    def down(locator)
      case focus
      when Hamster::Hash
        raise KeyError, "key not found: #{locator.inspect}" unless focus.key?(locator)
        child = focus.get(locator)
      when Hamster::Vector
        unless locator.is_a?(Integer) && locator >= 0 && locator < focus.size
          raise IndexError, "index #{locator.inspect} outside of vector bounds: 0...#{focus.size}"
        end
        child = focus.get(locator)
      else
        raise Error, "cannot descend into #{focus.class}"
      end
      self.class.new(child, @crumbs.cons(Crumb.new(focus, locator)))
    end

    # Move the focus back to the parent node.
    #
    # @raise [Error] if the focus is already the root
    # @return [Zipper]
    def up
      raise Error, "cannot go up: already at root" if root?
      crumb = @crumbs.head
      self.class.new(crumb.parent.put(crumb.locator, focus), @crumbs.tail)
    end

    # Move the focus to the next sibling: the element at the next index of a
    # vector parent, or the value of the next key (in iteration order) of a
    # hash parent.
    #
    # @raise [Error] if the focus is the root or has no next sibling
    # @return [Zipper]
    def next_sibling
      move_to_sibling(1, "last")
    end

    # Move the focus to the previous sibling: the element at the previous
    # index of a vector parent, or the value of the previous key (in
    # iteration order) of a hash parent.
    #
    # @raise [Error] if the focus is the root or has no previous sibling
    # @return [Zipper]
    def previous_sibling
      move_to_sibling(-1, "first")
    end

    # Replace the focused node with 'node'.
    #
    # @param node [Object] the new focus
    # @return [Zipper]
    def replace(node)
      self.class.new(node, @crumbs)
    end

    # Replace the focused node with the result of yielding it to the block.
    #
    # @yield [focus] the currently focused node
    # @yieldreturn [Object] the new focus
    # @return [Zipper]
    def modify(&block)
      replace(block.call(focus))
    end

    # Insert into the focused collection, following the collection's own
    # rules: 'insert(key, value)' on a {Hamster::Hash} focus (like
    # {Hamster::Hash#put}), or 'insert(index, item)' on a {Hamster::Vector}
    # focus (like {Hamster::Vector#insert}). The focus stays on the modified
    # collection.
    #
    # @raise [Error] if the focus is not a collection which supports insertion
    # @return [Zipper]
    def insert(*args)
      case focus
      when Hamster::Hash
        replace(focus.put(*args))
      when Hamster::Vector
        replace(focus.insert(*args))
      else
        raise Error, "cannot insert into #{focus.class}"
      end
    end

    # Delete the focused node from its parent collection. Where the focus
    # lands afterwards depends on the parent collection:
    #
    # - {Hamster::Vector} parent: the focus moves to the element which slid
    #   into the vacated index (the former right sibling). If the deleted
    #   element was the last one, the focus moves to the new last element
    #   (the former left sibling). If the vector becomes empty, the focus
    #   moves to the parent vector itself.
    # - {Hamster::Hash} parent: keys have no position, so the focus moves to
    #   the parent hash itself (with the key removed).
    #
    # @raise [Error] if the focus is the root
    # @return [Zipper]
    def delete
      raise Error, "cannot delete the root" if root?
      crumb = @crumbs.head
      parent = crumb.parent
      case parent
      when Hamster::Vector
        new_parent = parent.delete_at(crumb.locator)
        if new_parent.empty?
          self.class.new(new_parent, @crumbs.tail)
        else
          index = crumb.locator < new_parent.size ? crumb.locator : new_parent.size - 1
          self.class.new(new_parent.get(index), @crumbs.tail.cons(Crumb.new(new_parent, index)))
        end
      when Hamster::Hash
        self.class.new(parent.delete(crumb.locator), @crumbs.tail)
      end
    end

    # Rebuild the root of the structure, reflecting all edits made along the
    # current path. Only the ancestors of the focus are reconstructed; all
    # other subtrees are shared with the original structure.
    #
    # @return [Object] the (possibly modified) root node
    def root
      @crumbs.reduce(focus) { |node, crumb| crumb.parent.put(crumb.locator, node) }
    end

    private

    def move_to_sibling(offset, edge)
      raise Error, "cannot move to a sibling: already at root" if root?
      crumb = @crumbs.head
      parent = crumb.parent
      case parent
      when Hamster::Vector
        index = crumb.locator + offset
        if index < 0 || index >= parent.size
          raise Error, "cannot move to a sibling: already at #{edge} sibling"
        end
        self.class.new(parent.get(index), @crumbs.tail.cons(Crumb.new(parent, index)))
      when Hamster::Hash
        keys = parent.keys.to_a
        position = keys.index { |key| key.eql?(crumb.locator) } + offset
        if position < 0 || position >= keys.size
          raise Error, "cannot move to a sibling: already at #{edge} sibling"
        end
        key = keys[position]
        self.class.new(parent.get(key), @crumbs.tail.cons(Crumb.new(parent, key)))
      end
    end
  end
end
