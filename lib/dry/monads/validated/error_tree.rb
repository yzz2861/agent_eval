# frozen_string_literal: true

module Dry
  module Monads
    class Validated
      # ErrorTree is an optional error carrier for {Validated::Invalid}.
      # Plain arrays only give a flat list of errors, which makes it hard to
      # tell which nested field each error belongs to. ErrorTree keeps every
      # error attached to a path so that the frontend can locate it precisely.
      #
      # A path is an array of {Key} and {Index} segments. Object keys and
      # array indices are represented by different segment types, so a symbol
      # named `:items` is never confused with position 0 of an array. Bare
      # symbols and strings are coerced to keys, integers to indices.
      #
      # Any number of errors may be attached to the same path. ErrorTree acts
      # as a semigroup: trees are merged with `+` (also used by
      # {Validated::Invalid#apply}). Merging and prefixing never mutate the
      # receiver or the arguments and never wrap or drop the original error
      # objects.
      #
      # @example building a tree
      #   ErrorTree = Dry::Monads::Validated::ErrorTree
      #
      #   tree = ErrorTree.new(
      #     :name => :blank,
      #     [:addresses, 0, :street] => [:blank, :too_short]
      #   )
      #
      #   tree[[:addresses, 0, :street]]
      #   # => [:blank, :too_short]
      #
      # @example combining independent validations
      #   name_errors = ErrorTree.new(:name => :blank)
      #   age_errors  = ErrorTree.new(:age => :not_an_integer)
      #
      #   name_errors + age_errors
      #   # => ErrorTree({[Key(:name)]=>[:blank], [Key(:age)]=>[:not_an_integer]})
      #
      class ErrorTree
        include Dry::Equalizer(:to_h)

        # Path of errors attached to the value itself rather than a field
        ROOT_PATH = [].freeze

        # A single path segment. Segments are value objects.
        #
        # @abstract Use {Key} or {Index} instead
        class Segment
          include Dry::Equalizer(:value)

          # @return [Object] the wrapped key or index
          attr_reader :value

          def initialize(value)
            @value = value.is_a?(::String) ? value.dup.freeze : value
            freeze
          end
        end

        # Path segment that denotes an object/hash key.
        class Key < Segment
          # Coerces the value to a key.
          #
          # @param value [Object]
          # @return [Key]
          def self.[](value) = new(value)

          # @return [String]
          def inspect = "Key(#{value.inspect})"
        end

        # Path segment that denotes an array position.
        class Index < Segment
          # Coerces the value to an integer index.
          #
          # @param value [#to_int, Integer]
          # @return [Index]
          def self.[](value) = new(value)

          def initialize(value)
            super(value.is_a?(::Integer) ? value : Integer(value))
          end

          # @return [String]
          def inspect = "Index(#{value.inspect})"
        end

        # Coerces a path-like value to a frozen path.
        #
        # @param path [Segment, Array<Object>, Object]
        # @return [Array<Segment>] frozen path
        def self.coerce_path(path)
          segments =
            case path
            when ::Array then path.map { |segment| coerce_segment(segment) }
            else [coerce_segment(path)]
            end

          segments.freeze
        end

        # Coerces a single value to a path segment.
        #
        # @param segment [Segment, Symbol, String, Integer]
        # @return [Segment]
        def self.coerce_segment(segment)
          case segment
          when Segment then segment
          when ::Symbol, ::String then Key.new(segment)
          when ::Integer then Index.new(segment)
          else
            raise ::ArgumentError,
              "Cannot use #{segment.inspect} as a path segment: " \
              "wrap object keys with Key[] and array positions with Index[]"
          end
        end

        # Convenience constructor, see {#initialize} for accepted values.
        #
        # @return [ErrorTree]
        def self.[](*sources) = new(*sources)

        # Merges any number of trees without mutating the arguments.
        #
        # @param trees [Array<ErrorTree, Hash, Array<Array>>]
        # @return [ErrorTree]
        def self.merge(*trees) = EMPTY.merge(*trees)

        # Builds an error tree.
        #
        # @param sources [Array<nil, ErrorTree, Hash, Array<Array>>]
        #   - another ErrorTree is copied;
        #   - a Hash maps paths to errors; an Array value is treated as several
        #     errors attached to the same path, any other value as one error;
        #   - an Array of `[path, error]` pairs attaches one error per pair,
        #     use this form when a single error object is itself an Array.
        def initialize(*sources)
          @errors = {}
          sources.each { absorb(@errors, _1) unless _1.nil? }
          finalize(@errors)
          freeze
        end

        # Returns errors attached to the path. Path segments can be passed as
        # a single array or splatted. Returns an empty frozen array when the
        # path has no errors.
        #
        # @param path [Array<Object>] segments
        # @return [Array<Object>] frozen, possibly empty
        def [](*path)
          path = path.first if path.size == 1 && path.first.is_a?(::Array)
          @errors.fetch(self.class.coerce_path(path), EMPTY_ERRORS)
        end

        # Same as {#[]} but raises KeyError when the path is missing,
        # unless a default value or block is given.
        #
        # @return [Array<Object>]
        def fetch(path = ROOT_PATH, *default, &block)
          @errors.fetch(self.class.coerce_path(path), *default, &block)
        end

        # @return [Boolean] whether the path has any errors
        def key?(path) = @errors.key?(self.class.coerce_path(path))
        alias_method :has_path?, :key?

        # All paths that carry at least one error.
        #
        # @return [Array<Array<Segment>>]
        def paths = @errors.keys

        # Total number of errors across all paths.
        #
        # @return [Integer]
        def size
          @errors.sum(0) { |_, errors| errors.size }
        end

        # @return [Boolean]
        def empty? = @errors.empty?

        # Yields each path with its errors in insertion order.
        #
        # @yieldparam path [Array<Segment>] frozen path
        # @yieldparam errors [Array<Object>] frozen errors of the path
        # @return [Enumerator, self]
        def each(&block)
          return @errors.each unless block

          @errors.each(&block)
          self
        end

        # Returns a safe copy of the underlying mapping. Mutating the returned
        # Hash or Arrays never affects the tree.
        #
        # @return [Hash{Array<Segment> => Array<Object>}]
        def to_h
          @errors.transform_values(&:dup)
        end

        # Returns a tree with `prefix` prepended to every path. Does not mutate
        # self. A tree prefixed with an empty path is returned unchanged.
        #
        # @example attaching a subtree to an array element
        #   address_errors.prefix(:addresses, 0)
        #
        # @param prefix [Array<Object>] path segments (array or splatted)
        # @return [ErrorTree]
        def prefix(*prefix)
          prefix = prefix.first if prefix.size == 1 && prefix.first.is_a?(::Array)
          prefix_path = self.class.coerce_path(prefix)

          return self if prefix_path.empty?

          errors = @errors.to_h do |path, errors|
            [prefix_path + path, errors.dup]
          end

          self.class.send(:from_errors, errors)
        end

        # Merges other sources into a new tree. Errors are appended path by
        # path in the given order; the receiver is left untouched.
        #
        # @param others [Array<ErrorTree, Hash, Array<Array>>]
        # @return [ErrorTree]
        def merge(*others)
          errors = @errors.transform_values(&:dup)
          others.each { absorb(errors, _1) }
          self.class.send(:from_errors, errors)
        end

        # Semigroup concatenation used by Validated::Invalid#apply. Another
        # ErrorTree (or a buildable source) is merged path by path. An Array or
        # a List is appended to the root path, so that trees still compose when
        # errors are combined with plain, non-tree values.
        #
        # @param other [ErrorTree, Hash, Array<Array>, List, Array, Object]
        # @return [ErrorTree]
        def +(other)
          case other
          when self.class
            merge(other)
          when List, ::Array
            append_root(other.to_ary)
          else
            append_root([other])
          end
        end

        # @return [String]
        def inspect = "ErrorTree(#{@errors.inspect})"
        alias_method :to_s, :inspect

        # @param other [Object]
        # @return [Boolean]
        def ===(other)
          other.instance_of?(self.class) && to_h == other.to_h
        end

        # Builds a frozen tree from an unfrozen mapping.
        #
        # @param errors [Hash]
        # @return [ErrorTree]
        def self.from_errors(errors)
          errors.each_key { |path| path.freeze unless path.frozen? }
          errors.each_value(&:freeze)
          errors.freeze
          allocate.tap do |tree|
            tree.instance_variable_set(:@errors, errors)
            tree.freeze
          end
        end
        private_class_method :from_errors

        private

        EMPTY_ERRORS = [].freeze

        def append_root(errors_at_root)
          errors = @errors.transform_values(&:dup)
          errors[ROOT_PATH] = errors.fetch(ROOT_PATH, []).dup.concat(errors_at_root)
          self.class.send(:from_errors, errors)
        end

        def absorb(errors, source)
          case source
          when self.class
            source.each do |path, source_errors|
              errors[path] = (errors[path] || []).concat(source_errors)
            end
          when ::Hash
            source.each do |path, value|
              add(errors, path, value.is_a?(::Array) ? value : [value])
            end
          when ::Array
            source.each do |pair|
              unless pair.is_a?(::Array) && pair.size == 2
                raise ::ArgumentError,
                  "Expected a [path, error] pair, got #{pair.inspect}"
              end

              add(errors, pair[0], [pair[1]])
            end
          else
            raise ::ArgumentError,
              "Cannot absorb #{source.inspect} into an ErrorTree"
          end
        end

        def add(errors, path, path_errors)
          coerced_path = self.class.coerce_path(path)
          errors[coerced_path] = (errors[coerced_path] || []).concat(path_errors)
        end

        def finalize(errors)
          errors.each_value(&:freeze)
          errors.freeze
        end

        # An empty, reusable tree
        EMPTY = new
      end
    end
  end
end
