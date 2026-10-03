# frozen_string_literal: true

module Dry
  module Types
    # Thread-local tracking of values currently being traversed
    # by recursive types.
    #
    # A tracker is opened on the first application of a {Recursive}
    # type and stays alive until that application returns. Container
    # types push path segments while descending into their members.
    #
    # @api private
    module Traversal
      KEY = :"dry-types.recursive-traversal"

      # @return [Tracker, nil]
      #
      # @api private
      def self.current
        stack.last
      end

      # @api private
      def self.stack
        ::Thread.current[KEY] ||= []
      end

      # @api private
      def self.open
        tracker = Tracker.new
        stack << tracker
        yield
      ensure
        stack.delete(tracker)
      end

      # Push a path segment while descending into a container member.
      # When no traversal is active this is a no-op.
      #
      # @param [String] segment
      #
      # @api private
      def self.descend(segment)
        tracker = current

        if tracker.nil?
          yield
        else
          tracker.with_segment(segment) { yield }
        end
      end

      # Tracker of objects currently on the traversal path
      #
      # @api private
      class Tracker
        def initialize
          # object_id => path at which the object was first entered
          @entered = {}
          @path = ["$"]
        end

        # Immediate values cannot reference themselves
        #
        # @return [Boolean]
        #
        # @api private
        def trackable?(value)
          case value
          when ::Numeric, ::Symbol, nil, true, false
            false
          else
            true
          end
        end

        # Enter a value at a recursive type boundary. Raises when the
        # value is already on the current traversal path, i.e. the input
        # object references itself.
        #
        # @param [Object] value
        #
        # @raise [CyclicDataError]
        #
        # @api private
        def enter(value)
          return unless trackable?(value)

          id = value.object_id

          if @entered.key?(id)
            raise CyclicDataError.new(@path.join)
          end

          @entered[id] = @path.join
        end

        # @param [Object] value
        #
        # @api private
        def leave(value)
          return unless trackable?(value)

          @entered.delete(value.object_id)
        end

        # Push a path segment while descending into a container member
        #
        # @param [String] segment
        #
        # @api private
        def with_segment(segment)
          @path << segment
          yield
        ensure
          @path.pop
        end
      end
    end
  end
end
