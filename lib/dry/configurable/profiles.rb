# frozen_string_literal: true

module Dry
  module Configurable
    # A registry of named profiles, resolving their (possibly multiple)
    # inheritance chains through C3 linearization.
    #
    # C3 is the same algorithm Ruby uses for its own method resolution order:
    # it produces a deterministic order in which a profile always precedes its
    # parents, the local declaration order of parents is preserved, and every
    # profile appears exactly once (so a shared ancestor in a diamond cannot
    # be applied twice). When the declared constraints are contradictory, the
    # merge fails and {ProfileLinearizationError} is raised instead of
    # silently picking an arbitrary order.
    #
    # @api private
    class Profiles
      include Dry::Equalizer(:profiles)

      include Enumerable

      # @api private
      attr_reader :profiles

      # @api private
      def initialize(profiles = EMPTY_ARRAY)
        @profiles = profiles.each_with_object({}) { |profile, m| m[profile.name] = profile }
        @linearizations = {}
      end

      # @api private
      private def initialize_copy(source)
        @profiles = source.profiles.dup
        @linearizations = {}
      end

      # @api private
      def <<(profile)
        @linearizations = {}
        profiles[profile.name] = profile
        self
      end

      # Returns the profile for the given name, if defined.
      #
      # @return [Profile, nil]
      #
      # @api public
      def [](name)
        profiles[name.to_sym]
      end

      # Returns true if a profile with the given name is defined.
      #
      # @return [Boolean]
      #
      # @api public
      def key?(name)
        profiles.key?(name.to_sym)
      end

      # Returns the names of all defined profiles.
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def keys
        profiles.keys
      end

      # @api public
      def each(&)
        profiles.each_value(&)
      end

      # Returns the C3 linearization of the profile with the given name.
      #
      # The returned list is ordered from highest to lowest precedence: it
      # starts with the profile itself and ends with its most ancestral
      # parents. Applying the profiles in reverse order therefore lets more
      # specific profiles override the values of their ancestors, with every
      # profile applied exactly once.
      #
      # @param [String, Symbol] name
      #
      # @return [Array<Symbol>]
      #
      # @raise [UnknownProfileError] if the profile (or one of its declared
      #   parents) is not defined
      # @raise [CyclicProfileInheritanceError] if the inheritance chain
      #   contains a cycle
      # @raise [ProfileLinearizationError] if the declared precedence
      #   constraints are contradictory and no consistent order exists
      #
      # @api public
      def linearize(name)
        name = name.to_sym
        @linearizations[name] ||= compute_linearization(name).freeze
      end

      private

      def compute_linearization(name, stack = EMPTY_ARRAY)
        if stack.include?(name)
          raise CyclicProfileInheritanceError,
            "cyclic profile inheritance: #{(stack + [name]).join(" -> ")}"
        end

        unless (profile = self[name])
          raise UnknownProfileError, "+#{name}+ is not a defined profile"
        end

        parent_lists = profile.parents.map { |parent|
          compute_linearization(parent, stack + [name])
        }

        [name] + merge(parent_lists + [profile.parents])
      end

      # Merges the given precedence lists into a single order, C3-style:
      # repeatedly takes the first head that does not appear in the tail of
      # any remaining list. Fails when every remaining head is blocked, which
      # means the constraints contradict each other.
      def merge(sequences)
        sequences = sequences.map(&:dup).reject(&:empty?)
        result = []

        until sequences.empty?
          candidate = sequences.map(&:first).find { |head|
            sequences.none? { |seq| seq[1..]&.include?(head) }
          }

          unless candidate
            constraints = sequences.map { |seq| seq.join(" < ") }.join(", ")
            raise ProfileLinearizationError,
              "cannot linearize profile inheritance: contradictory precedence " +              "constraints (#{constraints})"
          end

          result << candidate
          sequences.each { |seq| seq.shift if seq.first == candidate }
          sequences.reject!(&:empty?)
        end

        result
      end
    end
  end
end
