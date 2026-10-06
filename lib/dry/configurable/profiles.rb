# frozen_string_literal: true

module Dry
  module Configurable
    # Registry of named profiles declared on a configurable class.
    #
    # Each profile may inherit from one or more base profiles. The effective
    # inheritance order is computed with the C3 linearization (the same
    # algorithm used to linearize Ruby's own ancestors): it is deterministic,
    # preserves every declared "child before parent" and "earlier parent before
    # later parent" constraint, visits each ancestor at most once, and raises
    # {ProfileLinearizationError} when the constraints contradict each other.
    #
    # When resolving a profile, the linearized profiles are merged from lowest
    # precedence (furthest ancestor) to highest precedence (the profile
    # itself), so each later layer wins. Every resulting {Config} is built
    # independently with freshly copied mutable values.
    #
    # @api public
    class Profiles
      # @api private
      def initialize
        @profiles = {}
        @lineages = {}
      end

      # @api private
      private def initialize_copy(source)
        @profiles = source.instance_variable_get(:@profiles).dup
        @lineages = {}
      end

      # Registers a new profile.
      #
      # @param name [Symbol]
      # @param inherits [Array<Symbol>] base profile names, in priority order
      #
      # @return [Profile]
      #
      # @api private
      def register(name, inherits, block, settings: nil)
        name = name.to_sym

        if @profiles.key?(name)
          raise ProfileError, "profile #{name.inspect} is already defined"
        end

        tree = ProfileDSL.new(&block).tree
        profile = Profile.new(name, inherits.map(&:to_sym), tree)

        # Validate overrides eagerly against the settings known at definition
        # time, so a typo fails loudly rather than at first resolution.
        validate_tree(tree, settings, []) if settings

        unknown = profile.parents.reject { |parent| @profiles.key?(parent) }
        unless unknown.empty?
          raise ProfileError,
            "profile #{name.inspect} inherits from unknown " \
            "#{unknown.size == 1 ? "profile" : "profiles"} " \
            "#{unknown.map(&:inspect).join(", ")} " \
            "(known profiles: #{names.inspect})"
        end

        @profiles[name] = profile
        @lineages = {}
        profile
      end

      # @return [Profile, nil]
      #
      # @api private
      def [](name)
        @profiles[name.to_sym]
      end

      # @return [Array<Symbol>] the names of all registered profiles, in
      #   declaration order
      #
      # @api public
      def names
        @profiles.keys
      end

      # Returns the resolved linearization of the named profile.
      #
      # The returned array starts with the profile itself and continues with
      # each ancestor exactly once, in descending precedence order.
      #
      # @param name [Symbol]
      #
      # @return [Array<Symbol>]
      #
      # @raise [ProfileError] if the profile does not exist
      # @raise [ProfileLinearizationError] if the profiles cannot be linearized
      #
      # @api public
      def lineage(name)
        @lineages[name.to_sym] ||= linearize!(fetch(name).name)
      end

      # Builds an independent {Config} for the named profile.
      #
      # @param name [Symbol]
      # @param settings [Settings]
      # @param config_class [Class]
      #
      # @return [Config]
      #
      # @api private
      def build_config(name, settings, config_class)
        profile_names = lineage(name)

        effective = profile_names.reverse_each.with_object({}) { |ancestor, merged|
          merge_tree(merged, @profiles[ancestor].tree)
        }

        validate_tree(effective, settings, [])

        config_class.new(settings).tap { |config| apply_tree(config, effective, settings) }
      end

      private

      def fetch(name)
        @profiles.fetch(name.to_sym) do
          raise ProfileError,
            "profile #{name.inspect} is not defined (known profiles: #{names.inspect})"
        end
      end

      # C3 linearization of `name`.
      #
      #   L(x) = [x] + merge(L(p1), ..., L(pn), [p1, ..., pn])
      def linearize!(name, visiting = [])
        return @lineages[name] if @lineages.key?(name)

        if visiting.include?(name)
          cycle = (visiting + [name]).map(&:inspect).join(" -> ")
          raise ProfileLinearizationError,
            "cannot linearize profiles: cyclic inheritance detected (#{cycle})"
        end

        profile = fetch(name)

        parent_lineages = profile.parents.map do |parent|
          linearize!(parent, visiting + [name])
        end

        lists = parent_lineages + [profile.parents]
        lists = lists.reject(&:empty?)

        result = [name] + c3_merge!(name, lists)
        @lineages[name] = result
      end

      def c3_merge!(name, lists)
        result = []
        remaining = lists.map(&:dup)

        until remaining.empty?
          # Consider heads in list order (duplicates across lists are fine): the
          # first head that is never in another list's tail wins, which keeps
          # earlier parents ahead of later parents.
          candidate = remaining.flatten.find do |candidate|
            remaining.none? { |list| list[1..].include?(candidate) }
          end

          unless candidate
            constraints = remaining.map { |list| "[#{list.join(" > ")}]" }.join(", ")
            raise ProfileLinearizationError,
              "cannot linearize profiles for #{name.inspect}: contradictory precedence " \
              "constraints remain (#{constraints}); no candidate preserves all " \
              "parent orders without repeating an ancestor"
          end

          result << candidate
          remaining.each { |list| list.delete(candidate) }
          remaining.reject!(&:empty?)
        end

        result
      end

      # Deep-merges two profile layers in place. Nested override hashes merge
      # recursively; everything else (leaves, explicit nil and RESTORE_DEFAULT)
      # is taken from the higher-priority `override`.
      def merge_tree(base, override)
        override.each do |key, value|
          if value.is_a?(::Hash) && base.key?(key) && base[key].is_a?(::Hash)
            # Source profile trees are frozen structurally; merge into a copy
            # rather than mutating them.
            base[key] = merge_tree(base[key].dup, value)
          else
            base[key] = value
          end
        end
        base
      end

      # Ensures every assigned setting exists and scalar settings never receive a
      # nested block (and vice-versa). Run only after merging, once the final
      # shape of every branch is known.
      def validate_tree(tree, settings, path)
        tree.each do |key, value|
          setting = settings[key]
          full_path = path + [key]
          full_path_name = full_path.map(&:inspect).join(".")

          unless setting
            raise ProfileSettingError,
              "profile assigns unknown setting #{full_path_name}"
          end

          if value.is_a?(::Hash)
            if setting.children.none?
              raise ProfileSettingError,
                "profile assigns nested values to scalar setting #{full_path_name}"
            end

            validate_tree(value, setting.children, full_path)
          elsif setting.children.any? && !value.equal?(ProfileDSL::RESTORE_DEFAULT)
            raise ProfileSettingError,
              "profile assigns scalar value #{value.inspect} to nested setting " \
              "#{full_path_name}"
          end
        end
      end

      def apply_tree(config, tree, settings)
        tree.each do |key, value|
          setting = settings[key]

          if value.equal?(ProfileDSL::RESTORE_DEFAULT)
            restore_default(config, key)
          elsif value.is_a?(::Hash)
            apply_tree(config[key], value, setting.children)
          else
            config[key] = deep_copy(value, setting)
          end
        end
      end

      def restore_default(config, key)
        # Re-materialize the setting's own declared default. An undefined default
        # leaves the key unset, exactly as on a freshly built config.
        config._assign_default(key)
      end

      # Copies mutable values so each built config owns its own objects. Mirrors
      # the mutability rules applied by Setting#to_value.
      def deep_copy(value, setting)
        return value.dup if setting.cloneable? && value.respond_to?(:dup)

        value
      end
    end
  end
end
