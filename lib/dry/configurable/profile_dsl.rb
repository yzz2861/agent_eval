# frozen_string_literal: true

module Dry
  module Configurable
    # DSL used to declare a named profile's overrides.
    #
    # Within the block, settings are assigned with either
    # `setting_name value` or `setting_name = value`. Nested settings are
    # opened with a block. Calling {#restore_default!} for a setting resets it
    # to the setting's own default, ignoring any value inherited from a parent
    # profile (while still distinguishing it from an explicit nil).
    #
    # @api private
    class ProfileDSL
      # Sentinel marking a setting that must fall back to its declared default
      # rather than inherit a value from a parent profile.
      #
      # @api public
      RESTORE_DEFAULT = Object.new.freeze

      # @return [Hash{Symbol => Object}] the collected, unvalidated override tree
      #
      # @api private
      attr_reader :tree

      def initialize(current_key: nil, &block)
        @__current_key__ = current_key
        @__restore_default__ = false
        @tree = {}
        instance_exec(&block) if block
      end

      # @return [Boolean] whether the block restored its enclosing setting's default
      #
      # @api private
      def restore_default?
        @__restore_default__
      end

      # Marks the given setting (or the setting enclosing the current block) as
      # restored to its declared default.
      #
      # @param name [Symbol, nil]
      #
      # @api public
      def restore_default!(name = nil)
        if name
          @tree[name.to_sym] = RESTORE_DEFAULT
        elsif @__current_key__
          @__restore_default__ = true
        else
          raise ProfileError,
            "restore_default! requires a setting name outside of a setting block"
        end
      end

      private

      # Supports `host "x"`, `host = "x"`, and nested blocks.
      def method_missing(name, *args, &block)
        setting_name = name.to_s.tr("=", "").to_sym

        if block
          nested = self.class.new(current_key: setting_name, &block)

          if nested.restore_default?
            @tree[setting_name] = RESTORE_DEFAULT
          else
            @tree[setting_name] = merge_branch(@tree[setting_name], nested.tree)
          end
        elsif !args.empty?
          @tree[setting_name] = args.first
        elsif name.end_with?("=")
          raise ArgumentError,
            "expected a value to assign to #{setting_name.inspect}"
        else
          nil
        end
      end

      def respond_to_missing?(_name, _include_private = false)
        true
      end

      def merge_branch(existing, branch)
        if existing.is_a?(::Hash) && branch.is_a?(::Hash)
          existing.merge(branch) { |_, left, right|
            left.is_a?(::Hash) && right.is_a?(::Hash) ? merge_branch(left, right) : right
          }
        else
          branch
        end
      end
    end
  end
end
