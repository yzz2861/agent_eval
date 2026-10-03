# frozen_string_literal: true

module I18n
  module Utils
    class << self
      if Hash.method_defined?(:except)
        def except(hash, *keys)
          hash.except(*keys)
        end
      else
        def except(hash, *keys)
          hash = hash.dup
          keys.each { |k| hash.delete(k) }
          hash
        end
      end

      def deep_merge(hash, other_hash, &block)
        deep_merge!(hash.dup, other_hash, &block)
      end

      def deep_merge!(hash, other_hash, &block)
        hash.merge!(other_hash) do |key, this_val, other_val|
          if this_val.is_a?(Hash) && other_val.is_a?(Hash)
            deep_merge(this_val, other_val, &block)
          elsif disabled_marker?(this_val) || disabled_marker?(other_val)
            # An explicit "disabled" marker is sticky: once a key is marked
            # disabled it must not be un-disabled by a later deep merge,
            # otherwise blocked text could re-appear (e.g. when a region's
            # overrides are merged on top of the headquarters translations).
            disabled_marker?(this_val) ? this_val : other_val
          elsif block_given?
            yield key, this_val, other_val
          else
            other_val
          end
        end
      end

      def deep_symbolize_keys(hash)
        hash.each_with_object({}) do |(key, value), result|
          result[key.respond_to?(:to_sym) ? key.to_sym : key] = deep_symbolize_keys_in_object(value)
          result
        end
      end

      # Recursively replaces the textual +I18n::DISABLED_TOKEN+ (used in
      # YAML/JSON files) with the I18n::DISABLED marker object, so a key
      # declared disabled survives as a real marker rather than a string.
      def mark_disabled_entries(object)
        case object
        when I18n::DISABLED_TOKEN
          I18n::DISABLED
        when Hash
          object.each_with_object({}) do |(key, value), result|
            result[key] = mark_disabled_entries(value)
          end
        when Array
          object.map { |element| mark_disabled_entries(element) }
        else
          object
        end
      end

      private

      def disabled_marker?(value)
        defined?(I18n::DISABLED) && (value.equal?(I18n::DISABLED) || (value.respond_to?(:disabled?) && value.disabled?))
      end

      def deep_symbolize_keys_in_object(value)
        case value
        when Hash
          deep_symbolize_keys(value)
        when Array
          value.map { |e| deep_symbolize_keys_in_object(e) }
        else
          value
        end
      end
    end
  end
end
