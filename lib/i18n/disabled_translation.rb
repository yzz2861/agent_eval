# frozen_string_literal: true

module I18n
  # A sentinel value that explicitly disables a translation.
  #
  # Some locales must not show a text that is provided for other locales
  # (e.g. a campaign copy supplied by a headquarter locale). Storing a plain
  # nil does not help here, because nil is treated like a missing key:
  # the lookup falls back to other locales or backends and the default
  # option kicks in.
  #
  # Storing the I18n.disabled sentinel instead marks the key as disabled:
  #
  # * the lookup does not continue to fallback locales
  #   (I18n::Backend::Fallbacks) or to other backends in a
  #   I18n::Backend::Chain
  # * the default option is not evaluated
  # * I18n.t returns nil and I18n.exists? returns false
  #
  # The marker never leaks into namespace (subtree) lookups: disabled entries
  # are removed from returned hashes, and hashes that only contained disabled
  # entries are pruned. Deep merges (e.g. when a Chain backend merges
  # namespaces from several backends) keep the marker, so a disabled key can
  # not be resurrected by a less specific backend.
  #
  # In memory, use the sentinel directly:
  #
  #   I18n.backend.store_translations(:de, :promo => { :banner => I18n.disabled })
  #
  # In translation files (YAML, JSON, ...) use the MARKER string:
  #
  #   de:
  #     promo:
  #       banner: i18n:disabled
  class DisabledTranslation
    # String that is converted to the sentinel when translations are stored.
    # Use this in translation files (YAML, JSON) which can not hold the
    # sentinel object itself.
    MARKER = "i18n:disabled"

    class << self
      # The canonical sentinel instance. Any instance of this class is
      # treated as a disabled marker, but using this instance (via
      # I18n.disabled) is preferred.
      def instance
        @instance ||= new.freeze
      end

      # Recursively replaces MARKER strings with the sentinel instance.
      # Applied to data passed to store_translations.
      def resolve_markers(object)
        case object
        when Hash
          object.each_with_object({}) do |(key, value), result|
            result[key] = resolve_markers(value)
          end
        when Array
          object.map { |value| resolve_markers(value) }
        when MARKER
          instance
        else
          object
        end
      end

      # Prepares a lookup result for the caller of I18n.translate: the
      # sentinel itself becomes nil and disabled entries are removed from
      # hashes and arrays. Hashes that only contained disabled entries are
      # pruned from their parents.
      def scrub(object)
        case object
        when DisabledTranslation
          nil
        when Hash
          object.each_with_object({}) do |(key, value), result|
            next if value.is_a?(DisabledTranslation)
            scrubbed = scrub(value)
            next if value.is_a?(Hash) && !value.empty? && scrubbed.empty?
            result[key] = scrubbed
          end
        when Array
          object.each_with_object([]) do |value, result|
            result << scrub(value) unless value.is_a?(DisabledTranslation)
          end
        else
          object
        end
      end
    end

    def inspect
      "#<I18n::DisabledTranslation>"
    end

    # Renders as an empty string so that an accidentally interpolated marker
    # displays nothing.
    def to_s
      ""
    end
  end
end
