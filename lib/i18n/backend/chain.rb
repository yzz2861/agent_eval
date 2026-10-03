# frozen_string_literal: true

module I18n
  module Backend
    # Backend that chains multiple other backends and checks each of them when
    # a translation needs to be looked up. This is useful when you want to use
    # standard translations with a Simple backend but store custom application
    # translations in a database or other backends.
    #
    # To use the Chain backend instantiate it and set it to the I18n module.
    # You can add chained backends through the initializer or backends
    # accessor:
    #
    #   # preserves the existing Simple backend set to I18n.backend
    #   I18n.backend = I18n::Backend::Chain.new(I18n::Backend::ActiveRecord.new, I18n.backend)
    #
    # The implementation assumes that all backends added to the Chain implement
    # a lookup method with the same API as Simple backend does.
    # 
    # Fallback translations using the :default option are only used by the last backend of a chain.
    class Chain
      module Implementation
        include Base

        attr_accessor :backends

        def initialize(*backends)
          self.backends = backends
        end

        def initialized?
          backends.all? do |backend|
            backend.instance_eval do
              return false unless initialized?
            end
          end
          true
        end

        def reload!
          backends.each { |backend| backend.reload! }
        end

        def eager_load!
          backends.each { |backend| backend.eager_load! }
        end

        def store_translations(locale, data, options = EMPTY_HASH)
          backends.first.store_translations(locale, data, options)
        end

        def available_locales
          backends.map { |backend| backend.available_locales }.flatten.uniq
        end

        def translate(locale, key, default_options = EMPTY_HASH)
          namespace = nil
          without_default = Utils.except(default_options, :default)

          disabled = catch(:i18n_disabled) do
            backends.each do |backend|
              options = backend == backends.last ? default_options : without_default
              translation = catch(:exception) do
                backend.translate(locale, key, options)
              end
              if namespace_lookup?(translation, options)
                # Prefer the raw stored subtree (which retains I18n::DISABLED
                # markers) only when it actually contains a marker, so a
                # disabled leaf cannot be resurrected from another backend.
                # Otherwise keep the already processed translation (which may
                # come from a default or pluralization).
                raw = backend.send(:lookup, locale, key, options[:scope], options) rescue nil
                subtree = (raw.is_a?(Hash) && hash_contains_disabled?(raw)) ? raw : translation
                namespace = _deep_merge(subtree, namespace || {})
              elsif disabled_entry?(translation)
                # A key explicitly disabled in an earlier backend must not
                # fall through to later backends.
                throw(:i18n_disabled, translation)
              elsif translation.is_a?(I18n::MissingTranslation)
                # Plain miss: keep checking the remaining backends.
                next
              elsif !translation.nil? || (options.key?(:default) && options[:default].nil?)
                return translation
              end
            end
            false
          end

          # Propagate the disabled signal up to the caller (and any wrapping
          # Fallbacks backend) without consulting defaults or more backends.
          if disabled
            disabled = I18n::DisabledTranslation.new(locale, key, default_options) unless disabled.respond_to?(:disabled?) && disabled.disabled?
            throw(default_options[:fallback_in_progress] ? :i18n_disabled : :exception, disabled)
          end
          if namespace
            return prune_disabled_entries(namespace)
          end
          throw(:exception, I18n::MissingTranslation.new(locale, key, default_options))
        end

        def exists?(locale, key, options = EMPTY_HASH)
          super
        end

        def localize(locale, object, format = :default, options = EMPTY_HASH)
          backends.each do |backend|
            catch(:exception) do
              result = backend.localize(locale, object, format, options) and return result
            end
          end
          throw(:exception, I18n::MissingTranslation.new(locale, format, options))
        end

        protected
          # Delegates lookup to the backends in order, returning the first
          # non-nil result (which may be the I18n::DISABLED marker) so that
          # modules layered on top of a Chain (e.g. Fallbacks) can inspect it.
          def lookup(locale, key, scope = [], options = EMPTY_HASH)
            backends.each do |backend|
              result = backend.send(:lookup, locale, key, scope, options)
              return result unless result.nil?
            end
            nil
          end

          def init_translations
            backends.each do |backend|
              backend.send(:init_translations)
            end
          end

          def translations
            backends.reverse.each_with_object({}) do |backend, memo|
              partial_translations = backend.instance_eval do
                init_translations unless initialized?
                translations
              end
              Utils.deep_merge!(memo, partial_translations) { |_, a, b| b || a }
            end
          end

          def namespace_lookup?(result, options)
            result.is_a?(Hash) && !options.has_key?(:count)
          end

        private
          # This is approximately what gets used in ActiveSupport.
          # However since we are not guaranteed to run in an ActiveSupport context
          # it is wise to have our own copy. We underscore it
          # to not pollute the namespace of the including class.
          def _deep_merge(hash, other_hash)
            copy = hash.dup
            other_hash.each_pair do |k,v|
              value_from_other = hash[k]
              if value_from_other.is_a?(Hash) && v.is_a?(Hash)
                copy[k] = _deep_merge(value_from_other, v)
              elsif disabled_marker_value?(value_from_other) || disabled_marker_value?(v)
                copy[k] = disabled_marker_value?(value_from_other) ? value_from_other : v
              else
                copy[k] = v
              end
            end
            copy
          end

          def disabled_marker_value?(value)
            value.respond_to?(:disabled?) && value.disabled?
          end

          def hash_contains_disabled?(value)
            case value
            when Hash then value.any? { |k, v| disabled_marker_value?(v) || hash_contains_disabled?(v) }
            when Array then value.any? { |v| hash_contains_disabled?(v) }
            else false
            end
          end
      end

      include Implementation
    end
  end
end
