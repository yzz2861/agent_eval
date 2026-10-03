# frozen_string_literal: true

# I18n locale fallbacks are useful when you want your application to use
# translations from other locales when translations for the current locale are
# missing. E.g. you might want to use :en translations when translations in
# your applications main locale :de are missing.
#
# To enable locale fallbacks you can simply include the Fallbacks module to
# the Simple backend - or whatever other backend you are using:
#
#   I18n::Backend::Simple.include(I18n::Backend::Fallbacks)
module I18n
  @@fallbacks = nil

  class << self
    # Returns the current fallbacks implementation. Defaults to +I18n::Locale::Fallbacks+.
    def fallbacks
      @@fallbacks ||= I18n::Locale::Fallbacks.new
      if Fiber.respond_to?(:[])
        Fiber[:i18n_fallbacks] || @@fallbacks
      else
        Thread.current[:i18n_fallbacks] || @@fallbacks
      end
    end

    # Sets the current fallbacks implementation. Use this to set a different fallbacks implementation.
    def fallbacks=(fallbacks)
      @@fallbacks = fallbacks.is_a?(Array) ? I18n::Locale::Fallbacks.new(fallbacks) : fallbacks
      if Fiber.respond_to?(:[])
        Fiber[:i18n_fallbacks] = @@fallbacks
      else
        Thread.current[:i18n_fallbacks] = @@fallbacks
      end
    end
  end

  module Backend
    module Fallbacks
      # Overwrites the Base backend translate method so that it will try each
      # locale given by I18n.fallbacks for the given locale. E.g. for the
      # locale :"de-DE" it might try the locales :"de-DE", :de and :en
      # (depends on the fallbacks implementation) until it finds a result with
      # the given options. If it does not find any result for any of the
      # locales it will then throw MissingTranslation as usual.
      #
      # The default option takes precedence over fallback locales only when
      # it's a Symbol. When the default contains a String, Proc or Hash
      # it is evaluated last after all the fallback locales have been tried.
      def translate(locale, key, options = EMPTY_HASH)
        return super unless options.fetch(:fallback, true)
        return super if options[:fallback_in_progress]
        default = extract_non_symbol_default!(options) if options[:default]

        fallback_options = options.merge(:fallback_in_progress => true, fallback_original_locale: locale)
        disabled = catch(:i18n_disabled) do
          I18n.fallbacks[locale].each do |fallback|
            begin
              catch(:exception) do
                result = super(fallback, key, fallback_options)
                unless result.nil?
                  on_fallback(locale, fallback, key, options) if locale.to_s != fallback.to_s
                  return result
                end
              end
            rescue I18n::InvalidLocale
              # we do nothing when the locale is invalid, as this is a fallback anyways.
            end
          end
          false
        end

        # Do not fall through to defaults when the key is disabled.
        throw(:exception, I18n::DisabledTranslation.new(locale, key, options)) if disabled

        return if options.key?(:default) && options[:default].nil?

        return super(locale, nil, options.merge(:default => default)) if default
        throw(:exception, I18n::MissingTranslation.new(locale, key, options))
      end

      def resolve_entry(locale, object, subject, options = EMPTY_HASH)
        return subject if options[:resolve] == false
        result = catch(:exception) do
          options = options.reject { |key, _| key == :fallback_in_progress } if options.key?(:fallback_in_progress)

          case subject
          when Symbol
            I18n.translate(subject, **options.merge(
              :locale => options[:fallback_original_locale],
              :throw => true,
              :skip_interpolation => true
            ))
          when Proc
            date_or_time = options.delete(:object) || object
            resolve_entry(options[:fallback_original_locale], object, subject.call(date_or_time, **options))
          else
            subject
          end
        end
        return result if result.respond_to?(:disabled?) && result.disabled?
        result unless result.is_a?(MissingTranslation)
      end

      def extract_non_symbol_default!(options)
        defaults = [options[:default]].flatten
        first_non_symbol_default = defaults.detect{|default| !default.is_a?(Symbol)}
        if first_non_symbol_default
          options[:default] = defaults[0, defaults.index(first_non_symbol_default)]
        end
        return first_non_symbol_default
      end

      def exists?(locale, key, options = EMPTY_HASH)
        return super unless options.fetch(:fallback, true)
        I18n.fallbacks[locale].each do |fallback|
          begin
            state = exists_state(fallback, key, options)
            # A disabled key is explicitly not present here and must not be
            # reported as existing through another fallback locale.
            return false if state == :disabled
            return true if state == :found
          rescue I18n::InvalidLocale
            # we do nothing when the locale is invalid, as this is a fallback anyways.
          end
        end

        false
      end

      private

        # Ternary existence check used while walking fallback locales.
        # Relies on #lookup, which Simple provides and Chain implements by
        # delegating to its backends.
        def exists_state(locale, key, options)
          entry = catch(:exception) do
            lookup(locale, key, options[:scope], options)
          end
          return :disabled if disabled_entry?(entry)
          entry.nil? ? :missing : :found
        end

        # Overwrite on_fallback to add specified logic when the fallback succeeds.
        def on_fallback(_original_locale, _fallback_locale, _key, _options)
          nil
        end
    end
  end
end
