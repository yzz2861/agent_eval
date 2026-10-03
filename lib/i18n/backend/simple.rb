# frozen_string_literal: true

require 'i18n/backend/base'

module I18n
  module Backend
    # A simple backend that reads translations from YAML files and stores them in
    # an in-memory hash. Relies on the Base backend.
    #
    # The implementation is provided by a Implementation module allowing to easily
    # extend Simple backend's behavior by including modules. E.g.:
    #
    #     module I18n::Backend::Pluralization
    #       def pluralize(*args)
    #         # extended pluralization logic
    #         super
    #       end
    #     end
    #     
    #     I18n::Backend::Simple.include(I18n::Backend::Pluralization)
    class Simple
      module Implementation
        include Base
        
        # Mutex to ensure that concurrent translations loading will be thread-safe
        MUTEX = Mutex.new

        def initialized?
          @initialized ||= false
        end

        # Stores translations for the given locale in memory.
        # This uses a deep merge for the translations hash, so existing
        # translations will be overwritten by new ones only at the deepest
        # level of the hash.
        def store_translations(locale, data, options = EMPTY_HASH)
          if I18n.enforce_available_locales &&
            I18n.available_locales_initialized? &&
            !I18n.locale_available?(locale)
            return data
          end
          locale = locale.to_sym
          translations[locale] ||= Concurrent::Hash.new
          data = Utils.deep_symbolize_keys(data) unless options.fetch(:skip_symbolize_keys, false)
          MUTEX.synchronize { Utils.deep_merge!(translations[locale], data) }
        end

        # Loads translation files on behalf of a named source (e.g. a plugin)
        # so that their contribution can be managed independently later.
        #
        # Sources override each other in the order they were first loaded:
        # a source that is loaded later wins over previously loaded sources
        # and all sources win over translations loaded through
        # #load_translations. Loading an already registered source again
        # replaces its translations in place, keeping its position in the
        # override order.
        #
        # All files are parsed before anything is stored, so a broken file
        # raises an error and leaves the previously stored translations
        # untouched.
        def load_source(source, *filenames)
          store_source(source, filenames.flatten)
        end

        # Reloads a previously registered source in place, keeping its
        # position in the override order. Re-parses the given files, or the
        # files the source was originally loaded with when no filenames are
        # given. Like #load_source, a broken file leaves the previously
        # stored translations untouched.
        def reload_source(source, *filenames)
          filenames = filenames.flatten
          if filenames.empty?
            entry = translation_sources[source]
            raise ArgumentError, "unknown translation source: #{source.inspect}" unless entry
            filenames = entry[:filenames]
          end
          store_source(source, filenames)
        end

        # Removes a source and all translations it contributed. Translations
        # from lower sources that were overridden by the removed source
        # become visible again. Returns true if the source was registered.
        def remove_source(source)
          return false unless translation_sources.delete(source)
          rebuild_translations
          true
        end

        # Get available locales from the translations hash
        def available_locales
          init_translations unless initialized?
          translations.inject([]) do |locales, (locale, data)|
            locales << locale unless data.size <= 1 && (data.empty? || data.has_key?(:i18n))
            locales
          end
        end

        # Clean up translations hash and set initialized to false on reload!
        def reload!
          @initialized = false
          @translations = nil
          super
        end

        def eager_load!
          init_translations unless initialized?
          super
        end

        def translations(do_init: false)
          # To avoid returning empty translations,
          # call `init_translations`
          init_translations if do_init && !initialized?

          @translations ||= Concurrent::Hash.new do |h, k|
            MUTEX.synchronize do
              h[k] = Concurrent::Hash.new
            end
          end
        end

      protected

        def init_translations
          load_translations
          replay_source_translations
          @initialized = true
        end

        # Tracks the files and parsed translations of each source, in the
        # order the sources were first loaded (which is the order in which
        # they override each other).
        def translation_sources
          @translation_sources ||= {}
        end

        def store_source(source, filenames)
          # Parse all files first so that a broken file does not leave half
          # of the new translations behind.
          entries = filenames.map { |filename| parse_file(filename) }
          translation_sources[source] = { :filenames => filenames, :entries => entries }
          rebuild_translations
          entries
        end

        # Rebuilds the translations hash from scratch: translations from the
        # load path form the bottom layer and each source is merged on top of
        # it in the order the sources were loaded, using the same merge rules
        # as #store_translations.
        def rebuild_translations
          @translations = nil
          init_translations
          I18n.config.clear_available_locales_set
          reset_memoizations! if respond_to?(:reset_memoizations!, true)
        end

        def replay_source_translations
          translation_sources.each_value do |source|
            source[:entries].each do |data, keys_symbolized|
              data.each { |locale, d| store_translations(locale, d || {}, skip_symbolize_keys: keys_symbolized) }
            end
          end
        end

        # Looks up a translation from the translations hash. Returns nil if
        # either key is nil, or locale, scope or key do not exist as a key in the
        # nested translations hash. Splits keys or scopes containing dots
        # into multiple keys, i.e. <tt>currency.format</tt> is regarded the same as
        # <tt>%w(currency format)</tt>.
        def lookup(locale, key, scope = [], options = EMPTY_HASH)
          init_translations unless initialized?
          keys = I18n.normalize_keys(locale, key, scope, options[:separator])

          keys.inject(translations) do |result, _key|
            return nil unless result.is_a?(Hash)
            unless result.has_key?(_key)
              _key = _key.to_s.to_sym
              return nil unless result.has_key?(_key)
            end
            result = result[_key]
            result = resolve_entry(locale, _key, result, Utils.except(options.merge(:scope => nil), :count)) if result.is_a?(Symbol)
            result
          end
        end
      end

      include Implementation
    end
  end
end
