# frozen_string_literal: true

require 'yaml'
require 'json'

module I18n
  module Backend
    module Base
      include I18n::Backend::Transliterator

      # Accepts a list of paths to translation files. Loads translations from
      # plain Ruby (*.rb), YAML files (*.yml), or JSON files (*.json). See #load_rb, #load_yml, and #load_json
      # for details.
      def load_translations(*filenames)
        filenames = I18n.load_path if filenames.empty?
        filenames.flatten.each do |filename|
          loaded_translations = load_file(filename)
          yield filename, loaded_translations if block_given?
        end
      end

      # This method receives a locale, a data hash and options for storing translations.
      # Should be implemented
      def store_translations(locale, data, options = EMPTY_HASH)
        raise NotImplementedError
      end

      def translate(locale, key, options = EMPTY_HASH)
        raise I18n::ArgumentError if (key.is_a?(String) || key.is_a?(Symbol)) && key.empty?
        raise InvalidLocale.new(locale) unless locale
        return nil if key.nil? && !options.key?(:default)

        entry = lookup(locale, key, options[:scope], options) unless key.nil?

        if entry.nil? && options.key?(:default)
          entry = default(locale, key, options[:default], options)
        else
          entry = resolve_entry(locale, key, entry, options)
        end

        count = options[:count]

        if entry.nil? && (subtrees? || !count)
          if (options.key?(:default) && !options[:default].nil?) || !options.key?(:default)
            throw(:exception, I18n::MissingTranslation.new(locale, key, options))
          end
        end

        entry = entry.dup if entry.is_a?(String)
        entry = pluralize(locale, entry, count) if count

        if entry.nil? && !subtrees?
          throw(:exception, I18n::MissingTranslation.new(locale, key, options))
        end

        deep_interpolation = options[:deep_interpolation]
        skip_interpolation = options[:skip_interpolation]
        values = Utils.except(options, *RESERVED_KEYS) unless options.empty?
        if !skip_interpolation && values && !values.empty?
          entry = if deep_interpolation
            deep_interpolate(locale, entry, values)
          else
            interpolate(locale, entry, values)
          end
        elsif entry.is_a?(String) && entry =~ I18n.reserved_keys_pattern
          raise ReservedInterpolationKey.new($1.to_sym, entry)
        end
        entry
      end

      def exists?(locale, key, options = EMPTY_HASH)
        lookup(locale, key, options[:scope]) != nil
      end

      # Acts the same as +strftime+, but uses a localized version of the
      # format string. Takes a key from the date/time formats translations as
      # a format argument (<em>e.g.</em>, <tt>:short</tt> in <tt>:'date.formats'</tt>).
      def localize(locale, object, format = :default, options = EMPTY_HASH)
        if object.nil? && options.include?(:default)
          return options[:default]
        end
        raise ArgumentError, "Object must be a Date, DateTime or Time object. #{object.inspect} given." unless object.respond_to?(:strftime)

        if Symbol === format
          key  = format
          type = object.respond_to?(:sec) ? 'time' : 'date'
          options = options.merge(:raise => true, :object => object, :locale => locale)
          format  = I18n.t(:"#{type}.formats.#{key}", **options)
        end

        format = translate_localization_format(locale, object, format, options)
        object.strftime(format)
      end

      # Localizes date/time ranges. The selected compact pattern is based on
      # the highest displayed calendar field whose values differ, while range
      # validity remains a comparison of the underlying instants.
      def localize_range(locale, start_object, end_object, format = :default, options = EMPTY_HASH)
        validate_range_objects(start_object, end_object)

        type = range_type(start_object, end_object)
        display_start, display_end = range_objects_in_time_zone(start_object, end_object, type, options)
        start_instant = range_instant(start_object, options[:time_zone] || options[:zone])
        end_instant = range_instant(end_object, options[:time_zone] || options[:zone])
        raise ArgumentError, 'The range start must be earlier than or equal to the end.' if start_instant > end_instant

        base_format = resolve_range_base_format(locale, type, format, options)
        mode = range_mode(display_start, display_end, base_format)
        range_format = lookup_range_format(locale, type, format, mode, options)

        if range_format
          format_range(locale, display_start, display_end, range_format, options)
        else
          separator = lookup_range_separator(locale, type, format, options) || ' - '
          [
            localize(locale, display_start, format, range_localization_options(options)),
            localize(locale, display_end, format, range_localization_options(options))
          ].join(separator)
        end
      end

      # Returns an array of locales for which translations are available
      # ignoring the reserved translation meta data key :i18n.
      def available_locales
        raise NotImplementedError
      end

      def reload!
        eager_load! if eager_loaded?
      end

      def eager_load!
        @eager_loaded = true
      end

      protected

        def eager_loaded?
          @eager_loaded ||= false
        end

        # The method which actually looks up for the translation in the store.
        def lookup(locale, key, scope = [], options = EMPTY_HASH)
          raise NotImplementedError
        end

        def subtrees?
          true
        end

        # Evaluates defaults.
        # If given subject is an Array, it walks the array and returns the
        # first translation that can be resolved. Otherwise it tries to resolve
        # the translation directly.
        def default(locale, object, subject, options = EMPTY_HASH)
          if options.size == 1 && options.has_key?(:default)
            options = {}
          else
            options = Utils.except(options, :default)
          end

          case subject
          when Array
            subject.each do |item|
              result = resolve(locale, object, item, options)
              return result unless result.nil?
            end and nil
          else
            resolve(locale, object, subject, options)
          end
        end

        # Resolves a translation.
        # If the given subject is a Symbol, it will be translated with the
        # given options. If it is a Proc then it will be evaluated. All other
        # subjects will be returned directly.
        def resolve(locale, object, subject, options = EMPTY_HASH)
          return subject if options[:resolve] == false
          result = catch(:exception) do
            case subject
            when Symbol
              I18n.translate(
                subject,
                **options.merge(
                  :locale => locale,
                  :throw => true,
                  :skip_interpolation => true
                )
              )
            when Proc
              date_or_time = options.delete(:object) || object
              resolve(locale, object, subject.call(date_or_time, **options))
            else
              subject
            end
          end
          result unless result.is_a?(MissingTranslation)
        end
        alias_method :resolve_entry, :resolve

        # Picks a translation from a pluralized mnemonic subkey according to English
        # pluralization rules :
        # - It will pick the :one subkey if count is equal to 1.
        # - It will pick the :other subkey otherwise.
        # - It will pick the :zero subkey in the special case where count is
        #   equal to 0 and there is a :zero subkey present. This behaviour is
        #   not standard with regards to the CLDR pluralization rules.
        # Other backends can implement more flexible or complex pluralization rules.
        def pluralize(locale, entry, count)
          entry = entry.reject { |k, _v| k == :attributes } if entry.is_a?(Hash)
          return entry unless entry.is_a?(Hash) && count

          key = pluralization_key(entry, count)
          raise InvalidPluralizationData.new(entry, count, key) unless entry.has_key?(key)
          entry[key]
        end

        # Interpolates values into a given subject.
        #
        #   if the given subject is a string then:
        #   method interpolates "file %{file} opened by %%{user}", :file => 'test.txt', :user => 'Mr. X'
        #   # => "file test.txt opened by %{user}"
        #
        #   if the given subject is an array then:
        #   each element of the array is recursively interpolated (until it finds a string)
        #   method interpolates ["yes, %{user}", ["maybe no, %{user}", "no, %{user}"]], :user => "bartuz"
        #   # => ["yes, bartuz", ["maybe no, bartuz", "no, bartuz"]]
        def interpolate(locale, subject, values = EMPTY_HASH)
          return subject if values.empty?

          case subject
          when ::String then I18n.interpolate(subject, values)
          when ::Array then subject.map { |element| interpolate(locale, element, values) }
          else
            subject
          end
        end

        # Deep interpolation
        #
        #   deep_interpolate { people: { ann: "Ann is %{ann}", john: "John is %{john}" } },
        #                    ann: 'good', john: 'big'
        #   #=> { people: { ann: "Ann is good", john: "John is big" } }
        def deep_interpolate(locale, data, values = EMPTY_HASH)
          return data if values.empty?

          case data
          when ::String
            I18n.interpolate(data, values)
          when ::Hash
            data.each_with_object({}) do |(k, v), result|
              result[k] = deep_interpolate(locale, v, values)
            end
          when ::Array
            data.map do |v|
              deep_interpolate(locale, v, values)
            end
          else
            data
          end
        end

        # Loads a single translations file by delegating to #load_rb or
        # #load_yml depending on the file extension and directly merges the
        # data to the existing translations. Raises I18n::UnknownFileType
        # for all other file extensions.
        def load_file(filename)
          type = File.extname(filename).tr('.', '').downcase
          raise UnknownFileType.new(type, filename) unless respond_to?(:"load_#{type}", true)
          data, keys_symbolized = send(:"load_#{type}", filename)
          unless data.is_a?(Hash)
            raise InvalidLocaleData.new(filename, 'expects it to return a hash, but does not')
          end
          data.each { |locale, d| store_translations(locale, d || {}, skip_symbolize_keys: keys_symbolized) }

          data
        end

        # Loads a plain Ruby translations file. eval'ing the file must yield
        # a Hash containing translation data with locales as toplevel keys.
        def load_rb(filename)
          translations = eval(IO.read(filename), binding, filename.to_s)
          [translations, false]
        end

        # Loads a YAML translations file. The data must have locales as
        # toplevel keys.
        def load_yml(filename)
          begin
            if YAML.respond_to?(:unsafe_load_file) # Psych 4.0 way
              [YAML.unsafe_load_file(filename, symbolize_names: true, freeze: true), true]
            else
              [YAML.load_file(filename), false]
            end
          rescue TypeError, ScriptError, StandardError => e
            raise InvalidLocaleData.new(filename, e.inspect)
          end
        end
        alias_method :load_yaml, :load_yml

        # Loads a JSON translations file. The data must have locales as
        # toplevel keys.
        def load_json(filename)
          begin
            # Use #load_file as a proxy for a version of JSON where symbolize_names and freeze are supported.
            if ::JSON.respond_to?(:load_file)
              [::JSON.load_file(filename, symbolize_names: true, freeze: true), true]
            else
              [::JSON.parse(File.read(filename)), false]
            end
          rescue TypeError, StandardError => e
            raise InvalidLocaleData.new(filename, e.inspect)
          end
        end

        def translate_localization_format(locale, object, format, options)
          format.to_s.gsub(/%(|\^)[aAbBpP]/) do |match|
            case match
            when '%a' then I18n.t!(:"date.abbr_day_names",                  :locale => locale, :format => format)[object.wday]
            when '%^a' then I18n.t!(:"date.abbr_day_names",                 :locale => locale, :format => format)[object.wday].upcase
            when '%A' then I18n.t!(:"date.day_names",                       :locale => locale, :format => format)[object.wday]
            when '%^A' then I18n.t!(:"date.day_names",                      :locale => locale, :format => format)[object.wday].upcase
            when '%b' then I18n.t!(:"date.abbr_month_names",                :locale => locale, :format => format)[object.mon]
            when '%^b' then I18n.t!(:"date.abbr_month_names",               :locale => locale, :format => format)[object.mon].upcase
            when '%B' then I18n.t!(:"date.month_names",                     :locale => locale, :format => format)[object.mon]
            when '%^B' then I18n.t!(:"date.month_names",                    :locale => locale, :format => format)[object.mon].upcase
            when '%p' then I18n.t!(:"time.#{(object.respond_to?(:hour) ? object.hour : 0) < 12 ? :am : :pm}", :locale => locale, :format => format).upcase
            when '%P' then I18n.t!(:"time.#{(object.respond_to?(:hour) ? object.hour : 0) < 12 ? :am : :pm}", :locale => locale, :format => format).downcase
            end
          end
        rescue MissingTranslationData => e
          e.message
        end

        def pluralization_key(entry, count)
          key = :zero if count == 0 && entry.has_key?(:zero)
          key ||= count == 1 ? :one : :other
        end

        def validate_range_objects(start_object, end_object)
          [start_object, end_object].each do |object|
            raise ArgumentError, "Object must be a Date, DateTime or Time object. #{object.inspect} given." unless object.respond_to?(:strftime)
          end
        end

        def range_type(start_object, end_object)
          types = [start_object, end_object].map { |object| object.respond_to?(:sec) ? 'time' : 'date' }.uniq
          types.include?('time') ? 'time' : 'date'
        end

        def range_objects_in_time_zone(start_object, end_object, type, options)
          time_zone = options[:time_zone] || options[:zone]
          offsets = [start_object, end_object].map { |object| range_time_zone_identity(object) }.uniq

          if offsets.size > 1 && time_zone.nil?
            raise ArgumentError, 'Range endpoints use different time zones. Pass :time_zone to select the calendar fields to display.'
          end

          [start_object, end_object].map { |object| convert_range_object(object, type, time_zone) }
        end

        def range_offset(object)
          return object.utc_offset if object.respond_to?(:utc_offset)
          return (object.offset * 86_400).to_i if object.is_a?(::DateTime)
          nil
        end

        def range_time_zone_identity(object)
          return object.time_zone if object.respond_to?(:time_zone)
          range_offset(object)
        end

        def convert_range_object(object, type, time_zone)
          return object if object.is_a?(::Date) && !object.is_a?(::DateTime) && type == 'date'
          return object if object.is_a?(::Date) && !object.is_a?(::DateTime) && time_zone.nil?
          return object unless time_zone

          offset = range_time_zone_offset(time_zone)
          if object.respond_to?(:getlocal)
            object.getlocal(offset)
          elsif object.is_a?(::DateTime)
            object.new_offset(Rational(offset, 86_400))
          else
            ::DateTime.civil(object.year, object.mon, object.mday, 0, 0, 0, Rational(offset, 86_400))
          end
        end

        def range_time_zone_offset(time_zone)
          return time_zone.utc_offset if time_zone.respond_to?(:utc_offset)
          return time_zone.to_i if time_zone.is_a?(::Numeric)
          return 0 if time_zone.to_s.upcase == 'UTC'
          unless time_zone.to_s =~ /\A([+-])(\d{2}):?(\d{2})(?::?(\d{2}))?\z/
            raise ArgumentError, 'Time zone must be an offset in seconds, an offset string such as "+09:00", UTC, or an object responding to #utc_offset.'
          end

          sign = $1 == '-' ? -1 : 1
          sign * (($2.to_i * 3600) + ($3.to_i * 60) + ($4.to_i))
        end

        def range_instant(object, time_zone)
          if object.respond_to?(:to_r) && object.respond_to?(:utc_offset)
            object.utc.to_r
          elsif object.is_a?(::DateTime)
            object.new_offset(0).ajd
          elsif object.is_a?(::Date)
            if time_zone.nil?
              ::DateTime.civil(object.year, object.mon, object.mday).ajd
            else
              offset = Rational(range_time_zone_offset(time_zone), 86_400)
              ::DateTime.civil(object.year, object.mon, object.mday, 0, 0, 0, offset).new_offset(0).ajd
            end
          end
        end

        def resolve_range_base_format(locale, type, format, options)
          return format.to_s unless format.is_a?(::Symbol)

          resolved = I18n.t(
            :"#{type}.formats.#{format}",
            **options.except(:object).merge(
              :locale => locale,
              :raise => true,
              :skip_interpolation => true
            )
          )
          resolved.respond_to?(:call) ? nil : resolved.to_s
        end

        def range_mode(start_object, end_object, format)
          displayed_fields = format_directives(format)

          if displayed_fields.include?(:year) && start_object.year != end_object.year
            :cross_year
          elsif displayed_fields.include?(:month) && start_object.mon != end_object.mon
            :cross_month
          elsif displayed_fields.include?(:day) && start_object.mday != end_object.mday
            :same_month
          else
            :same_day
          end
        end

        def format_directives(format)
          directives = []
          return [:year, :month, :day] if format.nil?

          format.scan(/%%|%(?<flags>[\-_0^#:]+)?(?<width>\d+)?(?<directive>[a-zA-Z])/) do |*|
            match = Regexp.last_match
            next if match[0] == '%%'

            directive = match[:directive]
            case directive
            when 'Y', 'C', 'G', 'g', 'y'
              directives << :year
            when 'm', 'B', 'b', 'h'
              directives << :month
            when 'd', 'e'
              directives << :day
            end
          end
          directives.uniq
        end

        def lookup_range_format(locale, type, format, mode, options)
          range_format_keys(type, format, mode).each do |key|
            result = translate_if_available(locale, key, options)
            return result unless result.nil?
          end
          nil
        end

        def lookup_range_separator(locale, type, format, options)
          keys = [type]
          keys << format if format.is_a?(::Symbol)
          translate_if_available(locale, (keys + [:'range_separator']).join('.').to_sym, options) ||
            translate_if_available(locale, :range_separator, options)
        end

        def format_range(locale, start_object, end_object, range_format, options)
          case range_format
          when ::Array
            start_format, end_format = range_format
            [
              start_format && localize(locale, start_object, start_format, range_localization_options(options)),
              end_format && localize(locale, end_object, end_format, range_localization_options(options))
            ].join
          when ::Hash
            template = range_format[:template] || range_format[:format]
            separator = range_format[:separator] || ' - '
            template ||= "%{start}#{separator}%{end}"
            values = {
              :start => range_format[:start] && localize(locale, start_object, range_format[:start], range_localization_options(options)),
              :end => range_format[:end] && localize(locale, end_object, range_format[:end], range_localization_options(options))
            }
            ::I18n.interpolate(template, values)
          else
            ::I18n.interpolate(
              range_format,
              :start => localize(locale, start_object, :default, range_localization_options(options)),
              :end => localize(locale, end_object, :default, range_localization_options(options))
            )
          end
        end

        def range_localization_options(options)
          options.except(:time_zone, :zone, :object)
        end

        def translate_if_available(locale, key, options)
          result = catch(:exception) do
            I18n.t(
              key,
              **options.except(:default, :object).merge(
                :locale => locale,
                :throw => true,
                :skip_interpolation => true
              )
            )
          end
          result unless result.is_a?(MissingTranslation)
        end

        def range_format_keys(type, format, mode)
          keys = []
          keys << :"#{type}.range_formats.#{format}.#{mode}" if format.is_a?(::Symbol)
          keys << :"#{type}.range_formats.#{mode}"
          keys << :"#{type}.interval_formats.#{format}.#{mode}" if format.is_a?(::Symbol)
          keys << :"#{type}.interval_formats.#{mode}"
          keys
        end
    end
  end
end
