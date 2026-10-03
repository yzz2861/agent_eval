# frozen_string_literal: true

require 'date'
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

      # Localizes a date/time range. Unlike joining two separately localized
      # values with a dash, this uses locale-specific compact range patterns
      # (see <tt>date.ranges</tt>/<tt>time.ranges</tt>). The most significant
      # *displayed* calendar field on which the two ends differ decides which
      # pattern is used (+same_day+, +same_month+, +different_month+ or
      # +different_year+), while the start/end ordering is always checked on
      # the actual instants.
      #
      # When the two ends carry different offsets they are projected into the
      # zone given by <tt>:time_zone</tt>, or into the start end zone when it
      # is omitted; the system time zone is never guessed. Locales without a
      # matching range pattern fall back to two fully localized dates.
      def localize_range(locale, start_object, end_object = nil, format = :default, options = EMPTY_HASH)
        if start_object.is_a?(::Range)
          range = start_object
          start_object = range.begin
          end_object = range.end
        end

        unless start_object.respond_to?(:strftime) && end_object.respond_to?(:strftime)
          raise ArgumentError, "Objects must be Date, DateTime or Time objects. #{start_object.inspect} and #{end_object.inspect} given."
        end

        type = start_object.respond_to?(:sec) ? 'time' : 'date'

        start_datetime, end_datetime, projected = ordered_range_datetimes(start_object, end_object, options[:time_zone])
        start_render = projected ? start_datetime : start_object
        end_render = projected ? end_datetime : end_object

        if Symbol === format
          key = format
          lookup_options = options.merge(:raise => true, :object => start_object, :locale => locale)
          base_format = I18n.t(:"#{type}.formats.#{key}", **lookup_options)
          range_formats = translate_range_entry(locale, :"#{type}.ranges.#{key}", start_object, lookup_options)
        else
          base_format = format
          range_formats = nil
        end

        variant = range_variant(base_format, start_datetime, end_datetime)
        parts = range_formats && range_formats[variant]

        unless parts.is_a?(::Array) && parts.size == 2 && parts.all? { |part| part.is_a?(::String) }
          return localize_full_range(locale,
            start_render, end_render, format, options)
        end

        separator = range_separator(locale, type, format, options)
        start_part = render_range_part(locale, start_render, parts[0], options)
        end_part = render_range_part(locale, end_render, parts[1], options)
        end_part.empty? ? start_part : start_part << separator << end_part
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

        DEFAULT_RANGE_SEPARATOR = " \u2013 "

        RANGE_FORMAT_FIELD_YEAR   = /(?<!%)%(?:[-_^0-9# +:]*(?:E|O)?)?[YGg]/.freeze
        RANGE_FORMAT_FIELD_MONTH  = /(?<!%)%(?:[-_^0-9# +:]*(?:E|O)?)?[mBbh]/.freeze
        RANGE_FORMAT_FIELD_DAY    = /(?<!%)%(?:[-_^0-9# +:]*(?:E|O)?)?[dejUVW]/.freeze

        # Returns the most significant calendar field that is both displayed
        # by +format+ and different between the two ends.
        def range_variant(format, start_datetime, end_datetime)
          format = format.to_s
          if RANGE_FORMAT_FIELD_YEAR.match?(format) && start_datetime.year != end_datetime.year
            :different_year
          elsif RANGE_FORMAT_FIELD_MONTH.match?(format) &&
              (start_datetime.year != end_datetime.year || start_datetime.mon != end_datetime.mon)
            :different_month
          elsif RANGE_FORMAT_FIELD_DAY.match?(format) &&
              (start_datetime.year != end_datetime.year || start_datetime.mon != end_datetime.mon || start_datetime.day != end_datetime.day)
            :same_month
          else
            :same_day
          end
        end

        # Compares the actual instants (independently of their offsets) and
        # returns both ends projected into one explicit zone. The third return
        # value indicates whether the original objects had to be converted.
        def ordered_range_datetimes(start_object, end_object, time_zone)
          start_datetime = to_range_datetime(start_object)
          end_datetime = to_range_datetime(end_object)

          if start_datetime > end_datetime
            raise ArgumentError, "Range start object must be earlier than or equal to the end object. #{start_object.inspect} and #{end_object.inspect} given."
          end

          if time_zone
            offset = range_zone_offset(time_zone, start_datetime)
            projected = true
          elsif start_datetime.offset == end_datetime.offset
            offset = start_datetime.offset
            projected = false
          else
            raise ArgumentError, "Range ends use different time zones (#{format_range_offset(start_datetime)} and #{format_range_offset(end_datetime)}); pass :time_zone to choose the zone to render the range in."
          end

          [start_datetime.new_offset(offset), end_datetime.new_offset(offset), projected]
        end

        def to_range_datetime(object)
          object.is_a?(::DateTime) ? object : object.to_datetime
        end

        def range_zone_offset(time_zone, reference_datetime)
          case time_zone
          when ::Numeric
            Rational(time_zone, 86_400)
          when ::String
            ::DateTime.now.new_offset(time_zone).offset
          when ::DateTime
            time_zone.offset
          else
            if time_zone.respond_to?(:utc_to_local)
              local = time_zone.utc_to_local(reference_datetime.new_offset(0).to_time)
              Rational(local.utc_offset, 86_400)
            else
              raise ArgumentError, "Unsupported :time_zone #{time_zone.inspect}. Pass an offset (Integer/String), a DateTime or a time zone object."
            end
          end
        end

        def format_range_offset(datetime)
          datetime.strftime('%z')
        end

        def render_range_part(locale, datetime, part_format, options)
          format = translate_localization_format(locale, datetime, part_format, options)
          datetime.strftime(format)
        end

        def range_separator(locale, type, format, options)
          separator = catch(:exception) do
            I18n.t!(:"#{type}.range_separator", **options.merge(:locale => locale, :throw => true))
          end
          separator = nil if separator.is_a?(MissingTranslation)
          separator = nil unless separator.is_a?(::String)
          separator || DEFAULT_RANGE_SEPARATOR
        end

        def localize_full_range(locale, start_object, end_object, format, options)
          type = start_object.respond_to?(:sec) ? 'time' : 'date'
          separator = range_separator(locale, type, format, options)
          start_format = localize_range_part(locale, start_object, format, options)
          end_format = localize_range_part(locale, end_object, format, options)
          start_format << separator << end_format
        end

        def localize_range_part(locale, object, format, options)
          localize(locale, object, format, options.except(:time_zone))
        end

        def translate_range_entry(locale, key, object, options)
          entry = catch(:exception) do
            I18n.t!(key, **options.merge(:locale => locale, :throw => true, :raise => nil, :object => object))
          end
          entry unless entry.is_a?(MissingTranslation)
        end

        def pluralization_key(entry, count)
          key = :zero if count == 0 && entry.has_key?(:zero)
          key ||= count == 1 ? :one : :other
        end
    end
  end
end
