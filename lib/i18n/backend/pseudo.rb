# frozen_string_literal: true

require 'strscan'

module I18n
  module Backend
    # Pseudolocalizes translated text for layout and character-width testing.
    # Include it in a backend, or use I18n::Backend::Pseudo with Simple.
    module Pseudolocalization
      FORMAT_PATTERN = %r{
        % (?: % |
          (?:\d+\$)?(?:[-#+ 0*:_]*(?:\d+|\*)[-#+ 0*:_]*(?:\.(?:\d+|\*))?[A-Za-z] |
          (?:\d+\$)?[-#+ 0*:_]*(?:\d+|\*)[-#+ 0*:_]*(?:\.(?:\d+|\*))?
            <[A-Za-z_]\w*>[-#+ 0*:_]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[A-Za-z] |
          <[A-Za-z_]\w*>(?:[-#+ 0*:_]*(?:\d+|\*)[-#+ 0*:_]*(?:\.(?:\d+|\*))? |
                         [-#+ 0*:_]*(?:\d+|\*)[-#+ 0*:_]*(?:\.(?:\d+|\*))?)[A-Za-z])
        )
      }x
      EMBEDDED_HTML_PATTERN = /<(script|style)\b(?:[^>"']|"[^"]*"|'[^']*')*>.*?<\/\1\s*>/im
      HTML_PATTERN = %r{
        (?:<!--.*?--> |
           <!DOCTYPE(?:[^>"']|"[^"]*"|'[^']*')*> |
           <!\[CDATA\[.*?\]\]> |
           <\/[A-Za-z][^>]*> |
           <[A-Za-z](?:[^>"']|"[^"]*"|'[^']*')*?\/?>)
      }mx
      ENTITY_PATTERN = /&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/

      TRANSLITERATIONS = {
        'a' => 'á', 'b' => 'ƀ', 'c' => 'ç', 'd' => 'ð', 'e' => 'é',
        'f' => 'ƒ', 'g' => 'ğ', 'h' => 'ħ', 'i' => 'í', 'j' => 'ĵ',
        'k' => 'ķ', 'l' => 'ĺ', 'm' => 'ɱ', 'n' => 'ñ', 'o' => 'ó',
        'p' => 'þ', 'q' => 'ǫ', 'r' => 'ŕ', 's' => 'š', 't' => 'ţ',
        'u' => 'ü', 'v' => 'ν', 'w' => 'ŵ', 'x' => '×', 'y' => 'ý',
        'z' => 'ž'
      }.freeze

      def initialize(...)
        @pseudo_locale ||= :pseudo
        @pseudo_base_locale ||= :en
        @pseudo_expansion_ratio ||= 0.3
        @pseudo_random_seed ||= 0
        @pseudo_html ||= false
        super
      end

      attr_writer :pseudo_locale, :pseudo_base_locale, :pseudo_expansion_ratio,
                  :pseudo_random_seed, :pseudo_html

      def translate(locale, key, options = EMPTY_HASH)
        return super unless pseudo_locale?(locale)

        html = options.key?(:pseudo_html) ? options[:pseudo_html] : options.fetch(:html, pseudo_html?)
        lookup_options = Utils.except(options, :html, :pseudo_html).merge(
          :skip_interpolation => true
        )

        entry = catch(:exception) { super(locale, key, lookup_options) }
        if entry.is_a?(MissingTranslation) && pseudo_base_locale && locale.to_sym != pseudo_base_locale.to_sym
          missing_translation = entry
          entry = catch(:exception) { super(pseudo_base_locale, key, lookup_options) }
          entry = missing_translation if entry.is_a?(MissingTranslation)
        end
        throw(:exception, entry) if entry.is_a?(MissingTranslation)
        return entry unless entry

        entry = pseudolocalize_entry(entry, html)
        values = Utils.except(options, *RESERVED_KEYS, :html, :pseudo_html) unless options.empty?
        if options[:skip_interpolation] || values.nil? || values.empty?
          if entry.is_a?(String) && entry =~ I18n.reserved_keys_pattern
            raise ReservedInterpolationKey.new($1.to_sym, entry)
          end
          return entry
        end

        if options[:deep_interpolation]
          deep_interpolate(locale, entry, values)
        else
          interpolate(locale, entry, values)
        end
      end

      def available_locales
        locales = super
        return locales if pseudo_locale.nil? || locales.include?(pseudo_locale)

        locales + [pseudo_locale]
      end

      def exists?(locale, key, options = EMPTY_HASH)
        return super unless pseudo_locale?(locale)
        return true if super

        base_locale = pseudo_base_locale
        base_locale && locale.to_sym != base_locale.to_sym && super(base_locale, key, options)
      end

      def pseudo_locale
        @pseudo_locale ||= :pseudo
      end

      def pseudo_base_locale
        defined?(@pseudo_base_locale) && @pseudo_base_locale ? @pseudo_base_locale : (I18n.default_locale || :en)
      end

      def pseudo_expansion_ratio
        @pseudo_expansion_ratio ||= 0.3
      end

      def pseudo_random_seed
        @pseudo_random_seed ||= 0
      end

      def pseudo_html
        @pseudo_html ||= false
      end
      alias_method :pseudo_html?, :pseudo_html

      protected

        def pseudolocalize_entry(entry, html = pseudo_html?)
          case entry
          when String
            unless pseudo_expansion_ratio.is_a?(Numeric) && pseudo_expansion_ratio >= 0
              raise ArgumentError, 'pseudo_expansion_ratio must be a non-negative number'
            end

            Pseudolocalizer.new(
              entry,
              :html => html,
              :expansion_ratio => pseudo_expansion_ratio,
              :seed => pseudo_random_seed
            ).call
          when Array
            entry.dup.map! { |item| pseudolocalize_entry(item, html) }
          when Hash
            entry.each_with_object(entry.dup) do |(key, value), result|
              result[key] = pseudolocalize_entry(value, html)
            end
          else
            entry
          end
        end

      private

        def pseudo_locale?(locale)
          pseudo_locale && locale && locale.to_sym == pseudo_locale.to_sym
        end

      class Pseudolocalizer
        def initialize(string, html:, expansion_ratio:, seed:)
          @string = string
          @html = html
          @expansion_ratio = expansion_ratio.to_f
          @seed = seed.to_i
        end

        def call
          parts = tokenize
          padding = padding_for(parts)
          random = Random.new(string_seed)
          expanded = false

          parts.map do |part|
            if part[:protected?]
              part[:value]
            else
              value = substitute(part[:value], random)
              unless expanded || padding.zero? || text_length(value).zero?
                value = "#{value}#{'~' * padding}"
                expanded = true
              end
              value
            end
          end.join
        end

        private

          attr_reader :string, :html, :expansion_ratio, :seed

          def tokenize
            scanner = StringScanner.new(string)
            parts = []

            until scanner.eos?
              token = scanner.scan(token_pattern)
              if token
                parts << { :value => token, :protected? => true }
              else
                text = scanner.scan_until(token_pattern)
                if text.nil?
                  text = scanner.rest
                  scanner.terminate
                end

                delimiter = scanner.matched
                text = text[0...-delimiter.length] if delimiter
                parts << { :value => text, :protected? => false } unless text.empty?
                parts << { :value => delimiter, :protected? => true } if delimiter
              end
            end

            parts
          end

          def token_pattern
            patterns = I18n.config.interpolation_patterns.dup
            patterns << Pseudolocalization::FORMAT_PATTERN
            if html
              patterns.concat([
                Pseudolocalization::EMBEDDED_HTML_PATTERN,
                Pseudolocalization::HTML_PATTERN,
                Pseudolocalization::ENTITY_PATTERN
              ])
            end
            Regexp.union(patterns)
          end

          def padding_for(parts)
            text_length = parts.reject { |part| part[:protected?] }.sum do |part|
              text_length(part[:value])
            end
            [(text_length * expansion_ratio).round, 0].max
          end

          def text_length(value)
            value.delete(' \t\r\n').length
          end

          def substitute(value, random)
            value.gsub(/[A-Za-z]/) do |character|
              next character unless random.rand < 0.8

              replacement = Pseudolocalization::TRANSLITERATIONS[character.downcase]
              next character unless replacement

              character == character.downcase ? replacement : replacement.upcase
            end
          end

          def string_seed
            string.each_byte.with_index.reduce(seed) do |digest, (byte, index)|
              (digest ^ (byte + index + 0x9e3779b9)) & 0xffffffff
            end
          end
      end

      private_constant :Pseudolocalizer
    end

    # Ready-to-use Simple backend with Pseudolocalization enabled.
    class Pseudo < Simple
      include Pseudolocalization

      def initialize(
        pseudo_locale: :pseudo,
        pseudo_base_locale: :en,
        expansion_ratio: 0.3,
        pseudo_expansion_ratio: expansion_ratio,
        random_seed: 0,
        pseudo_random_seed: random_seed,
        html: false,
        pseudo_html: html
      )
        @pseudo_locale = pseudo_locale
        @pseudo_base_locale = pseudo_base_locale
        @pseudo_expansion_ratio = pseudo_expansion_ratio
        @pseudo_random_seed = pseudo_random_seed
        @pseudo_html = pseudo_html
        super()
      end
    end
  end
end
