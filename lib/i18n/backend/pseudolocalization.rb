# frozen_string_literal: true

require 'strscan'
require 'zlib'

module I18n
  module Backend
    # Pseudolocalization makes ordinary copy wider and replaces some letters
    # while preserving machine-readable parts of a translation.
    #
    #   I18n::Backend::Simple.include(I18n::Backend::Pseudolocalization)
    #   I18n.backend.store_translations(:en, message: 'Hello %{name}')
    #   I18n.t(:message, locale: :pseudo, name: 'World')
    #
    #   I18n::Backend::Pseudolocalization.configure do |config|
    #     config.expansion_ratio = 0.4
    #     config.random_seed = 42
    #     config.html = true
    #   end
    #
    # The :pseudo locale and locales ending in -pseudo, -xa, or -zxx use
    # I18n.default_locale as their source. A prefixed pseudo locale such as
    # :"de-pseudo" uses its prefix (:de) as the source.
    module Pseudolocalization
      PSEUDO_LOCALE_SUFFIX = /(?:-pseudo|-xa|-zxx)\z/i
      private_constant :PSEUDO_LOCALE_SUFFIX

      SETTINGS_OPTION = :__i18n_pseudolocalization__
      private_constant :SETTINGS_OPTION

      I18n.reserve_key(SETTINGS_OPTION) unless I18n::RESERVED_KEYS.include?(SETTINGS_OPTION)

      class << self
        # Locale that uses I18n.default_locale as its source locale.
        attr_accessor :pseudo_locale

        # Explicit source locale. When nil, a prefixed pseudo locale uses its
        # prefix and all other pseudo locales use I18n.default_locale.
        attr_accessor :source_locale

        # Amount of filler added to ordinary text. 0.3 adds approximately 30%.
        attr_accessor :expansion_ratio

        # Seed used by the deterministic letter replacement.
        attr_accessor :random_seed

        # When true, HTML tags, attributes, and entities remain unchanged.
        attr_accessor :html

        def configure
          yield self
        end

        alias_method :expansion, :expansion_ratio
        alias_method :expansion=, :expansion_ratio=
        alias_method :seed, :random_seed
        alias_method :seed=, :random_seed=

        def reset_configuration!
          @pseudo_locale = :pseudo
          @source_locale = nil
          @expansion_ratio = 0.3
          @random_seed = 1234
          @html = false
        end
      end

      reset_configuration!

      def self.transform(value, **options)
        Transformer.new(**options).transform(value)
      end

      class Transformer
        INTERPOLATION = /%\{[^}]*\}/
        NAMED_PRINTF = /%<[A-Za-z_]\w*>[+\-0 #]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[A-Za-z]/
        PRINTF_WITH_WIDTH = /%(?:<[A-Za-z_]\w*>|[1-9]\d+\$)?[+\-0 #]*(?:\d+|\*)(?:\.(?:\d+|\*))?[A-Za-z]/
        ESCAPED_PERCENT = /%%/
        HTML_ENTITY = /&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);/
        HTML_TAG = %r{
          <!--.*?--> |
          <!\[CDATA\[.*?\]\]> |
          <![A-Z][^<>]*> |
          <\?.*?\?> |
          </?[A-Za-z][^<>]*>
        }xmui

        LETTER_REPLACEMENTS = {
          'a' => %w[á à â ä ā],
          'b' => %w[ƀ],
          'c' => %w[ç ć č ĉ],
          'd' => %w[ð ď],
          'e' => %w[é è ê ë ē],
          'f' => %w[ƒ],
          'g' => %w[ĝ ğ ġ],
          'h' => %w[ĥ],
          'i' => %w[í ì î ï ī],
          'j' => %w[ĵ],
          'k' => %w[ķ],
          'l' => %w[ļ ł],
          'm' => %w[ḿ],
          'n' => %w[ñ ń],
          'o' => %w[ó ò ô ö ō],
          'p' => %w[þ],
          'q' => %w[ǫ],
          'r' => %w[ř],
          's' => %w[š ś ŝ],
          't' => %w[ŧ],
          'u' => %w[ú ù û ü ū],
          'v' => %w[ṽ],
          'w' => %w[ŵ],
          'x' => %w[ẍ],
          'y' => %w[ý ŷ ÿ],
          'z' => %w[ž ź]
        }.freeze

        def initialize(expansion_ratio: nil,
                       expansion: nil,
                       random_seed: nil,
                       seed: nil,
                       html: Pseudolocalization.html)
          expansion_ratio ||= expansion || Pseudolocalization.expansion_ratio
          random_seed ||= seed || Pseudolocalization.random_seed

          expansion_ratio = Float(expansion_ratio)
          if expansion_ratio.negative? || !expansion_ratio.finite?
            raise ArgumentError, 'expansion_ratio must be a finite number greater than or equal to 0'
          end

          @expansion_ratio = expansion_ratio.to_f
          @random_seed = normalize_seed(random_seed)
          @html = html
        end

        def transform(value)
          return value if pseudolocalized?(value)

          scanner = StringScanner.new(value)
          result = +'['
          ordinary_character_count = 0
          random = Random.new(@random_seed ^ Zlib.crc32(value))

          until scanner.eos?
            token = scan_preserved_token(scanner)

            if token
              result << token
            else
              character = scanner.getch
              ordinary_character_count += 1 if character.match?(/[[:alpha:]]/)
              result << transform_character(character, random)
            end
          end

          result << '~' * (ordinary_character_count * @expansion_ratio).ceil
          result << ']'
          result.instance_variable_set(:@__i18n_pseudolocalized__, true)
          result
        end

        private

          def scan_preserved_token(scanner)
            scanner.scan(INTERPOLATION) ||
              scanner.scan(NAMED_PRINTF) ||
              scanner.scan(PRINTF_WITH_WIDTH) ||
              scanner.scan(ESCAPED_PERCENT) ||
              (@html && scanner.scan(HTML_ENTITY)) ||
              (@html && scanner.scan(HTML_TAG))
          end

          def pseudolocalized?(value)
            value.instance_variable_defined?(:@__i18n_pseudolocalized__)
          end

          def transform_character(character, random)
            lowercase = character.downcase
            replacements = LETTER_REPLACEMENTS[lowercase]

            return character unless replacements
            return character if random.rand >= 0.85

            replacement = replacements.sample(random: random)
            character == lowercase ? replacement : replacement.upcase
          end

          def normalize_seed(seed)
            seed.is_a?(Integer) ? seed : Zlib.crc32(seed.to_s)
          end
      end

      def translate(locale, key, options = EMPTY_HASH)
        forced = options[:pseudo] == true
        return super unless forced || pseudo_locale?(locale)

        source_locale = pseudo_source_locale(locale, forced)
        pseudo_options = options.dup
        pseudo_options.delete(:pseudo)
        pseudo_options[SETTINGS_OPTION] = true
        previous_active = pseudo_state(:i18n_pseudolocalization_active)
        previous_transformed = pseudo_state(:i18n_pseudolocalization_transformed)
        set_pseudo_state(:i18n_pseudolocalization_active, true)
        set_pseudo_state(:i18n_pseudolocalization_transformed, false)

        begin
          result = super(source_locale, key, pseudo_options)
          result = pseudolocalize_entry(result) unless pseudo_state(:i18n_pseudolocalization_transformed)
          result
        ensure
          set_pseudo_state(:i18n_pseudolocalization_active, previous_active)
          set_pseudo_state(:i18n_pseudolocalization_transformed, previous_transformed)
        end
      end

      protected

        def interpolate(locale, entry, values = EMPTY_HASH)
          if pseudo_active?
            entry = pseudolocalize_entry(entry)
            set_pseudo_state(:i18n_pseudolocalization_transformed, true)
          end

          super
        end

        def deep_interpolate(locale, entry, values = EMPTY_HASH)
          if pseudo_active?
            entry = pseudolocalize_entry(entry)
            set_pseudo_state(:i18n_pseudolocalization_transformed, true)
          end

          super
        end

      private

        def pseudo_active?
          pseudo_state(:i18n_pseudolocalization_active) == true
        end

        def pseudo_state(key)
          if Fiber.respond_to?(:[])
            Fiber[key]
          else
            Thread.current[key]
          end
        end

        def set_pseudo_state(key, value)
          if Fiber.respond_to?(:[])
            Fiber[key] = value
          else
            Thread.current[key] = value
          end
        end

        def pseudo_locale?(locale)
          locale.to_s == Pseudolocalization.pseudo_locale.to_s ||
            locale.to_s.match?(PSEUDO_LOCALE_SUFFIX) ||
            locale.to_s =~ /\A(?:xa|zxx)\z/i
        end

        def pseudo_source_locale(locale, forced = false)
          return Pseudolocalization.source_locale if Pseudolocalization.source_locale

          locale_name = locale.to_s
          if locale_name.match?(PSEUDO_LOCALE_SUFFIX)
            locale_name.sub(PSEUDO_LOCALE_SUFFIX, '').to_sym
          elsif forced
            locale
          else
            I18n.default_locale
          end
        end

        def pseudolocalize_entry(entry)
          transformer = Transformer.new

          deep_pseudolocalize(entry, transformer)
        end

        def deep_pseudolocalize(entry, transformer)
          case entry
          when String
            transformer.transform(entry)
          when Array
            entry.map { |item| deep_pseudolocalize(item, transformer) }
          when Hash
            entry.each_with_object({}) do |(key, value), result|
              result[key] = deep_pseudolocalize(value, transformer)
            end
          when Proc
            return entry if entry.instance_variable_defined?(:@__i18n_pseudolocalized__)

            wrapped = entry
            ->(*args, **kwargs, &block) do
              deep_pseudolocalize(wrapped.call(*args, **kwargs, &block), transformer)
            end.tap do |wrapper|
              wrapper.instance_variable_set(:@__i18n_pseudolocalized__, true)
            end
          else
            entry
          end
        end
    end
  end
end
