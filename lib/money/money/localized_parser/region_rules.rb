# frozen_string_literal: true

class Money
  class LocalizedParser
    module RegionRules
      NBSP = "\u00A0"
      NNBSP = "\u202F"
      SPACE_CHARS = " " + NBSP + NNBSP
      SPACES = "[" + SPACE_CHARS + "]"

      RULES = {
        western: { decimal: ".", group: "," },
        swiss: { decimal: ".", group: "'" },
        continental: { decimal: ",", group: "." },
        continental_space: { decimal: ",", group: SPACES },
        french: { decimal: ",", group: SPACES },
        brazilian: { decimal: ",", group: "." },
        indian: { decimal: ".", group: ",", first_group: :indian },
      }.freeze

      LOCALES = {
        "en-us" => { currency: "USD" }.merge(RULES.fetch(:western)),
        "en-gb" => { currency: "GBP" }.merge(RULES.fetch(:western)),
        "en-ca" => { currency: "CAD" }.merge(RULES.fetch(:western)),
        "en-au" => { currency: "AUD" }.merge(RULES.fetch(:western)),
        "en-in" => { currency: "INR" }.merge(RULES.fetch(:indian)),
        "de-de" => { currency: "EUR" }.merge(RULES.fetch(:continental)),
        "fr-fr" => { currency: "EUR" }.merge(RULES.fetch(:french)),
        "fr-ch" => { currency: "CHF" }.merge(RULES.fetch(:swiss)),
        "de-ch" => { currency: "CHF" }.merge(RULES.fetch(:swiss)),
        "it-it" => { currency: "EUR" }.merge(RULES.fetch(:continental)),
        "es-es" => { currency: "EUR" }.merge(RULES.fetch(:continental)),
        "nl-nl" => { currency: "EUR" }.merge(RULES.fetch(:continental)),
        "pt-br" => { currency: "BRL" }.merge(RULES.fetch(:brazilian)),
        "sv-se" => { currency: "SEK" }.merge(RULES.fetch(:continental_space)),
        "nb-no" => { currency: "NOK" }.merge(RULES.fetch(:continental)),
        "ru-ru" => { currency: "RUB" }.merge(RULES.fetch(:continental)),
        "pl-pl" => { currency: "PLN" }.merge(RULES.fetch(:continental_space)),
        "cs-cz" => { currency: "CZK" }.merge(RULES.fetch(:continental_space)),
        "ja-jp" => { currency: "JPY" }.merge(RULES.fetch(:western)),
        "zh-cn" => { currency: "CNY" }.merge(RULES.fetch(:western)),
      }.freeze

      ALIASES = {}.tap do |aliases|
        LOCALES.each_key do |locale|
          aliases[locale] = locale
          language, region = locale.split("-")
          aliases[region] = locale if region
          aliases["#{language}_#{region}"] = locale
        end
      end.freeze

      def self.find(name)
        key = name.to_s.tr("_", "-").downcase
        resolved = ALIASES[key] || LOCALES[key]
        LOCALES.fetch(resolved) do
          raise LocalizedParser::InvalidAmount, "unknown or regionless locale: #{name.inspect}"
        end
      end
    end
  end
end
