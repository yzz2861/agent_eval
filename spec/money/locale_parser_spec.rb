# frozen_string_literal: true

RSpec.describe Money::LocaleParser do
  describe "Money.parse_localized" do
    it "parses United States grouping, decimals, symbols and accounting parentheses" do
      expect(Money.parse_localized("$1,234.56", "en-US"))
        .to eq Money.new(123_456, "USD")
      expect(Money.parse_localized("($1,234.56)", :en_us))
        .to eq Money.new(-123_456, "USD")
      expect(Money.parse_localized("$(1,234.56)", :en_us))
        .to eq Money.new(-123_456, "USD")
      expect(Money.parse_localized("(1,234.56)", :en_us))
        .to eq Money.new(-123_456, "USD")
      expect(Money.parse_localized("-$1,234.56", "en-US"))
        .to eq Money.new(-123_456, "USD")
      expect(Money.parse_localized("$1,234.56-", "en-US"))
        .to eq Money.new(-123_456, "USD")
      expect(Money.parse_localized("1,234.56", "en-US", "USD"))
        .to eq Money.new(123_456, "USD")
      expect(Money.parse_localized("1,234.56", "en-US", currency: "USD"))
        .to eq Money.new(123_456, "USD")
    end

    it "does not treat a bare dollar sign as USD without the region declaring it" do
      expect(Money.parse_localized("$1,234.56", "en-CA"))
        .to eq Money.new(123_456, "CAD")
      expect(Money.parse_localized("$1,234.56", "en-US", "CAD"))
        .to eq Money.new(123_456, "CAD")
      expect(Money.parse_localized("C$1,234.56", "en-US", "CAD"))
        .to eq Money.new(123_456, "CAD")
      expect { Money.parse_localized("$1,234.56", "en-US", "EUR") }
        .to raise_error(described_class::InvalidFormat, /conflict/)
      expect { Money.parse_localized("$1,234.56", "de-DE", "EUR") }
        .to raise_error(described_class::InvalidFormat)
    end

    it "parses European decimal and grouping rules with local symbol positions" do
      expect(Money.parse_localized("1.234,56 €", "de-DE"))
        .to eq Money.new(123_456, "EUR")
      expect(Money.parse_localized("(1 234,56 €)", "de-DE"))
        .to eq Money.new(-123_456, "EUR")
      expect(Money.parse_localized("1 234,56 €", "de-DE"))
        .to eq Money.new(123_456, "EUR")
      expect(Money.parse_localized("1 234,56", "fr-FR"))
        .to eq Money.new(123_456, "EUR")
      expect(Money.parse_localized("€1.234,56", "nl-NL"))
        .to eq Money.new(123_456, "EUR")
    end

    it "parses nonbreaking and narrow nonbreaking spaces" do
      expect(Money.parse_localized("1 234,56 €", "fr-FR"))
        .to eq Money.new(123_456, "EUR")
      expect(Money.parse_localized("1 234,56 €", "fr-FR"))
        .to eq Money.new(123_456, "EUR")
      expect(Money.parse_localized("1 234,56 kr", "sv-SE"))
        .to eq Money.new(123_456, "SEK")
    end

    it "parses Indian grouping lengths" do
      expect(Money.parse_localized("₹12,34,567.89", "en-IN"))
        .to eq Money.new(12_345_678_9, "INR")
      expect(Money.parse_localized("₹1,23,456.78", "en-IN"))
        .to eq Money.new(12_345_678, "INR")
    end

    it "parses additional regional samples" do
      expect(Money.parse_localized("R$1.234,56", "pt-BR"))
        .to eq Money.new(123_456, "BRL")
      expect(Money.parse_localized("1’234.56", "de-CH"))
        .to eq Money.new(123_456, "CHF")
      expect(Money.parse_localized("1 234,56 zł", "pl-PL"))
        .to eq Money.new(123_456, "PLN")
      expect(Money.parse_localized("1 234,56 ₽", "ru-RU"))
        .to eq Money.new(123_456, "RUB")
    end

    it "rejects text that merely looks legal in another region" do
      invalid = [
        "12,34",
        "1.234",
        "12,34,56",
        "12,345,6",
        "1,2345.67",
        "1,23,456.78",
        "1.234.56",
        "1 234.56",
        "1..234,56",
        "1,234,.56",
        "1,234.56.78",
        ".56",
        "1.",
      ]

      invalid.each do |text|
        expect { Money.parse_localized(text, "en-US") }
          .to raise_error(described_class::InvalidFormat), text
      end
    end

    it "rejects invalid grouping in Indian and European formats" do
      expect { Money.parse_localized("₹1,234,567.89", "en-IN") }
        .to raise_error(described_class::InvalidFormat)
      expect { Money.parse_localized("1.234,56", "de-DE") }
        .not_to raise_error
      expect { Money.parse_localized("1.23,456.78", "de-DE") }
        .to raise_error(described_class::InvalidFormat)
      expect { Money.parse_localized("1 23.456,78", "de-DE") }
        .to raise_error(described_class::InvalidFormat)
    end

    it "rejects multiple signs and invalid parentheses or symbol positions" do
      [
        "--10",
        "-10-",
        "+-10",
        "$-10",
        "10 $-",
        "(-10)",
        "(+10)",
        "10$",
        "10 kr 20",
      ].each do |text|
        expect { Money.parse_localized(text, "en-US") }
          .to raise_error(described_class::InvalidFormat), text
      end

      expect { Money.parse_localized("€10", "de-DE") }
        .to raise_error(described_class::InvalidFormat, /wrong position/)
      expect { Money.parse_localized("10 €", "nl-NL") }
        .to raise_error(described_class::InvalidFormat, /wrong position/)
    end

    it "rejects conflicting or repeated currency markers" do
      expect(Money.parse_localized("$10 USD", "en-US"))
        .to eq Money.new(1000, "USD")
      expect(Money.parse_localized("US$10 USD", "en-US"))
        .to eq Money.new(1000, "USD")

      [
        "C$10 USD",
        "$$10",
        "USD 10 USD",
      ].each do |text|
        expect { Money.parse_localized(text, "en-US") }
          .to raise_error(described_class::InvalidFormat), text
      end
    end

    it "rejects unsupported whitespace and unknown regions" do
      expect { Money.parse_localized("1,234.56\n", "en-US") }
        .to raise_error(described_class::InvalidFormat, /line break/)
      expect { Money.parse_localized("1,234.56", :en) }
        .to raise_error(described_class::InvalidFormat, /unknown region/)
      expect { Money.parse_localized(1234.56, "en-US") }
        .to raise_error(described_class::InvalidFormat, /must be a String/)
    end

    it "uses exact decimal representations and keeps ordinary constructors unchanged" do
      money = Money.parse_localized("1,234.56", "en-US")
      expect(money.fractional).to eq(123_456)
      expect(money.fractional).to be_an(Integer)

      expect(Money.new(12_345, "USD").fractional).to eq(12_345)
      expect(Money.from_amount(1, "USD").fractional).to eq(100)
    end

    it "requires a region" do
      expect { Money.parse_localized("1,234.56", currency: "USD") }
        .to raise_error(ArgumentError, /region/)
    end

    it "has a from_localized alias" do
      expect(Money.from_localized("$1,234.56", "en-US"))
        .to eq Money.new(123_456, "USD")
    end

    it "does not silently accept excess decimal precision" do
      expect { Money.parse_localized("1.234", "en-US") }
        .to raise_error(described_class::InvalidFormat)
      expect { Money.parse_localized("1.5", "en-US", "JPY") }
        .to raise_error(described_class::InvalidFormat)
      expect(Money.parse_localized("1.234", "en-US", "TND"))
        .to eq Money.new(1234, "TND")
    end
  end
end
