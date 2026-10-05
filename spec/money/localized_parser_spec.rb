# frozen_string_literal: true

RSpec.describe Money do
  describe ".parse_localized" do
    it "parses North American grouping and decimals" do
      expect(described_class.parse_localized("1,234.50", locale: "en-US"))
        .to eq(Money.new(123_450, "USD"))
    end

    it "parses continental grouping and decimals" do
      expect(described_class.parse_localized("1.234,50", locale: "de-DE"))
        .to eq(Money.new(123_450, "EUR"))
    end

    it "parses French amounts with a narrow no-break space" do
      expect(described_class.parse_localized("1 234,50 €", locale: "fr-FR"))
        .to eq(Money.new(123_450, "EUR"))
    end

    it "parses Swiss apostrophe grouping" do
      expect(described_class.parse_localized("1'234.50", locale: "fr-CH"))
        .to eq(Money.new(123_450, "CHF"))
    end

    it "parses Brazilian, Indian, Polish and Swedish samples" do
      aggregate_failures do
        expect(described_class.parse_localized("R$ 1.234,50", locale: "pt-BR"))
          .to eq(Money.new(123_450, "BRL"))
        expect(described_class.parse_localized("₹1,00,000.00", locale: "en-IN"))
          .to eq(Money.new(10_000_000, "INR"))
        expect(described_class.parse_localized("-1 234,50 zł", locale: "pl-PL"))
          .to eq(Money.new(-123_450, "PLN"))
        expect(described_class.parse_localized("1 234,50 kr", locale: "sv-SE", currency: "SEK"))
          .to eq(Money.new(123_450, "SEK"))
      end
    end

    it "accepts minus signs before or after the amount and around symbols" do
      aggregate_failures do
        expect(described_class.parse_localized("-$1,234.50", locale: "en-US")).to eq(Money.new(-123_450, "USD"))
        expect(described_class.parse_localized("$-1,234.50", locale: "en-US")).to eq(Money.new(-123_450, "USD"))
        expect(described_class.parse_localized("1,234.50-", locale: "en-US")).to eq(Money.new(-123_450, "USD"))
      end
    end

    it "parses accounting-style parenthesized negatives" do
      aggregate_failures do
        expect(described_class.parse_localized("($1,234.50)", locale: "en-US")).to eq(Money.new(-123_450, "USD"))
        expect(described_class.parse_localized("$ (1,234.50)", locale: "en-US")).to eq(Money.new(-123_450, "USD"))
        expect(described_class.parse_localized("(1,234.50) USD", locale: "en-US")).to eq(Money.new(-123_450, "USD"))
        expect(described_class.parse_localized("(1 234,50 EUR)", locale: "fr-FR")).to eq(Money.new(-123_450, "EUR"))
      end
    end

    it "does not assume dollar always means USD" do
      expect(described_class.parse_localized("$1,234.50", locale: "en-CA")).to eq(Money.new(123_450, "CAD"))
      expect(described_class.parse_localized("$1.234,50", locale: "de-DE", currency: "USD"))
        .to eq(Money.new(123_450, "USD"))
    end

    it "allows a currency marker to clarify an ambiguous symbol" do
      expect(described_class.parse_localized("US$1,234.50", locale: "en-US")).to eq(Money.new(123_450, "USD"))
      expect(described_class.parse_localized("C$1,234.50", locale: "en-US", currency: "CAD"))
        .to eq(Money.new(123_450, "CAD"))
    end

    it "accepts explicit currency as positional argument or region alias" do
      expect(described_class.parse_localized("1,234.50", "en-US", "USD")).to eq(Money.new(123_450, "USD"))
      expect(described_class.parse_localized("1,234.50", region: "US", currency: "USD"))
        .to eq(Money.new(123_450, "USD"))
    end

    it "uses BigDecimal parsing without rounding in infinite precision mode", :default_infinite_precision_true do
      money = described_class.parse_localized("2.675", locale: "en-US", currency: "CLF")

      expect(money.fractional).to eq(BigDecimal("26750"))
    end

    it "keeps ordinary numeric constructors unchanged" do
      expect(Money.new(101, "USD").fractional).to eq(101)
      expect(Money.from_amount(2.675, "USD").fractional).to eq(268)
      expect(described_class.parse_localized("2.675", locale: "en-US", currency: "USD").fractional)
        .to eq(268)
    end

    it "rejects a lone comma as a decimal mark" do
      expect(described_class.parse_localized("1,234", locale: "en-US"))
        .to eq(Money.new(123_400, "USD"))
      expect { described_class.parse_localized("1,23", locale: "en-US") }
        .to raise_error(Money::LocalizedParsingError, "invalid digit grouping")
      expect { described_class.parse_localized("1.23", locale: "de-DE") }
        .to raise_error(Money::LocalizedParsingError, "invalid digit grouping")
    end

    it "rejects incorrect grouping lengths" do
      aggregate_failures do
        expect { described_class.parse_localized("100,000.00", locale: "en-IN") }
          .to raise_error(Money::LocalizedParsingError)
        expect { described_class.parse_localized("1,00,000.00", locale: "en-US") }
          .to raise_error(Money::LocalizedParsingError)
        expect { described_class.parse_localized("1 00 000,50", locale: "fr-FR") }
          .to raise_error(Money::LocalizedParsingError)
      end
    end

    it "rejects regionally misplaced symbols" do
      expect { described_class.parse_localized("1.234,50", locale: "en-US") }
        .to raise_error(Money::LocalizedParsingError)
      expect { described_class.parse_localized("1,234.50", locale: "fr-FR") }
        .to raise_error(Money::LocalizedParsingError)
    end

    it "rejects repeated or conflicting currency markers" do
      aggregate_failures do
        expect { described_class.parse_localized("$1,234.50 USD", locale: "en-US") }
          .to raise_error(Money::LocalizedParsingError, "multiple currency markers")
        expect { described_class.parse_localized("$1,234.50 €", locale: "en-US") }
          .to raise_error(Money::LocalizedParsingError)
        expect { described_class.parse_localized("US$1,234.50", locale: "en-US", currency: "CAD") }
          .to raise_error(Money::LocalizedParsingError, /conflicts with CAD/)
      end
    end

    it "rejects ambiguous currency symbols without an explicit currency" do
      expect { described_class.parse_localized("$1.234,50", locale: "de-DE") }
        .to raise_error(Money::LocalizedParsingError, /ambiguous currency marker/)
    end

    it "rejects multiple signs, parenthesized positives, and malformed numbers" do
      aggregate_failures do
        expect { described_class.parse_localized("--1", locale: "en-US") }.to raise_error(Money::LocalizedParsingError)
        expect { described_class.parse_localized("(+1)", locale: "en-US") }.to raise_error(Money::LocalizedParsingError)
        expect { described_class.parse_localized(",50", locale: "en-US") }.to raise_error(Money::LocalizedParsingError)
        expect do
          described_class.parse_localized("1.23.45", locale: "de-DE")
        end.to raise_error(Money::LocalizedParsingError)
        expect do
          described_class.parse_localized("1\n234.50", locale: "en-US")
        end.to raise_error(Money::LocalizedParsingError)
      end
    end

    it "requires a region and rejects non-string input" do
      expect { described_class.parse_localized("1.00", locale: "en") }.to raise_error(Money::LocalizedParsingError)
      expect { described_class.parse_localized(1.0, locale: "en-US") }.to raise_error(Money::LocalizedParsingError)
    end

  end
end
