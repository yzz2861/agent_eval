# frozen_string_literal: true

RSpec.describe Money::Bank::HistoricalExchange do
  subject(:bank) { described_class.new }

  let(:t0) { Time.utc(2024, 1, 1) }
  let(:t1) { Time.utc(2024, 7, 1) }
  let(:t2) { Time.utc(2025, 1, 1) }

  describe "#add_rate" do
    it "registers a rate with validity interval and source version" do
      rate = bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "v1")

      expect(rate).to be_a(described_class::Rate)
      expect(rate.from).to eq "USD"
      expect(rate.to).to eq "EUR"
      expect(rate.rate).to eq BigDecimal("0.9")
      expect(rate.valid_from).to eq t0
      expect(rate.valid_to).to eq t1
      expect(rate.source).to eq "v1"
      expect(bank.rates).to eq [rate]
    end

    it "accepts currency objects and symbols" do
      bank.add_rate(:usd, Money::Currency.new("EUR"), 0.9, valid_from: t0, source: "v1")

      expect(bank.rates.first.from).to eq "USD"
      expect(bank.rates.first.to).to eq "EUR"
    end

    it "accepts dates for the validity interval" do
      bank.add_rate("USD", "EUR", 0.9,
                    valid_from: Date.new(2024, 1, 1),
                    valid_to: Date.new(2024, 7, 1),
                    source: "v1")

      expect(bank.get_rate("USD", "EUR", at: Time.utc(2024, 3, 1))).to eq BigDecimal("0.9")
      expect(bank.get_rate("USD", "EUR", at: Time.utc(2024, 8, 1))).to be_nil
    end
  end

  describe "#get_rate" do
    before do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "v1")
    end

    it "returns the rate covering the given time" do
      expect(bank.get_rate("USD", "EUR", at: t0)).to eq BigDecimal("0.9")
    end

    it "treats valid_to as exclusive" do
      expect(bank.get_rate("USD", "EUR", at: t1)).to be_nil
    end

    it "returns nil when no rate covers the time" do
      expect(bank.get_rate("USD", "EUR", at: t0 - 1)).to be_nil
    end

    it "returns nil for an unknown pair" do
      expect(bank.get_rate("EUR", "USD", at: t0)).to be_nil
    end

    context "with several versions covering the same time" do
      before do
        bank.add_rate("USD", "EUR", 0.91, valid_from: t0, source: "v2")
      end

      it "raises AmbiguousRate without an explicit source" do
        expect { bank.get_rate("USD", "EUR", at: t0) }
          .to raise_error(Money::Bank::AmbiguousRate, /source/)
      end

      it "picks the requested source version" do
        expect(bank.get_rate("USD", "EUR", at: t0, source: "v2")).to eq BigDecimal("0.91")
      end
    end
  end

  describe "#quote" do
    context "with a direct rate" do
      before do
        bank.add_rate("USD", "EUR", 0.8765, valid_from: t0, source: "v1")
      end

      it "quotes a direct conversion, rounding only the final result" do
        quote = bank.quote(Money.new(10_05, "USD"), "EUR", at: t0)

        expect(quote.exact_fractional).to eq BigDecimal("880.8825")
        expect(quote.fractional).to eq 881
        expect(quote.to_money).to eq Money.new(881, "EUR")
      end

      it "records the point in time, path and actual rates" do
        quote = bank.quote(Money.new(100, "USD"), "EUR", at: t0)

        expect(quote.at).to eq t0
        expect(quote.from_currency).to eq Money::Currency.new("USD")
        expect(quote.to_currency).to eq Money::Currency.new("EUR")
        expect(quote.legs.size).to eq 1
        expect(quote.legs.first.rate).to eq BigDecimal("0.8765")
        expect(quote.legs.first.source).to eq "v1"
        expect(quote.rate).to eq BigDecimal("0.8765")
      end

      it "raises UnknownRate when the time is not covered" do
        expect { bank.quote(Money.new(100, "USD"), "EUR", at: t0 - 1) }
          .to raise_error(Money::Bank::UnknownRate, /USD.*EUR/)
      end

      it "raises UnknownRate for an unknown pair" do
        expect { bank.quote(Money.new(100, "USD"), "JPY", at: t0) }
          .to raise_error(Money::Bank::UnknownRate)
      end

      it "supports a per-call rounding block" do
        quote = bank.quote(Money.new(10_05, "USD"), "EUR", at: t0, &:floor)

        expect(quote.fractional).to eq 880
      end
    end

    context "with a bank-level rounding method" do
      subject(:bank) { described_class.new { |n| n.floor } }

      it "uses the rounding method for the final step" do
        bank.add_rate("USD", "EUR", 0.8765, valid_from: t0, source: "v1")
        quote = bank.quote(Money.new(10_05, "USD"), "EUR", at: t0)

        expect(quote.fractional).to eq 880
      end
    end

    context "with a multi-hop path" do
      before do
        bank.add_rate("USD", "EUR", 0.885, valid_from: t0, source: "v1")
        bank.add_rate("EUR", "JPY", 160, valid_from: t0, source: "v1")
      end

      it "keeps intermediate values exact and rounds only at the end" do
        # 1 cent USD -> 0.00885 EUR exactly. Rounding the intermediate to
        # EUR cents (0.01) would yield 2 JPY; the exact path yields 1 JPY.
        quote = bank.quote(Money.new(1, "USD"), "JPY", at: t0, via: ["EUR"])

        expect(quote.exact_fractional).to eq BigDecimal("1.416")
        expect(quote.to_money).to eq Money.new(1, "JPY")
      end

      it "records every leg of the path" do
        quote = bank.quote(Money.new(100_00, "USD"), "JPY", at: t0, via: ["EUR"])

        expect(quote.legs.map { |leg| [leg.from, leg.to] })
          .to eq [["USD", "EUR"], ["EUR", "JPY"]]
        expect(quote.rate).to eq BigDecimal("0.885") * BigDecimal("160")
      end

      it "requires every edge to cover the requested time" do
        bank.add_rate("EUR", "GBP", 0.85, valid_from: t1, source: "v1")

        expect { bank.quote(Money.new(100, "USD"), "GBP", at: t0, via: ["EUR"]) }
          .to raise_error(Money::Bank::UnknownRate, /EUR.*GBP/)
      end

      it "refuses to stitch legs from different source versions" do
        bank.add_rate("EUR", "GBP", 0.85, valid_from: t0, source: "v2")

        expect do
          bank.quote(Money.new(100, "USD"), "GBP", at: t0, via: %w[EUR])
        end.to raise_error(Money::Bank::AmbiguousRate, /source/)
      end

      it "allows an explicit source strategy spanning the whole path" do
        bank.add_rate("USD", "EUR", 0.9, valid_from: t0, source: "v2")
        bank.add_rate("EUR", "JPY", 161, valid_from: t0, source: "v2")

        quote = bank.quote(Money.new(100_00, "USD"), "JPY", at: t0, via: ["EUR"], source: "v2")

        expect(quote.legs.map(&:source)).to eq %w[v2 v2]
        expect(quote.rate).to eq BigDecimal("0.9") * BigDecimal("161")
      end
    end
  end

  describe "quote stability" do
    before do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, source: "v1")
    end

    it "is not affected by later bank updates" do
      quote = bank.quote(Money.new(100_00, "USD"), "EUR", at: t0)

      bank.add_rate("USD", "EUR", 0.5, valid_from: t0, source: "v2")

      expect(quote.to_money).to eq Money.new(90_00, "EUR")
      expect(quote.rate).to eq BigDecimal("0.9")
    end

    it "can be recomputed from its stored path and rates" do
      quote = bank.quote(Money.new(10_05, "USD"), "EUR", at: t0)

      bank.add_rate("USD", "EUR", 0.5, valid_from: t0, source: "v2")

      expect(quote.recompute).to eq quote
      expect(quote.recompute.exact_fractional).to eq quote.exact_fractional
    end

    it "freezes the quote and its legs" do
      quote = bank.quote(Money.new(100, "USD"), "EUR", at: t0)

      expect(quote).to be_frozen
      expect(quote.legs).to be_frozen
      expect(quote.legs.first).to be_frozen
    end
  end

  describe "#exchange_with" do
    before do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, source: "v1")
    end

    it "exchanges using the rates covering the given time" do
      expect(bank.exchange_with(Money.new(100_00, "USD"), "EUR", at: t0))
        .to eq Money.new(90_00, "EUR")
    end

    it "returns the same object when currencies match" do
      money = Money.new(100, "USD")

      expect(bank.exchange_with(money, "USD", at: t0)).to equal money
    end

    it "raises UnknownRate when the time is not covered" do
      expect { bank.exchange_with(Money.new(100, "USD"), "EUR", at: t0 - 1) }
        .to raise_error(Money::Bank::UnknownRate)
    end
  end
end
