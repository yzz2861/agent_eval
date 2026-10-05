# frozen_string_literal: true

RSpec.describe Money::Basket do
  let(:usd_100) { Money.new(100, "USD") }
  let(:eur_50) { Money.new(50, "EUR") }
  let(:basket) { Money::Basket.new([usd_100, eur_50]) }

  describe ".new" do
    it "keeps one net balance per currency" do
      basket = Money::Basket.new([Money.new(100, "USD"), Money.new(25, "USD"), eur_50])
      expect(basket.to_h).to eq(
        Money::Currency.new("USD") => Money.new(125, "USD"),
        Money::Currency.new("EUR") => eur_50,
      )
    end

    it "never converts between currencies" do
      expect(basket.monies).to contain_exactly(usd_100, eur_50)
    end

    it "drops balances that net to zero" do
      basket = Money::Basket.new([usd_100, Money.new(-100, "USD")])
      expect(basket).to eq Money::Basket.empty
      expect(basket).to be_zero
    end

    it "raises a TypeError for non-Money entries" do
      expect { Money::Basket.new([100]) }.to raise_error(TypeError)
    end

    it "is immutable" do
      expect(basket).to be_frozen
      expect { basket.to_h[:usd] = usd_100 }.not_to change { basket.to_h }
    end
  end

  describe ".empty" do
    it "is empty and zero" do
      expect(Money::Basket.empty).to be_empty
      expect(Money::Basket.empty).to be_zero
    end
  end

  describe "#monies and #currencies" do
    it "enumerates balances in a deterministic order" do
      reversed = Money::Basket.new([eur_50, usd_100])
      expect(basket.monies).to eq reversed.monies
      expect(basket.currencies.map(&:id)).to eq [:eur, :usd]
    end
  end

  describe "#+" do
    it "merges another basket per currency without conversion" do
      other = Money::Basket.new([Money.new(10, "USD"), Money.new(5, "JPY")])
      merged = basket + other
      expect(merged.to_h).to eq(
        Money::Currency.new("USD") => Money.new(110, "USD"),
        Money::Currency.new("EUR") => eur_50,
        Money::Currency.new("JPY") => Money.new(5, "JPY"),
      )
    end

    it "merges a single Money object" do
      expect((basket + Money.new(1, "USD")).to_h[Money::Currency.new("USD")]).to eq Money.new(101, "USD")
    end

    it "does not mutate the operands" do
      other = Money::Basket.new([Money.new(10, "USD")])
      basket + other
      expect(basket.to_h.size).to eq 2
      expect(other.to_h.size).to eq 1
    end

    it "raises a TypeError for unsupported types" do
      expect { basket + 1 }.to raise_error(TypeError)
    end
  end

  describe "#-" do
    it "subtracts another basket per currency" do
      result = basket - Money::Basket.new([Money.new(40, "USD"), eur_50])
      expect(result.to_h).to eq(Money::Currency.new("USD") => Money.new(60, "USD"))
    end

    it "subtracts a single Money object" do
      result = basket - Money.new(100, "USD")
      expect(result.to_h).to eq(Money::Currency.new("EUR") => eur_50)
    end

    it "can produce negative balances" do
      result = basket - Money.new(200, "USD")
      expect(result.to_h[Money::Currency.new("USD")]).to eq Money.new(-100, "USD")
    end
  end

  describe "#-@" do
    it "negates every balance" do
      expect((-basket).to_h).to eq(
        Money::Currency.new("USD") => Money.new(-100, "USD"),
        Money::Currency.new("EUR") => Money.new(-50, "EUR"),
      )
    end
  end

  describe "#*" do
    it "scales every balance by the same factor" do
      expect((basket * 2).to_h).to eq(
        Money::Currency.new("USD") => Money.new(200, "USD"),
        Money::Currency.new("EUR") => Money.new(100, "EUR"),
      )
    end

    it "drops balances scaled to zero" do
      expect(basket * 0).to eq Money::Basket.empty
    end

    it "raises a TypeError when the factor is not numeric" do
      expect { basket * "2" }.to raise_error(TypeError)
    end
  end

  describe "#== and #eql?" do
    it "is not affected by the order currencies were added" do
      expect(basket).to eq Money::Basket.new([eur_50, usd_100])
      expect(basket).to eql Money::Basket.new([eur_50, usd_100])
      expect(basket.hash).to eq Money::Basket.new([eur_50, usd_100]).hash
    end

    it "is not affected by zero balances" do
      with_zero = basket + Money.new(0, "JPY")
      expect(with_zero).to eq basket
      expect(with_zero.hash).to eq basket.hash
    end

    it "differs when any per-currency balance differs" do
      expect(basket).not_to eq Money::Basket.new([Money.new(101, "USD"), eur_50])
      expect(basket).not_to eq Money::Basket.new([usd_100])
      expect(basket).not_to eq usd_100
    end
  end

  describe "#<=>" do
    it "compares baskets per currency" do
      smaller = Money::Basket.new([Money.new(50, "USD"), Money.new(50, "EUR")])
      greater = Money::Basket.new([Money.new(100, "USD"), Money.new(51, "EUR")])
      expect(smaller <=> basket).to eq(-1)
      expect(greater <=> basket).to eq 1
      expect(basket <=> Money::Basket.new([eur_50, usd_100])).to eq 0
      expect(smaller).to be < basket
      expect(greater).to be > basket
    end

    it "is incomparable when currency sets differ" do
      other = Money::Basket.new([usd_100, Money.new(5, "JPY")])
      expect(basket <=> other).to be_nil
      expect(basket <=> Money::Basket.new([usd_100])).to be_nil
    end

    it "is incomparable when per-currency directions disagree" do
      mixed = Money::Basket.new([Money.new(200, "USD"), Money.new(1, "EUR")])
      expect(basket <=> mixed).to be_nil
    end

    it "returns nil for non-basket arguments" do
      expect(basket <=> usd_100).to be_nil
    end
  end

  describe "#value_in" do
    it "converts every balance using the given quotes" do
      total = basket.value_in("EUR", "USD" => BigDecimal("0.5"))
      expect(total).to eq Money.from_amount(BigDecimal("1.0"), "EUR")
    end

    it "requires no quote for the target currency" do
      total = basket.value_in("USD", "EUR" => 2)
      expect(total).to eq Money.from_amount(2, "USD")
    end

    it "accepts currency objects and symbols as quote keys" do
      total = basket.value_in(:eur, Money::Currency.new("USD") => Rational(1, 2))
      expect(total).to eq Money.from_amount(BigDecimal("1.0"), "EUR")
    end

    it "reports every missing quote" do
      basket = Money::Basket.new([usd_100, eur_50, Money.new(5, "JPY")])
      expect { basket.value_in("GBP", {}) }.to raise_error(Money::Basket::MissingQuotesError) do |error|
        expect(error.missing_currencies.map(&:id)).to eq [:eur, :jpy, :usd]
        expect(error.message).to include("EUR", "JPY", "USD")
      end
    end

    it "does not require quotes for zero balances" do
      basket = Money::Basket.new([usd_100, Money.new(0, "JPY")])
      expect(basket.value_in("USD", {})).to eq Money.new(100, "USD")
    end

    it "validates the quotes argument" do
      expect { basket.value_in("EUR", "not a hash") }.to raise_error(ArgumentError)
      expect { basket.value_in("EUR", "USD" => "0.5") }.to raise_error(ArgumentError)
    end

    it "does not modify the basket" do
      basket.value_in("EUR", "USD" => 1)
      expect(basket.to_h.size).to eq 2
    end
  end

  describe "#inspect" do
    it "lists balances per currency" do
      expect(basket.inspect).to eq "#<Money::Basket EUR:50 USD:100>"
    end
  end
end
