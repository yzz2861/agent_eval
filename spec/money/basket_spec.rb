# frozen_string_literal: true

RSpec.describe Money::Basket do
  let(:usd_100) { Money.new(1_00, "USD") }
  let(:usd_50) { Money.new(50, "USD") }
  let(:eur_100) { Money.new(1_00, "EUR") }
  let(:jpy_100) { Money.new(100, "JPY") }

  describe ".empty" do
    it "returns an empty basket" do
      expect(described_class.empty).to be_empty
      expect(described_class.empty).to be_zero
    end
  end

  describe "#initialize" do
    it "nets amounts sharing the same currency" do
      basket = described_class.new([usd_100, usd_50])
      expect(basket["USD"]).to eq(Money.new(1_50, "USD"))
    end

    it "keeps amounts in different currencies separate" do
      basket = described_class.new([usd_100, eur_100])
      expect(basket["USD"]).to eq(usd_100)
      expect(basket["EUR"]).to eq(eur_100)
    end

    it "drops zero balances" do
      basket = described_class.new([usd_100, Money.new(0, "EUR")])
      expect(basket.currencies).to eq([Money::Currency.new("USD")])
    end

    it "drops balances that net to zero" do
      basket = described_class.new([usd_100, Money.new(-1_00, "USD")])
      expect(basket).to be_empty
    end

    it "raises a TypeError for elements that are not Money" do
      expect { described_class.new([100]) }.to raise_error(TypeError)
    end
  end

  describe "#currencies and #monies" do
    it "returns currencies sorted by id regardless of insertion order" do
      basket = described_class.new([usd_100, eur_100, jpy_100])
      expect(basket.currencies.map(&:id)).to eq(%i[eur jpy usd])
    end

    it "returns one Money per currency" do
      basket = described_class.new([usd_100, eur_100])
      expect(basket.monies).to contain_exactly(usd_100, eur_100)
    end
  end

  describe "#each" do
    it "iterates over the monies" do
      basket = described_class.new([usd_100, eur_100])
      expect(basket.map(&:currency)).to eq(basket.currencies)
    end
  end

  describe "#[]" do
    it "returns the net amount for a currency" do
      basket = described_class.new([usd_100, usd_50])
      expect(basket["USD"]).to eq(Money.new(1_50, "USD"))
      expect(basket[:usd]).to eq(Money.new(1_50, "USD"))
      expect(basket[Money::Currency.new("USD")]).to eq(Money.new(1_50, "USD"))
    end

    it "returns a zero Money for a currency the basket does not hold" do
      basket = described_class.new([usd_100])
      expect(basket["EUR"]).to eq(Money.new(0, "EUR"))
    end
  end

  describe "#merge and #+" do
    it "combines two baskets per currency without conversion" do
      basket = described_class.new([usd_100]) + described_class.new([eur_100])
      expect(basket["USD"]).to eq(usd_100)
      expect(basket["EUR"]).to eq(eur_100)
    end

    it "nets amounts in the same currency" do
      basket = described_class.new([usd_100]) + described_class.new([usd_50])
      expect(basket["USD"]).to eq(Money.new(1_50, "USD"))
    end

    it "accepts a single Money object" do
      basket = described_class.new([usd_100]) + eur_100
      expect(basket["EUR"]).to eq(eur_100)
    end

    it "does not modify the operands" do
      basket = described_class.new([usd_100])
      basket + eur_100
      expect(basket.currencies).to eq([Money::Currency.new("USD")])
    end

    it "drops balances that cancel out" do
      basket = described_class.new([usd_100]) + Money.new(-1_00, "USD")
      expect(basket).to be_empty
    end

    it "raises a TypeError for unsupported types" do
      expect { described_class.empty + 1 }.to raise_error(TypeError)
    end
  end

  describe "#-" do
    it "subtracts another basket per currency" do
      basket = described_class.new([usd_100, eur_100]) - described_class.new([usd_50])
      expect(basket["USD"]).to eq(usd_50)
      expect(basket["EUR"]).to eq(eur_100)
    end

    it "subtracts a single Money object" do
      basket = described_class.new([usd_100]) - usd_50
      expect(basket["USD"]).to eq(usd_50)
    end

    it "can produce negative balances" do
      basket = described_class.empty - usd_100
      expect(basket["USD"]).to eq(Money.new(-1_00, "USD"))
    end

    it "raises a TypeError for unsupported types" do
      expect { described_class.empty - 1 }.to raise_error(TypeError)
    end
  end

  describe "#-@" do
    it "negates every balance" do
      basket = -described_class.new([usd_100, eur_100])
      expect(basket["USD"]).to eq(Money.new(-1_00, "USD"))
      expect(basket["EUR"]).to eq(Money.new(-1_00, "EUR"))
    end
  end

  describe "#*" do
    it "scales every balance by the given ratio" do
      basket = described_class.new([usd_100, eur_100]) * 2
      expect(basket["USD"]).to eq(Money.new(2_00, "USD"))
      expect(basket["EUR"]).to eq(Money.new(2_00, "EUR"))
    end

    it "supports fractional ratios" do
      basket = described_class.new([usd_100]) * 0.5
      expect(basket["USD"]).to eq(usd_50)
    end

    it "returns an empty basket when scaled by zero" do
      basket = described_class.new([usd_100, eur_100]) * 0
      expect(basket).to be_empty
    end

    it "raises a TypeError when the ratio is not numeric" do
      expect { described_class.new([usd_100]) * "2" }.to raise_error(TypeError)
    end
  end

  describe "#== and #eql?" do
    it "is equal to a basket with the same balances" do
      basket = described_class.new([usd_100, eur_100])
      other = described_class.new([eur_100, usd_100])
      expect(basket).to eq(other)
      expect(basket).to eql(other)
    end

    it "is not affected by the order amounts were added in" do
      basket = described_class.new([usd_100, usd_50, eur_100])
      other = described_class.new([eur_100, usd_50, usd_100])
      expect(basket).to eq(other)
      expect(basket.hash).to eq(other.hash)
    end

    it "is not changed by adding or removing zero entries" do
      basket = described_class.new([usd_100])
      with_zero = described_class.new([usd_100, Money.new(0, "EUR")])
      expect(basket).to eq(with_zero)
      expect(basket.hash).to eq(with_zero.hash)
      expect(basket + Money.new(0, "JPY")).to eq(basket)
    end

    it "is not equal to a basket with different balances" do
      basket = described_class.new([usd_100])
      expect(basket).not_to eq(described_class.new([usd_50]))
      expect(basket).not_to eq(described_class.new([eur_100]))
      expect(basket).not_to eq(usd_100)
    end

    it "can be used as a Hash key" do
      hash = { described_class.new([usd_100, eur_100]) => :found }
      expect(hash[described_class.new([eur_100, usd_100])]).to eq(:found)
    end
  end

  describe "#<=>" do
    it "compares baskets per currency" do
      small = described_class.new([usd_50, eur_100])
      big = described_class.new([usd_100, eur_100])
      expect(small).to be < big
      expect(big).to be > small
      expect(small).to be <= described_class.new([usd_50, eur_100])
    end

    it "returns nil when baskets are not consistently ordered" do
      basket = described_class.new([usd_100, eur_100])
      other = described_class.new([usd_50, Money.new(2_00, "EUR")])
      expect(basket <=> other).to be_nil
    end

    it "returns nil when compared with a non-basket" do
      expect(described_class.empty <=> usd_100).to be_nil
    end

    it "compares two empty baskets as equal" do
      expect(described_class.empty <=> described_class.empty).to eq(0)
      expect(described_class.empty).to be <= described_class.new([usd_100])
    end
  end

  describe "#value_in" do
    it "values the basket in a single currency using explicit rates" do
      basket = described_class.new([usd_100, eur_100])
      value = basket.value_in("USD", "EUR" => 1.5)
      expect(value).to eq(Money.new(2_50, "USD"))
    end

    it "does not require a rate for the target currency itself" do
      basket = described_class.new([usd_100])
      expect(basket.value_in("USD", {})).to eq(usd_100)
    end

    it "accepts currency keys as String, Symbol or Currency" do
      basket = described_class.new([eur_100])
      expect(basket.value_in("USD", "EUR" => 2)).to eq(Money.new(2_00, "USD"))
      expect(basket.value_in("USD", eur: 2)).to eq(Money.new(2_00, "USD"))
      expect(basket.value_in("USD", Money::Currency.new("EUR") => 2)).to eq(Money.new(2_00, "USD"))
    end

    it "returns a zero Money for an empty basket" do
      expect(described_class.empty.value_in("USD", {})).to eq(Money.new(0, "USD"))
    end

    it "raises MissingRatesError reporting every missing rate" do
      basket = described_class.new([usd_100, eur_100, jpy_100])
      expect { basket.value_in("USD", {}) }
        .to raise_error(Money::Basket::MissingRatesError, /EUR, JPY/)
    end

    it "exposes the missing currencies and the target currency on the error" do
      basket = described_class.new([eur_100, jpy_100])
      basket.value_in("USD", "JPY" => 0.01)
    rescue Money::Basket::MissingRatesError => e
      expect(e.missing_currencies).to eq([Money::Currency.new("EUR")])
      expect(e.target_currency).to eq(Money::Currency.new("USD"))
    else
      raise "expected Money::Basket::MissingRatesError"
    end

    it "raises a TypeError when a rate is not numeric" do
      basket = described_class.new([eur_100])
      expect { basket.value_in("USD", "EUR" => "1.5") }.to raise_error(TypeError)
    end
  end

  describe "#inspect" do
    it "returns a human readable representation" do
      basket = described_class.new([usd_100])
      expect(basket.inspect).to include("Money::Basket")
    end
  end
end
