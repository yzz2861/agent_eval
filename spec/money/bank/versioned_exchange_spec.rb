# frozen_string_literal: true

RSpec.describe Money::Bank::VersionedExchange do
  subject(:bank) { described_class.new }

  # Fixed, fictional timestamps and rates used only for these tests.
  let(:t0) { Time.utc(2026, 1, 1) }
  let(:t1) { Time.utc(2026, 2, 1) }
  let(:t2) { Time.utc(2026, 3, 1) }

  describe "#add_rate" do
    it "registers a rate version with validity interval and source" do
      version = bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")

      expect(version.from).to eq "USD"
      expect(version.to).to eq "EUR"
      expect(version.rate).to eq BigDecimal("0.9")
      expect(version.valid_from).to eq t0
      expect(version.valid_to).to eq t1
      expect(version.source).to eq "feed-v1"
    end

    it "accepts open-ended intervals" do
      version = bank.add_rate("USD", "EUR", 0.9)

      expect(version.valid_from).to be_nil
      expect(version.valid_to).to be_nil
    end

    it "raises ArgumentError when valid_from is not before valid_to" do
      expect { bank.add_rate("USD", "EUR", 0.9, valid_from: t1, valid_to: t0) }
        .to raise_error(ArgumentError)
    end

    it "raises OverlappingRate when the interval overlaps an existing version of the same pair" do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")

      expect { bank.add_rate("USD", "EUR", 0.8, valid_from: t0, valid_to: t1, source: "feed-v2") }
        .to raise_error(Money::Bank::OverlappingRate)
      expect { bank.add_rate("USD", "EUR", 0.8, valid_from: t0 + 86_400, valid_to: t2, source: "feed-v2") }
        .to raise_error(Money::Bank::OverlappingRate)
      expect { bank.add_rate("USD", "EUR", 0.8, source: "feed-v2") }
        .to raise_error(Money::Bank::OverlappingRate)
    end

    it "allows adjacent intervals for the same pair" do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")

      expect { bank.add_rate("USD", "EUR", 0.8, valid_from: t1, valid_to: t2, source: "feed-v2") }
        .not_to raise_error
    end

    it "allows overlapping intervals for different pairs" do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1)

      expect { bank.add_rate("EUR", "USD", 1.1, valid_from: t0, valid_to: t1) }.not_to raise_error
    end
  end

  describe "#rate_at" do
    before do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")
    end

    it "returns the version effective at the given moment" do
      expect(bank.rate_at("USD", "EUR", t0 + 86_400).rate).to eq BigDecimal("0.9")
    end

    it "treats valid_from as inclusive and valid_to as exclusive" do
      expect(bank.rate_at("USD", "EUR", t0)).not_to be_nil
      expect(bank.rate_at("USD", "EUR", t1)).to be_nil
    end

    it "returns nil when no rate covers the moment" do
      expect(bank.rate_at("USD", "EUR", t2)).to be_nil
      expect(bank.rate_at("EUR", "USD", t0)).to be_nil
    end
  end

  describe "#quote" do
    context "with a direct rate" do
      before do
        bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")
        bank.add_rate("USD", "EUR", 0.8, valid_from: t1, valid_to: t2, source: "feed-v2")
      end

      it "quotes the amount using the rate effective at the given moment" do
        quote = bank.quote(Money.new(100_00, "USD"), "EUR", at: t0 + 86_400)

        expect(quote.amount).to eq Money.new(90_00, "EUR")
        expect(quote.path).to eq ["USD", "EUR"]
        expect(quote.hops.size).to eq 1
        expect(quote.hops.first.source).to eq "feed-v1"
      end

      it "uses a different historical version for a different moment" do
        quote = bank.quote(Money.new(100_00, "USD"), "EUR", at: t1 + 86_400)

        expect(quote.amount).to eq Money.new(80_00, "EUR")
        expect(quote.hops.first.source).to eq "feed-v2"
      end

      it "raises UnknownRate when no rate covers the moment" do
        expect { bank.quote(Money.new(100_00, "USD"), "EUR", at: t2) }
          .to raise_error(Money::Bank::UnknownRate)
      end

      it "raises UnknownRate for an unknown pair" do
        expect { bank.quote(Money.new(100_00, "USD"), "JPY", at: t0) }
          .to raise_error(Money::Bank::UnknownRate)
      end

      it "does not hop through intermediate currencies without an explicit strategy" do
        bank.add_rate("EUR", "JPY", 160.0, valid_from: t0, valid_to: t2, source: "feed-v1")

        expect { bank.quote(Money.new(100_00, "USD"), "JPY", at: t0 + 86_400) }
          .to raise_error(Money::Bank::UnknownRate)
      end
    end

    context "with the same currency" do
      it "returns an equivalent amount with an empty path" do
        money = Money.new(100_00, "USD")
        quote = bank.quote(money, "USD", at: t0)

        expect(quote.amount).to eq money
        expect(quote.hops).to be_empty
        expect(quote.path).to eq ["USD"]
        expect(quote.rate).to eq BigDecimal("1")
      end
    end

    context "with an explicit multi-hop strategy" do
      before do
        bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t2, source: "feed-v1")
        bank.add_rate("EUR", "JPY", 160.0, valid_from: t0, valid_to: t2, source: "feed-v1")
      end

      it "converts through the given path" do
        quote = bank.quote(Money.new(100_00, "USD"), "JPY",
                           at: t0 + 86_400, strategy: ["USD", "EUR", "JPY"])

        expect(quote.amount).to eq Money.new(14_400, "JPY")
        expect(quote.path).to eq ["USD", "EUR", "JPY"]
        expect(quote.rate).to eq BigDecimal("144")
      end

      it "requires every edge to cover the quoted moment" do
        bank = described_class.new
        bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")
        bank.add_rate("EUR", "JPY", 160.0, valid_from: t1, valid_to: t2, source: "feed-v2")

        expect { bank.quote(Money.new(100_00, "USD"), "JPY",
                            at: t0 + 86_400, strategy: ["USD", "EUR", "JPY"]) }
          .to raise_error(Money::Bank::UnknownRate)
      end

      it "raises ArgumentError when the strategy does not match source and target" do
        expect { bank.quote(Money.new(100_00, "USD"), "JPY",
                            at: t0, strategy: ["EUR", "JPY"]) }
          .to raise_error(ArgumentError)
        expect { bank.quote(Money.new(100_00, "USD"), "JPY",
                            at: t0, strategy: ["USD"]) }
          .to raise_error(ArgumentError)
      end

      it "keeps intermediate values exact and rounds only the final step" do
        bank = described_class.new
        bank.add_rate("USD", "EUR", 0.334, valid_from: t0, valid_to: t2, source: "feed-v1")
        bank.add_rate("EUR", "JPY", 4.5, valid_from: t0, valid_to: t2, source: "feed-v1")

        quote = bank.quote(Money.new(100, "USD"), "JPY",
                           at: t0 + 86_400, strategy: ["USD", "EUR", "JPY"])

        # Exact intermediate: 33.4 EUR cents; exact result 1.503 JPY.
        # Rounding the intermediate to 33 cents would give 1.485 -> 1 JPY.
        expect(quote.exact_fractional).to eq BigDecimal("1.503")
        expect(quote.amount).to eq Money.new(2, "JPY")
      end
    end

    context "snapshot behavior" do
      before do
        bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")
      end

      it "is not affected by later bank updates" do
        quote = bank.quote(Money.new(100_00, "USD"), "EUR", at: t0 + 86_400)

        bank.add_rate("USD", "EUR", 0.5, valid_from: t1, valid_to: t2, source: "feed-v2")

        expect(quote.amount).to eq Money.new(90_00, "EUR")
        expect(quote.recalculate).to eq Money.new(90_00, "EUR")
        expect(quote.hops.first.rate).to eq BigDecimal("0.9")
      end

      it "snapshots the path and the actual rate values" do
        quote = bank.quote(Money.new(100_00, "USD"), "EUR", at: t0 + 86_400)
        snapshot = quote.to_h

        expect(snapshot[:path]).to eq ["USD", "EUR"]
        expect(snapshot[:hops]).to eq(
          [{ from: "USD", to: "EUR", rate: "0.9", source: "feed-v1",
             valid_from: t0, valid_to: t1 }],
        )
        expect(snapshot[:rate]).to eq "0.9"
        expect(snapshot[:fractional]).to eq "9000"
      end
    end
  end

  describe "#exchange_with" do
    before do
      bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t2, source: "feed-v1")
    end

    it "exchanges using the rate effective at the given moment" do
      expect(bank.exchange_with(Money.new(100_00, "USD"), "EUR", at: t0 + 86_400))
        .to eq Money.new(90_00, "EUR")
    end

    it "returns the same object for the same currency" do
      money = Money.new(100_00, "USD")
      expect(bank.exchange_with(money, "USD", at: t0)).to equal money
    end

    it "uses the given rounding block" do
      bank.add_rate("USD", "JPY", 133.335, valid_from: t0, valid_to: t2, source: "feed-v1")

      exchanged = bank.exchange_with(Money.new(100, "USD"), "JPY", at: t0 + 86_400, &:floor)
      expect(exchanged).to eq Money.new(133, "JPY")
    end

    it "uses the bank rounding method when one is given" do
      bank = described_class.new { |n| n.ceil }
      bank.add_rate("USD", "JPY", 133.335, valid_from: t0, valid_to: t2, source: "feed-v1")

      expect(bank.exchange_with(Money.new(100, "USD"), "JPY", at: t0 + 86_400))
        .to eq Money.new(134, "JPY")
    end
  end
end
