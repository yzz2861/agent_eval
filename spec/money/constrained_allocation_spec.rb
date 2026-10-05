# frozen_string_literal: true

RSpec.describe Money::Allocation do
  describe "generate_with_constraints" do
    # Independent reference for the continuous ideal: try every boundary
    # pattern (0 = fixed on min, 1 = fixed on max, 2 = free) and keep the one
    # satisfying the proportional water-filling stationarity conditions.
    def ideal_shares(total, parts)
      n = parts.length
      mins = parts.map { |part| part.fetch(:min, 0).to_r }
      maxs = parts.map { |part| part[:max]&.to_r }
      weights = parts.map { |part| part.fetch(:weight, 1).to_r }
      if weights.all?(&:zero?)
        all_fixed = mins.sum == total
        weights.each_index { |index| weights[index] = 1 if !all_fixed && maxs[index].nil? }
      end

      [0, 1, 2].repeated_permutation(n).each do |pattern|
        shares = Array.new(n)
        free_indices = []
        free_weight = 0.to_r
        fixed_total = 0.to_r
        valid_pattern = true

        pattern.each_with_index do |state, index|
          case state
          when 0
            shares[index] = mins[index]
            fixed_total += mins[index]
          when 1
            valid_pattern = false if maxs[index].nil?
            valid_pattern = false if weights[index].zero? && maxs[index] != mins[index]
            shares[index] = maxs[index]
            fixed_total += maxs[index].to_r
          when 2
            if weights[index].zero?
              valid_pattern = false
            else
              free_indices << index
              free_weight += weights[index]
              fixed_total += mins[index]
            end
          end
        end
        next unless valid_pattern

        if free_weight.zero?
          next unless fixed_total == total
          scale_low = 0.to_r
          scale_high = Float::INFINITY
          pattern.each_with_index do |state, index|
            next if weights[index].zero?

            if state == 1
              scale_low = [scale_low, (maxs[index] - mins[index]) / weights[index]].max
            elsif state == 0
              scale_high = 0
            end
          end
          zero_weight_valid = pattern.each_with_index.all? do |state, index|
            weights[index].positive? || state != 1 || maxs[index] == mins[index]
          end
          return shares if scale_low <= scale_high && zero_weight_valid
          next
        end

        remainder = total.to_r - fixed_total
        next if remainder.negative?
        t = remainder / free_weight

        free_indices.each { |index| shares[index] = mins[index] + t * weights[index] }

        valid = pattern.each_with_index.all? do |state, index|
          case state
          when 0
            weights[index].zero? || t.zero?
          when 1
            mins[index] + t * weights[index] >= maxs[index]
          else
            shares[index] > mins[index] && (!maxs[index] || shares[index] < maxs[index])
          end
        end
        return shares if valid
      end

      raise "no ideal allocation found"
    end

    def brute_force(total, parts, ideal)
      mins = parts.map { |part| part.fetch(:min, 0).to_i }
      maxs = parts.map { |part| (part[:max] || total).to_i }
      candidates = mins.each_index.map { |index| (mins[index]..maxs[index]).to_a }

      feasible = candidates.first.product(*candidates.drop(1)).select do |values|
        values.sum == total
      end

      feasible.min_by do |values|
        l1 = values.each_with_index.sum { |value, index| (value - ideal[index]).abs }
        l2 = values.each_with_index.sum { |value, index| (value - ideal[index])**2 }
        # Earlier indices win remainder ties, mirroring the documented rule.
        base = total + 1
        lexicographic = values.each_with_index.sum do |value, index|
          -value * base**(values.length - index)
        end
        [l1, l2, lexicographic]
      end
    end

    def assert_matches_reference(total, parts)
      result = described_class.generate_with_constraints(total, parts)
      ideal = ideal_shares(total.abs, normalized_parts(parts))
      expected = brute_force(total.abs, normalized_parts(parts), ideal)
      expect(result.map(&:abs)).to eq(expected)
    end

    def normalized_parts(parts)
      parts.map do |part|
        {
          weight: part.fetch(:weight, 1).to_r,
          min: part.fetch(:min, 0).to_r,
          max: part[:max]&.to_r,
        }
      end
    end

    it "matches exhaustive L1-optimal solutions across small cases" do
      weight_sets = [0, 1, 2, 3]
      min_sets = [0, 1, 3]
      max_sets = [nil, 2, 5]

      weight_sets.repeated_permutation(3).to_a.uniq.each do |weights|
        min_sets.repeated_permutation(3).to_a.uniq.each do |mins|
          max_sets.repeated_permutation(3).to_a.uniq.each do |maxs|
            parts = weights.each_index.map do |index|
              part = { weight: weights[index], min: mins[index] }
              part[:max] = maxs[index] if maxs[index]
              part
            end

            next if parts.any? { |part| part[:max] && part[:max] < part[:min] }
            next if mins.sum > 7

            effective_weights = weights.map(&:to_r)
            if effective_weights.all?(&:zero?)
              all_fixed = mins.sum == 7
              unless all_fixed
                effective_weights.each_index do |index|
                  effective_weights[index] = 1 if parts[index][:max].nil?
                end
              end
            end
            bounded = parts.each_with_index.all? do |part, index|
              effective_weights[index].zero? || part[:max]
            end
            capacity = parts.each_with_index.sum do |part, index|
              effective_weights[index].zero? ? mins[index] : (part[:max] || 0)
            end
            next if bounded && capacity < 7

            assert_matches_reference(7, parts)
          end
        end
      end
    end

    it "redistributes after a maximum is hit instead of clamping" do
      result = described_class.generate_with_constraints(100, [
        { weight: 1, max: 10 },
        { weight: 1 },
        { weight: 1 },
      ])

      expect(result).to eq([10, 45, 45])
    end

    it "chains redistribution when several maximums bind" do
      result = described_class.generate_with_constraints(100, [
        { weight: 1, max: 20 },
        { weight: 1, max: 30 },
        { weight: 1 },
      ])

      expect(result).to eq([20, 30, 50])
    end

    it "honours minimums before proportional sharing" do
      result = described_class.generate_with_constraints(10, [
        { weight: 1, min: 3, max: 3 },
        { weight: 1 },
        { weight: 1 },
      ])

      expect(result).to eq([3, 4, 3])
      expect(result.sum).to eq(10)
    end

    it "fixes zero-weight parts at their minimum" do
      result = described_class.generate_with_constraints(100, [
        { weight: 0, min: 5 },
        { weight: 1 },
        { weight: 1 },
      ])

      expect(result).to eq([5, 48, 47])
    end

    it "splits evenly when all weights are zero and minimums allow it" do
      expect(described_class.generate_with_constraints(100, [
        { weight: 0, min: 0 },
        { weight: 0, min: 0 },
      ])).to eq([50, 50])

      expect(described_class.generate_with_constraints(5, [
        { weight: 0 },
        { weight: 0 },
        { weight: 0 },
      ])).to eq([2, 2, 1])
    end

    it "raises when all-zero weights cannot cover the minimums" do
      expect {
        described_class.generate_with_constraints(10, [
          { weight: 0, min: 6 },
          { weight: 0, min: 5 },
        ])
      }.to raise_error(ArgumentError, /minimum amounts/)
    end

    it "raises when positive-weight parts cannot absorb beyond their maximums" do
      expect {
        described_class.generate_with_constraints(100, [
          { weight: 0, min: 10, max: 10 },
          { weight: 1, max: 40 },
        ])
      }.to raise_error(ArgumentError, /maximum amounts/)
    end

    it "applies largest-remainder apportionment with stable ties" do
      expect(described_class.generate_with_constraints(100, [
        { weight: 1 }, { weight: 1 }, { weight: 1 }
      ])).to eq([34, 33, 33])

      expect(described_class.generate_with_constraints(5, [
        { weight: 1 }, { weight: 1 }, { weight: 1 }
      ])).to eq([2, 2, 1])
    end

    it "allocates negative totals by magnitude and negates" do
      result = described_class.generate_with_constraints(-100, [
        { weight: 1, max: 20 },
        { weight: 1 },
        { weight: 1 },
      ])

      expect(result).to eq([-20, -40, -40])
      expect(result.sum).to eq(-100)
    end

    it "returns zeros for a zero total with zero minimums" do
      expect(described_class.generate_with_constraints(0, [
        { weight: 1 }, { weight: 1 }
      ])).to eq([0, 0])
    end

    it "accepts fractional weights" do
      result = described_class.generate_with_constraints(100, [
        { weight: 0.25 }, { weight: 0.25 }, { weight: 0.5 }
      ])

      expect(result).to eq([25, 25, 50])
    end

    it "handles a huge amount with binding maximums" do
      total = 10**18
      parts = [
        { weight: 1, max: 10**10 },
        { weight: 2 },
        { weight: 3 },
        { weight: 0, min: 100 },
      ]

      result = described_class.generate_with_constraints(total, parts)

      expect(result.sum).to eq(total)
      expect(result[0]).to eq(10**10)
      expect(result[3]).to eq(100)
      result.each_with_index do |value, index|
        part = parts[index]
        expect(value).to be >= part.fetch(:min, 0)
        expect(value).to be <= part[:max] if part[:max]
      end

      distributable = total - 10**10 - 100
      expect(result[1]).to eq((distributable * 2r / 5).round)
      expect(result[2]).to eq((distributable * 3r / 5).round)
      expect(result[1] + result[2]).to eq(distributable)
    end

    it "handles a huge negative amount and negates the allocation" do
      total = -(10**24 + 7)
      parts = [
        { weight: 1, max: 10**20 },
        { weight: 2 },
        { weight: 0, min: 7 },
      ]

      result = described_class.generate_with_constraints(total, parts)

      expect(result.sum).to eq(total)
      expect(result.map(&:class)).to all(eq(Integer))
      expect(result[0]).to eq(-(10**20))
      expect(result[2]).to eq(-7)
      result.each { |value| expect(value).to be <= 0 }
    end

    it "raises clear errors for invalid and infeasible input" do
      expect { described_class.generate_with_constraints(100, []) }
        .to raise_error(ArgumentError, /at least one part/)
      expect { described_class.generate_with_constraints(100, nil) }
        .to raise_error(ArgumentError, /at least one part/)
      expect { described_class.generate_with_constraints(100, [{ weight: -1 }]) }
        .to raise_error(ArgumentError, /non-negative/)
      expect { described_class.generate_with_constraints(100, [{ min: 10, max: 5 }]) }
        .to raise_error(ArgumentError, /cannot exceed/)
      expect { described_class.generate_with_constraints(100, [{ min: 60 }, { min: 60 }]) }
        .to raise_error(ArgumentError, /minimum amounts \(120\) exceed total/)
      expect { described_class.generate_with_constraints(100, [{ max: 40 }, { max: 40 }]) }
        .to raise_error(ArgumentError, /maximum amounts \(80\) are below total/)
      expect { described_class.generate_with_constraints(100, [{ min: 1.5 }]) }
        .to raise_error(ArgumentError, /whole number/)
    end
  end

  describe "Money#allocate_with_constraints" do
    it "returns Money objects that sum to the original" do
      result = Money.us_dollar(1_00).allocate_with_constraints([
        { weight: 1, max: 20 },
        { weight: 1 },
      ])

      expect(result.map(&:fractional)).to eq([20, 80])
      expect(result.sum).to eq(Money.us_dollar(1_00))
      expect(result.map { |money| money.currency.id }).to all(eq(:usd))
    end

    it "preserves the money subclass" do
      special_money_class = Class.new(Money)
      result = special_money_class.new(100).allocate_with_constraints([{ weight: 1 }])
      expect(result.first).to be_a special_money_class
    end

    it "works with negative money" do
      result = Money.us_dollar(-1_00).allocate_with_constraints([
        { weight: 1, max: 20 },
        { weight: 1 },
      ])

      expect(result.map(&:fractional)).to eq([-20, -80])
      expect(result.sum).to eq(Money.us_dollar(-1_00))
    end

    it "rounds non-integral infinite-precision amounts before allocating" do
      Money.default_infinite_precision = true
      begin
        money = Money.new(BigDecimal("10.6"), "USD")
        result = money.allocate_with_constraints([{ weight: 1 }, { weight: 1 }])
        expect(result.map { |part| part.fractional.to_i }).to eq([6, 5])
        expect(result.sum).to eq(Money.new(BigDecimal("11"), "USD"))
      ensure
        Money.default_infinite_precision = false
      end
    end
  end
end
