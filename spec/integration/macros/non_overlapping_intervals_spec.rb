# frozen_string_literal: true

require "date"

RSpec.describe "non_overlapping_intervals macro" do
  def booking(resource_id, starts_on, ends_on)
    {resource_id: resource_id, starts_on: starts_on, ends_on: ends_on}
  end

  def contract_with(**options)
    Class.new(Dry::Validation::Contract) do
      params do
        required(:bookings).array(:hash) do
          optional(:resource_id).filled(:integer)
          optional(:starts_on).filled(:date)
          optional(:ends_on).filled(:date)
        end
      end

      rule(:bookings).validate(
        non_overlapping_intervals: {
          group_key: :resource_id, start_key: :starts_on, end_key: :ends_on, **options
        }
      )
    end.new
  end

  let(:default_contract) { contract_with }
  let(:half_open_contract) { contract_with(endpoints: "[)") }
  let(:open_contract) { contract_with(endpoints: "()") }

  context "with the default closed endpoints" do
    it "accepts disjoint intervals" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-04", "2026-01-05")
      ])

      expect(result).to be_success
    end

    it "treats touching endpoints as overlapping and marks both records" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with another record"],
          1 => ["overlaps with another record"]
        }
      )
    end

    it "reports every overlapping pair but not disjoint records" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-10"),
        booking(1, "2026-01-02", "2026-01-03"),
        booking(1, "2026-01-04", "2026-01-05")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with another record", "overlaps with another record"],
          1 => ["overlaps with another record"],
          2 => ["overlaps with another record"]
        }
      )
    end

    it "marks all records in a true overlapping chain" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-02", "2026-01-05"),
        booking(1, "2026-01-04", "2026-01-06")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with another record"],
          1 => ["overlaps with another record", "overlaps with another record"],
          2 => ["overlaps with another record"]
        }
      )
    end

    it "detects a containing interval regardless of input order" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-04", "2026-01-05"),
        booking(1, "2026-01-01", "2026-01-10")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with another record"],
          1 => ["overlaps with another record"]
        }
      )
    end

    it "detects duplicate intervals" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-05"),
        booking(1, "2026-01-01", "2026-01-05")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with another record"],
          1 => ["overlaps with another record"]
        }
      )
    end

    it "does not compare records from different resource groups" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-10"),
        booking(2, "2026-01-01", "2026-01-10"),
        booking(2, "2026-01-02", "2026-01-03")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          1 => ["overlaps with another record"],
          2 => ["overlaps with another record"]
        }
      )
    end
  end

  context "with half-open endpoints" do
    it "accepts back-to-back intervals" do
      result = half_open_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_success
    end

    it "still detects interior overlaps" do
      result = half_open_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-04"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_failure
    end

    it "skips zero-width intervals" do
      result = half_open_contract.(bookings: [
        booking(1, "2026-01-03", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-03")
      ])

      expect(result).to be_success
    end
  end

  context "with fully open endpoints" do
    it "accepts intervals sharing either endpoint" do
      result = open_contract.(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_success
    end
  end

  context "with left-open right-closed endpoints" do
    it "does not treat a back-to-back touch as overlapping" do
      result = contract_with(endpoints: "(]").(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_success
    end

    it "still detects a real interior overlap" do
      result = contract_with(endpoints: "(]").(bookings: [
        booking(1, "2026-01-01", "2026-01-04"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_failure
    end
  end

  context "endpoint presets and overrides" do
    it "accepts the closed_open alias" do
      result = contract_with(endpoints: :closed_open).(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_success
    end

    it "accepts explicit left_open/right_open overrides" do
      result = contract_with(left_open: true, right_open: false).(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-05")
      ])

      expect(result).to be_success
    end

    it "rejects an unknown endpoints preset" do
      expect { contract_with(endpoints: :bogus).(bookings: []) }.to raise_error(
        ArgumentError, /endpoints.*must be one of/
      )
    end
  end

  context "empty and inverted intervals" do
    it "skips inverted intervals" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-05", "2026-01-01"),
        booking(1, "2026-01-02", "2026-01-06")
      ])

      expect(result).to be_success
    end

    it "treats a zero-width closed interval as a point that can overlap" do
      result = default_contract.(bookings: [
        booking(1, "2026-01-03", "2026-01-03"),
        booking(1, "2026-01-03", "2026-01-03")
      ])

      expect(result).to be_failure
    end
  end

  context "records that failed field schema checks" do
    it "ignores records with an invalid start value" do
      result = half_open_contract.(bookings: [
        {resource_id: 1, starts_on: "not-a-date", ends_on: "2026-01-10"},
        booking(1, "2026-01-01", "2026-01-10")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {0 => {starts_on: ["must be a date"]}}
      )
    end

    it "ignores records with an invalid group value" do
      result = half_open_contract.(bookings: [
        {resource_id: "oops", starts_on: "2026-01-01", ends_on: "2026-01-10"},
        booking(1, "2026-01-01", "2026-01-10")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {0 => {resource_id: ["must be an integer"]}}
      )
    end

    it "ignores records with missing endpoint fields" do
      required_contract = Class.new(Dry::Validation::Contract) do
        params do
          required(:bookings).array(:hash) do
            required(:resource_id).filled(:integer)
            required(:starts_on).filled(:date)
            required(:ends_on).filled(:date)
          end
        end

        rule(:bookings).validate(
          non_overlapping_intervals: {
            group_key: :resource_id, start_key: :starts_on, end_key: :ends_on,
            endpoints: "[)"
          }
        )
      end.new

      result = required_contract.(bookings: [
        {resource_id: 1, starts_on: "2026-01-01"},
        booking(1, "2026-01-01", "2026-01-10")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {0 => {ends_on: ["is missing"]}}
      )
    end
  end

  context "custom messages" do
    it "uses the provided message" do
      result = contract_with(message: "is already booked for that time").(bookings: [
        booking(1, "2026-01-01", "2026-01-03"),
        booking(1, "2026-01-02", "2026-01-05")
      ])

      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["is already booked for that time"],
          1 => ["is already booked for that time"]
        }
      )
    end
  end

  context "schema-coerced input" do
    it "compares coerced dates while reporting original indices" do
      result = half_open_contract.(bookings: [
        {"resource_id" => 1, "starts_on" => "2026-01-04", "ends_on" => "2026-01-05"},
        {"resource_id" => 1, "starts_on" => "2026-01-01", "ends_on" => "2026-01-10"}
      ])

      expect(result).to be_failure
      expect(result.to_h[:bookings].first[:starts_on]).to eql(Date.new(2026, 1, 4))
      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with another record"],
          1 => ["overlaps with another record"]
        }
      )
    end
  end

  context "with a nested array path" do
    let(:nested_contract) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:form).hash do
            required(:bookings).array(:hash) do
              required(:resource_id).filled(:integer)
              required(:starts_on).filled(:date)
              required(:ends_on).filled(:date)
            end
          end
        end

        rule("form.bookings").validate(
          non_overlapping_intervals: {
            group_key: :resource_id, start_key: :starts_on, end_key: :ends_on,
            endpoints: "[)"
          }
        )
      end.new
    end

    it "locates errors under the nested path" do
      result = nested_contract.(form: {bookings: [
        booking(1, "2026-01-01", "2026-01-05"),
        booking(1, "2026-01-03", "2026-01-08")
      ]})

      expect(result.errors.to_h).to eql(
        form: {bookings: {
          0 => ["overlaps with another record"],
          1 => ["overlaps with another record"]
        }}
      )
    end

    it "skips relation checks when the array itself failed schema checks" do
      result = nested_contract.(form: {bookings: "oops"})

      expect(result.errors.to_h).to eql(form: {bookings: ["must be an array"]})
    end
  end

  describe "comparison complexity" do
    # A value that counts every ordering comparison performed against it.
    let(:counter_class) do
      Class.new do
        include Comparable
        attr_reader :value

        def initialize(value, counter)
          @value = value
          @counter = counter
        end

        def <=>(other)
          @counter << 1
          value <=> other.value
        end
      end
    end

    def comparisons(size, groups: 1)
      counter = []
      records = []

      groups.times do |group|
        size.times do |i|
          records << {
            resource_id: group,
            starts_on: counter_class.new(2 * i, counter),
            ends_on: counter_class.new(2 * i + 1, counter)
          }
        end
      end

      detector = Dry::Validation::Macros::NonOverlappingIntervals.new(
        group_key: :resource_id, start_key: :starts_on, end_key: :ends_on
      )
      detector.call(records, ->(_path) { false })
      counter.size
    end

    def dense_comparisons(size)
      finish_comparisons = []
      start_class = Class.new do
        include Comparable
        attr_reader :kind, :value
        def initialize(value, kind = :start)
          @value = value
          @kind = kind
        end
        def <=>(other)
          value <=> other.value
        end
      end
      finish_class = Class.new(start_class) do
        def initialize(value, counter)
          super(value, :finish)
          @counter = counter
        end
        def <=>(other)
          @counter << 1 if other.kind == :finish
          super
        end
      end

      # Every interval contains the next start, so all records overlap (the
      # n^2 conflict pairs are unavoidable output). Starts are distinct, so
      # the start comparator never takes the tie-break branch; the wide finish
      # endpoints count every ordering comparison performed on them.
      records = Array.new(size) do |i|
        {
          resource_id: 0,
          starts_on: start_class.new(i),
          ends_on: finish_class.new(size + 1, finish_comparisons)
        }
      end

      detector = Dry::Validation::Macros::NonOverlappingIntervals.new(
        group_key: :resource_id, start_key: :starts_on, end_key: :ends_on
      )
      conflicts = detector.call(records, ->(_path) { false })
      [finish_comparisons.size, conflicts.size]
    end

    it "stays well below the pairwise number of comparisons" do
      small = comparisons(128)
      large = comparisons(256)

      expect(small).to be < 10 * 128
      expect(large).to be < 10 * 256
      expect(small).to be < 128 * 127 / 2
      expect(large).to be < 256 * 255 / 2
      # Near-linear growth for an n log n sort, nowhere near the ~4x a
      # pairwise algorithm would show.
      expect(large.to_f / small).to be < 2.5
    end

    it "sweeps resource groups independently" do
      expect(comparisons(128, groups: 4)).to be < 4 * 10 * 128
    end

    it "keeps sweep bookkeeping logarithmic even when all intervals overlap" do
      small_comparisons, small_conflicts = dense_comparisons(128)
      large_comparisons, large_conflicts = dense_comparisons(256)

      # The conflict pairs themselves are unavoidable output: every record
      # conflicts with every other record.
      expect(small_conflicts).to be(128 * 127 / 2)
      expect(large_conflicts).to be(256 * 255 / 2)

      # But finding them must not compare finishes pairwise: finishes are
      # equal here and only probed by the logarithmic active-set insertion,
      # so the count stays near O(n log n), nowhere near O(n^2).
      expect(small_comparisons).to be < 128 * 10
      expect(large_comparisons).to be < 256 * 10
      expect(large_comparisons).to be < 256 * 255 / 2
    end
  end
end
