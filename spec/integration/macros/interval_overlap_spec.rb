# frozen_string_literal: true

RSpec.describe Dry::Validation::Macros, ":non_overlapping" do
  subject(:contract) { contract_class.new }

  let(:contract_class) do
    interval_contract(:right_open)
  end

  def booking(resource_id, starts_at, ends_at)
    {resource_id: resource_id, starts_at: starts_at, ends_at: ends_at}
  end

  def interval_contract(endpoints, message: :default, typed: true, macro_name: :non_overlapping)
    endpoint_type = typed ? :date_time : :any
    endpoint_rule = case endpoints
    when :right_open
      nil
    when Symbol
      endpoints
    when Hash
      nil
    end

    Class.new(Dry::Validation::Contract) do
      params do
        required(:bookings).value(:array).each do
          schema do
            required(:resource_id).filled(:string)
            required(:starts_at).filled(endpoint_type)
            required(:ends_at).filled(endpoint_type)
          end
        end
      end

      options = {
        group_by: :resource_id,
        start_field: :starts_at,
        end_field: :ends_at
      }

      options[:endpoints] = endpoint_rule if endpoint_rule
      options.merge!(endpoints) if endpoints.is_a?(Hash)
      options[:message] = message unless message == :default

      rule(:bookings).validate(macro_name => options)
    end
  end

  it "reports both records when one interval contains another" do
    result = contract.(
      bookings: [
        booking("room-1", "2026-01-01T00:00:00Z", "2026-01-10T00:00:00Z"),
        booking("room-1", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z")
      ]
    )

    expect(result).to be_failure
    expect(result.errors.to_h).to eql(
      bookings: {
        0 => ["overlaps with interval 1"],
        1 => ["overlaps with interval 0"]
      }
    )
    expect(result.errors.map(&:path)).to eql([[:bookings, 0], [:bookings, 1]])
  end

  it "reports duplicate intervals after schema transformations" do
    result = contract.(
      bookings: [
        booking("room-1", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"),
        booking("room-1", "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00")
      ]
    )

    expect(result).to be_failure
    expect(result.to_h[:bookings][0][:starts_at]).to be_a(DateTime)
    expect(result.errors.to_h).to eql(
      bookings: {
        0 => ["overlaps with interval 1"],
        1 => ["overlaps with interval 0"]
      }
    )
  end

  it "allows adjacent intervals with right-open endpoints" do
    result = contract.(
      bookings: [
        booking("room-1", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"),
        booking("room-1", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z")
      ]
    )

    expect(result).to be_success
  end

  it "allows identical intervals in different resources" do
    result = contract.(
      bookings: [
        booking("room-1", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"),
        booking("room-2", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
      ]
    )

    expect(result).to be_success
  end

  it "skips records whose group or interval fields failed schema checks" do
    result = contract.(
      bookings: [
        booking("room-1", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"),
        booking("room-1", "not-a-date", "2026-01-03T00:00:00Z")
      ]
    )

    expect(result).to be_failure
    expect(result.errors.to_h).to eql(
      bookings: {1 => {starts_at: ["must be a date time"]}}
    )
  end

  it "skips relation checks when the group field has a schema error" do
    result = contract.(
      bookings: [
        booking("room-1", "2026-01-01T00:00:00Z", "2026-01-04T00:00:00Z"),
        booking("", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z")
      ]
    )

    expect(result).to be_failure
    expect(result.errors.to_h).to eql(
      bookings: {1 => {resource_id: ["must be filled"]}}
    )
  end

  context "with closed endpoints" do
    let(:contract_class) { interval_contract(:closed) }

    it "reports intervals that meet at an endpoint" do
      result = contract.(
        bookings: [
          booking("room-1", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"),
          booking("room-1", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z")
        ]
      )

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["overlaps with interval 1"],
          1 => ["overlaps with interval 0"]
        }
      )
    end

    it "treats equal endpoints as a non-empty interval" do
      result = contract.(
        bookings: [
          booking("room-1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
          booking("room-1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
        ]
      )

      expect(result).to be_failure
      expect(result.errors.to_h.dig(:bookings, 1)).to eql(["overlaps with interval 0"])
    end
  end

  context "with explicitly open endpoints" do
    let(:contract_class) do
      interval_contract(
        {start_open: true, end_open: true},
        message: "conflicts with another booking",
        typed: false
      )
    end

    it "treats zero-width and reversed intervals as empty" do
      result = contract.(
        bookings: [
          booking("room-1", 1, 1),
          booking("room-1", 1, 1),
          booking("room-1", 3, 2)
        ]
      )

      expect(result).to be_success
    end

    it "allows intervals that meet at both open endpoints" do
      result = contract.(
        bookings: [
          booking("room-1", 1, 2),
          booking("room-1", 2, 3)
        ]
      )

      expect(result).to be_success
    end

    it "reports overlapping interval interiors and the conflicting path" do
      result = contract.(
        bookings: [
          booking("room-1", 1, 3),
          booking("room-1", 1, 3)
        ]
      )

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(
        bookings: {
          0 => ["conflicts with another booking"],
          1 => ["conflicts with another booking"]
        }
      )
      messages = result.errors.to_a
      expect(messages.first.path).to eql([:bookings, 0])
      expect(messages.last.path).to eql([:bookings, 1])
    end
  end

  context "with mixed endpoint modes" do
    it "allows touching intervals with left-open endpoints" do
      contract = interval_contract(:left_open, typed: false).new

      result = contract.(
        bookings: [
          booking("room-1", 1, 2),
          booking("room-1", 2, 3)
        ]
      )

      expect(result).to be_success
    end

    it "allows touching intervals with right-open endpoints" do
      contract = interval_contract(:right_open, typed: false).new

      result = contract.(
        bookings: [
          booking("room-1", 1, 2),
          booking("room-1", 2, 3)
        ]
      )

      expect(result).to be_success
    end

    [:left_open, :right_open].each do |mode|
      it "treats a zero-width #{mode} interval as empty" do
        contract = interval_contract(mode, typed: false).new

        result = contract.(
          bookings: [
            booking("room-1", 2, 2),
            booking("room-1", 2, 2)
          ]
        )

        expect(result).to be_success
      end
    end
  end

  context "using the :interval_overlap alias" do
    let(:contract_class) do
      interval_contract(:right_open, macro_name: :interval_overlap)
    end

    it "checks intervals with the same macro behavior" do
      result = contract.(
        bookings: [
          booking("room-1", "2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z"),
          booking("room-1", "2026-01-02T00:00:00Z", "2026-01-04T00:00:00Z")
        ]
      )

      expect(result).to be_failure
      expect(result.errors.map(&:path)).to eql([[:bookings, 0], [:bookings, 1]])
    end
  end

  describe "comparison complexity" do
    let(:comparable) do
      Class.new do
        include Comparable

        class << self
          attr_accessor :comparisons
        end

        attr_reader :value

        def initialize(value)
          @value = value
        end

        def <=>(other)
          self.class.comparisons += 1
          value <=> other.value
        end
      end
    end

    let(:contract_class) do
      interval_contract(:right_open, typed: false).tap { comparable.comparisons = 0 }
    end

    it "uses fewer comparisons than an all-pairs scan" do
      size = 128

      records = size.times.map do |index|
        resource = index.even? ? "room-1" : "room-2"
        position = ((index / 2) + (index.even? ? 17 : 29)) % (size / 2)

        booking(
          resource,
          comparable.new(position * 2),
          comparable.new(position * 2 + 1)
        )
      end

      result = contract.(bookings: records)

      expect(result).to be_success
      expect(comparable.comparisons).to be < (size * Math.log2(size) * 6)
      expect(comparable.comparisons).to be < (size * (size - 1) / 2)
    end
  end
end
