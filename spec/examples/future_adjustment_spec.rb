require File.dirname(__FILE__) + "/../spec_helper"

describe IceCube::FutureAdjustment do
  it "exposes the anchor, offset and duration" do
    anchor = Time.utc(2020, 1, 1)
    adjustment = described_class.new(anchor, start_offset: 60, duration: 30)
    expect(adjustment.anchor).to eq anchor
    expect(adjustment.start_offset).to eq 60
    expect(adjustment.duration).to eq 30
  end

  it "defaults to no offset and inherited duration" do
    adjustment = described_class.new(Time.utc(2020, 1, 1))
    expect(adjustment.start_offset).to be_nil
    expect(adjustment.duration).to be_nil
  end

  it "round-trips through a hash" do
    adjustment = described_class.new(Time.utc(2020, 1, 1, 9),
                                     start_offset: -300, duration: 60)
    restored = described_class.from_hash(adjustment.to_hash)
    expect(restored).to eq adjustment
  end
end

describe IceCube::Schedule, "future adjustments" do
  let(:start) { Time.utc(2020, 1, 1, 9, 0, 0) }

  def daily_schedule(rule_builder = nil, duration: 3600)
    IceCube::Schedule.new(start, duration: duration) do |schedule|
      schedule.rrule(rule_builder ? rule_builder.call : IceCube::Rule.daily)
    end
  end

  describe "#add_future_adjustment" do
    it "returns the stored adjustment and keeps the list ordered" do
      schedule = daily_schedule
      later = schedule.add_future_adjustment(start + 3 * IceCube::ONE_DAY,
                                             start_offset: 3600)
      earlier = schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                               duration: 1800)
      expect(later).to be_a(IceCube::FutureAdjustment)
      expect(schedule.future_adjustments.map(&:anchor)).to eq [
        start + IceCube::ONE_DAY, start + 3 * IceCube::ONE_DAY
      ]
      expect(earlier.start_offset).to be_nil
      expect(earlier.duration).to eq 1800
    end

    it "rejects an anchor that is not an original-axis occurrence" do
      schedule = daily_schedule
      expect do
        schedule.add_future_adjustment(start + 12 * IceCube::ONE_HOUR)
      end.to raise_error(ArgumentError, /original recurrence axis/)
    end

    it "rejects a duplicate anchor" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + IceCube::ONE_DAY, start_offset: 3600)
      expect do
        schedule.add_future_adjustment(start + IceCube::ONE_DAY, duration: 1800)
      end.to raise_error(ArgumentError, /already exists/)
    end

    it "rejects a negative duration" do
      schedule = daily_schedule
      expect do
        schedule.add_future_adjustment(start, duration: -1)
      end.to raise_error(ArgumentError, /non-negative/)
    end

    it "can be removed by anchor" do
      schedule = daily_schedule
      anchor = start + IceCube::ONE_DAY
      adjustment = schedule.add_future_adjustment(anchor, start_offset: 3600)
      expect(schedule.remove_future_adjustment(anchor)).to eq adjustment
      expect(schedule.remove_future_adjustment(anchor)).to be_nil
      expect(schedule.future_adjustments).to be_empty
    end
  end

  describe "boundary around the cut point" do
    it "shifts an infinite recurring series from the anchor (inclusive)" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     start_offset: 2 * IceCube::ONE_HOUR,
                                     duration: 5400)

      occurrences = schedule.occurrences_between(
        Time.utc(2020, 1, 1), Time.utc(2020, 1, 4, 23, 59)
      )

      expect(occurrences.map(&:start_time)).to eq [
        Time.utc(2020, 1, 1, 9), Time.utc(2020, 1, 2, 9),
        Time.utc(2020, 1, 3, 11), Time.utc(2020, 1, 4, 11)
      ]
      expect(occurrences.map(&:duration)).to eq [3600, 3600, 5400, 5400]
    end

    it "works with a finite COUNT series" do
      schedule = daily_schedule(-> { IceCube::Rule.daily.count(4) })
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     start_offset: -1 * IceCube::ONE_HOUR,
                                     duration: 1800)

      expect(schedule.all_occurrences.map(&:start_time)).to eq [
        Time.utc(2020, 1, 1, 9), Time.utc(2020, 1, 2, 9),
        Time.utc(2020, 1, 3, 8), Time.utc(2020, 1, 4, 8)
      ]
      expect(schedule.all_occurrences.size).to eq 4
    end

    it "respects UNTIL on the original axis after a forward shift" do
      until_time = Time.utc(2020, 1, 3, 12)
      schedule = daily_schedule(-> { IceCube::Rule.daily.until(until_time) })
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     start_offset: 4 * IceCube::ONE_HOUR)

      occurrences = schedule.occurrences_between(
        Time.utc(2020, 1, 1), Time.utc(2020, 1, 10)
      )
      expect(occurrences.map(&:start_time)).to eq [
        Time.utc(2020, 1, 1, 9),
        Time.utc(2020, 1, 2, 13),
        Time.utc(2020, 1, 3, 13)
      ]
    end

    it "finds the exact first shifted occurrence at the cut point" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     start_offset: 2 * IceCube::ONE_HOUR)

      expect(schedule.occurs_at?(Time.utc(2020, 1, 2, 9))).to eq true
      expect(schedule.occurs_at?(Time.utc(2020, 1, 3, 9))).to eq false
      expect(schedule.occurs_at?(Time.utc(2020, 1, 3, 11))).to eq true
      expect(schedule.previous_occurrence(Time.utc(2020, 1, 3, 12))).to eq(
        Time.utc(2020, 1, 3, 11)
      )
    end
  end

  describe "multiple ordered segments" do
    it "replaces offsets against the original axis and inherits nil duration" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     start_offset: IceCube::ONE_HOUR,
                                     duration: 7200)
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     start_offset: 2 * IceCube::ONE_HOUR)
      schedule.add_future_adjustment(start + 3 * IceCube::ONE_DAY,
                                     duration: 900)

      occurrences = schedule.occurrences_between(
        start, Time.utc(2020, 1, 4, 23, 59)
      )

      expect(occurrences.map { |o| [o.start_time, o.duration.to_i] }).to eq [
        [Time.utc(2020, 1, 1, 9), 3600],
        [Time.utc(2020, 1, 2, 10), 7200],
        [Time.utc(2020, 1, 3, 11), 7200],
        [Time.utc(2020, 1, 4, 11), 900]
      ]
    end

    it "inherits the previous offset when only a duration is given" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     start_offset: 2 * IceCube::ONE_HOUR,
                                     duration: 7200)
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     duration: 900)

      occurrences = schedule.occurrences_between(start, Time.utc(2020, 1, 3, 23, 59))
      expect(occurrences.map { |o| [o.start_time, o.duration.to_i] }).to eq [
        [Time.utc(2020, 1, 1, 9), 3600],
        [Time.utc(2020, 1, 2, 11), 7200],
        [Time.utc(2020, 1, 3, 11), 900]
      ]
    end

    it "inherits the previous duration when only an offset is given" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     duration: 7200)
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     start_offset: 3 * IceCube::ONE_HOUR)

      occurrences = schedule.occurrences_between(start, Time.utc(2020, 1, 3, 23, 59))
      expect(occurrences.map { |o| [o.start_time, o.duration.to_i] }).to eq [
        [Time.utc(2020, 1, 1, 9), 3600],
        [Time.utc(2020, 1, 2, 9), 7200],
        [Time.utc(2020, 1, 3, 12), 7200]
      ]
    end

    it "allows inserting an earlier segment after a later one" do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + 2 * IceCube::ONE_DAY,
                                     start_offset: 3 * IceCube::ONE_HOUR)
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     start_offset: IceCube::ONE_HOUR)

      occurrences = schedule.occurrences_between(start, Time.utc(2020, 1, 3, 23, 59))
      expect(occurrences.map(&:start_time)).to eq [
        Time.utc(2020, 1, 1, 9),
        Time.utc(2020, 1, 2, 10),
        Time.utc(2020, 1, 3, 12)
      ]
    end
  end

  describe "exceptions and individually rescheduled instances" do
    it "keeps an original-axis exception cancelled inside later segments" do
      schedule = daily_schedule
      cancelled = start + 2 * IceCube::ONE_DAY
      schedule.add_exception_time(cancelled)
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     start_offset: IceCube::ONE_HOUR)

      occurrences = schedule.occurrences_between(start, start + 4 * IceCube::ONE_DAY)
      expect(occurrences.map(&:start_time)).to eq [
        Time.utc(2020, 1, 1, 9),
        Time.utc(2020, 1, 2, 10),
        Time.utc(2020, 1, 4, 10)
      ]
      expect(schedule.occurs_at?(cancelled + IceCube::ONE_HOUR)).to eq false
    end

    it "emits a single rescheduled instance unchanged" do
      schedule = daily_schedule
      rescheduled = Time.utc(2020, 1, 1, 15)
      schedule.add_exception_time(start)
      schedule.add_recurrence_time(rescheduled)
      schedule.add_future_adjustment(start,
                                     start_offset: 2 * IceCube::ONE_HOUR)

      occurrences = schedule.occurrences_between(
        Time.utc(2020, 1, 1), Time.utc(2020, 1, 2)
      )
      expect(occurrences.map(&:start_time)).to include rescheduled
      expect(occurrences.map(&:start_time)).not_to include(
        start + 2 * IceCube::ONE_HOUR
      )
    end
  end

  describe "serialization" do
    let(:schedule) do
      schedule = daily_schedule
      schedule.add_future_adjustment(start + IceCube::ONE_DAY,
                                     start_offset: IceCube::ONE_HOUR,
                                     duration: 7200)
      schedule.add_future_adjustment(start + 3 * IceCube::ONE_DAY,
                                     start_offset: -900)
      schedule
    end

    it "round-trips through a hash" do
      restored = IceCube::Schedule.from_hash(schedule.to_hash)
      expect(restored).to eq schedule
      expect(restored.future_adjustments).to eq schedule.future_adjustments
      window = [start, start + 4 * IceCube::ONE_DAY]
      expect(restored.occurrences_between(*window).map(&:start_time)).to eq(
        schedule.occurrences_between(*window).map(&:start_time)
      )
    end

    it "round-trips through YAML" do
      restored = IceCube::Schedule.from_yaml(schedule.to_yaml)
      expect(restored).to eq schedule
      expect(restored.future_adjustments.size).to eq 2
    end

    it "serializes adjustments in to_hash" do
      data = schedule.to_hash
      expect(data[:future_adjustments].size).to eq 2
      expect(data[:future_adjustments].first[:start_offset]).to eq 3600
    end
  end

  describe "daylight saving time", system_time_zone: "America/New_York" do
    it "keeps wall-clock offsets across the spring-forward transition" do
      local_start = Time.local(2020, 3, 6, 9)
      schedule = IceCube::Schedule.new(local_start) do |sch|
        sch.rrule IceCube::Rule.daily
      end
      schedule.add_future_adjustment(Time.local(2020, 3, 8, 9),
                                     start_offset: 2 * IceCube::ONE_HOUR)

      times = schedule.occurrences_between(
        Time.local(2020, 3, 6), Time.local(2020, 3, 10)
      ).map(&:to_time)
      expect(times).to eq [
        Time.local(2020, 3, 6, 9), Time.local(2020, 3, 7, 9),
        Time.local(2020, 3, 8, 11), Time.local(2020, 3, 9, 11)
      ]
    end
  end
end
