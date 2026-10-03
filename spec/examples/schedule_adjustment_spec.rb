require File.dirname(__FILE__) + "/../spec_helper"

describe IceCube::ScheduleAdjustment do
  # 2026-01-05 is a Monday
  let(:start_time) { Time.utc(2026, 1, 5, 9, 0, 0) }
  let(:anchor) { Time.utc(2026, 1, 7, 9, 0, 0) } # third daily occurrence

  def daily_schedule(rule)
    IceCube::Schedule.new(start_time, duration: ONE_HOUR).tap do |schedule|
      schedule.add_recurrence_rule rule
    end
  end

  def starts(occurrences)
    occurrences.map(&:start_time)
  end

  describe "finite recurrence (COUNT)" do
    let(:schedule) { daily_schedule(IceCube::Rule.daily.count(5)) }

    it "shifts occurrences from the anchor onward and changes their duration" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR, duration: 90 * ONE_MINUTE)

      expect(starts(schedule.all_occurrences)).to eq [
        Time.utc(2026, 1, 5, 9),
        Time.utc(2026, 1, 6, 9),
        Time.utc(2026, 1, 7, 11),
        Time.utc(2026, 1, 8, 11),
        Time.utc(2026, 1, 9, 11)
      ]
    end

    it "keeps occurrences before the anchor untouched" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR, duration: 90 * ONE_MINUTE)

      first_two = schedule.all_occurrences.first(2)
      expect(first_two.map { |o| o.end_time }).to eq [
        Time.utc(2026, 1, 5, 10),
        Time.utc(2026, 1, 6, 10)
      ]
    end

    it "applies the unified duration only from the anchor onward" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR, duration: 90 * ONE_MINUTE)

      adjusted = schedule.all_occurrences.last(3)
      expect(adjusted.map { |o| o.end_time }).to eq [
        Time.utc(2026, 1, 7, 12, 30),
        Time.utc(2026, 1, 8, 12, 30),
        Time.utc(2026, 1, 9, 12, 30)
      ]
    end

    it "still interprets COUNT on the original recurrence axis" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR)
      expect(schedule.all_occurrences.size).to eq 5
    end

    it "supports offset-only adjustments, keeping the schedule duration" do
      schedule.adjust_following(anchor, start_offset: -ONE_HOUR)

      occurrence = schedule.all_occurrences[2]
      expect(occurrence.start_time).to eq Time.utc(2026, 1, 7, 8)
      expect(occurrence.end_time).to eq Time.utc(2026, 1, 7, 9)
    end
  end

  describe "infinite recurrence" do
    let(:schedule) { daily_schedule(IceCube::Rule.daily) }

    it "shifts occurrences around the cut point without enumerating the series" do
      schedule.adjust_following(anchor, start_offset: 3 * ONE_HOUR, duration: 30 * ONE_MINUTE)

      expect(starts(schedule.first(4))).to eq [
        Time.utc(2026, 1, 5, 9),
        Time.utc(2026, 1, 6, 9),
        Time.utc(2026, 1, 7, 12),
        Time.utc(2026, 1, 8, 12)
      ]
    end

    it "finds shifted occurrences in a window around the cut point" do
      schedule.adjust_following(anchor, start_offset: 3 * ONE_HOUR)

      windowed = schedule.occurrences_between(Time.utc(2026, 1, 6, 12), Time.utc(2026, 1, 8, 12))
      expect(starts(windowed)).to eq [
        Time.utc(2026, 1, 7, 12),
        Time.utc(2026, 1, 8, 12)
      ]
    end

    it "finds occurrences pulled into a window by a negative offset" do
      schedule.adjust_following(anchor, start_offset: -6 * ONE_HOUR)

      windowed = schedule.occurrences_between(Time.utc(2026, 1, 7, 0), Time.utc(2026, 1, 7, 6))
      expect(starts(windowed)).to eq [Time.utc(2026, 1, 7, 3)]
    end

    it "answers next_occurrence across the cut point" do
      schedule.adjust_following(anchor, start_offset: 3 * ONE_HOUR)

      expect(schedule.next_occurrence(Time.utc(2026, 1, 6, 10))).to eq Time.utc(2026, 1, 7, 12)
    end

    it "answers occurs_at? against shifted times" do
      schedule.adjust_following(anchor, start_offset: 3 * ONE_HOUR)

      expect(schedule.occurs_at?(Time.utc(2026, 1, 7, 12))).to be_truthy
      expect(schedule.occurs_at?(Time.utc(2026, 1, 7, 9))).to be_falsey
      expect(schedule.occurs_at?(Time.utc(2026, 1, 6, 9))).to be_truthy
    end
  end

  describe "UNTIL on the original axis" do
    let(:schedule) { daily_schedule(IceCube::Rule.daily.until(Time.utc(2026, 1, 8, 9))) }

    it "bounds the original recurrence times, not the shifted ones" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR)

      expect(starts(schedule.all_occurrences)).to eq [
        Time.utc(2026, 1, 5, 9),
        Time.utc(2026, 1, 6, 9),
        Time.utc(2026, 1, 7, 11),
        Time.utc(2026, 1, 8, 11)
      ]
    end
  end

  describe "exceptions and rescheduled instances" do
    let(:schedule) { daily_schedule(IceCube::Rule.daily.count(5)) }

    it "keeps a cancelled instance cancelled after the shift" do
      schedule.add_exception_time(Time.utc(2026, 1, 8, 9))
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR)

      expect(starts(schedule.all_occurrences)).to eq [
        Time.utc(2026, 1, 5, 9),
        Time.utc(2026, 1, 6, 9),
        Time.utc(2026, 1, 7, 11),
        Time.utc(2026, 1, 9, 11)
      ]
    end

    it "does not shift an individually rescheduled instance" do
      schedule.add_exception_time(Time.utc(2026, 1, 8, 9))
      schedule.add_recurrence_time(Time.utc(2026, 1, 8, 15))
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR)

      expect(starts(schedule.all_occurrences)).to eq [
        Time.utc(2026, 1, 5, 9),
        Time.utc(2026, 1, 6, 9),
        Time.utc(2026, 1, 7, 11),
        Time.utc(2026, 1, 8, 15),
        Time.utc(2026, 1, 9, 11)
      ]
    end
  end

  describe "multiple adjustments as segments" do
    let(:schedule) { daily_schedule(IceCube::Rule.daily.count(5)) }

    it "applies each segment in anchor order" do
      schedule.adjust_following(Time.utc(2026, 1, 9, 9), start_offset: -ONE_HOUR)
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR, duration: 90 * ONE_MINUTE)

      occurrences = schedule.all_occurrences
      expect(starts(occurrences)).to eq [
        Time.utc(2026, 1, 5, 9),
        Time.utc(2026, 1, 6, 9),
        Time.utc(2026, 1, 7, 11),
        Time.utc(2026, 1, 8, 11),
        Time.utc(2026, 1, 9, 8)
      ]
      # the last segment has no unified duration, so the schedule's applies
      expect(occurrences.last.end_time).to eq Time.utc(2026, 1, 9, 9)
      expect(occurrences[2].end_time).to eq Time.utc(2026, 1, 7, 12, 30)
    end

    it "replaces an adjustment anchored at the same time" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR)
      schedule.adjust_following(anchor, start_offset: 5 * ONE_HOUR)

      expect(schedule.adjustments.size).to eq 1
      expect(schedule.all_occurrences[2].start_time).to eq Time.utc(2026, 1, 7, 14)
    end

    it "removes an adjustment by anchor" do
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR)
      schedule.remove_adjustment(anchor)

      expect(schedule.adjustments).to be_empty
      expect(schedule.all_occurrences[2].start_time).to eq anchor
    end
  end

  describe "serialization" do
    let(:schedule) { daily_schedule(IceCube::Rule.daily.count(5)) }

    before do
      schedule.add_exception_time(Time.utc(2026, 1, 8, 9))
      schedule.adjust_following(anchor, start_offset: 2 * ONE_HOUR, duration: 90 * ONE_MINUTE)
      schedule.adjust_following(Time.utc(2026, 1, 9, 9), start_offset: ONE_HOUR)
    end

    it "round-trips through a hash" do
      restored = IceCube::Schedule.from_hash(schedule.to_hash)

      expect(restored.adjustments).to eq schedule.adjustments
      expect(starts(restored.all_occurrences)).to eq starts(schedule.all_occurrences)
      expect(restored.all_occurrences.map(&:end_time)).to eq schedule.all_occurrences.map(&:end_time)
    end

    it "round-trips through YAML" do
      restored = IceCube::Schedule.from_yaml(schedule.to_yaml)

      expect(restored.adjustments).to eq schedule.adjustments
      expect(starts(restored.all_occurrences)).to eq starts(schedule.all_occurrences)
    end

    it "round-trips an adjustment through its own hash form" do
      adjustment = IceCube::ScheduleAdjustment.new(anchor, start_offset: 2 * ONE_HOUR, duration: 90 * ONE_MINUTE)
      restored = IceCube::ScheduleAdjustment.from_hash(adjustment.to_hash)

      expect(restored.anchor).to eq adjustment.anchor
      expect(restored.start_offset).to eq adjustment.start_offset
      expect(restored.duration).to eq adjustment.duration
    end

    it "affects schedule equality" do
      other = IceCube::Schedule.from_hash(schedule.to_hash)
      expect(other).to eq schedule

      other.remove_adjustment(anchor)
      expect(other).not_to eq schedule
    end
  end

  describe "validation" do
    it "requires an anchor time" do
      expect { IceCube::ScheduleAdjustment.new(nil) }.to raise_error ArgumentError
    end
  end
end

