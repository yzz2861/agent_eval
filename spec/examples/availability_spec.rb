require "spec_helper"

describe IceCube::Availability do
  def t(day, hour, min = 0)
    Time.utc(2010, 3, day, hour, min)
  end

  def hours_schedule(start_time, duration, &block)
    schedule = IceCube::Schedule.new(start_time, duration: duration)
    block&.call(schedule)
    schedule
  end

  let(:business_hours) do
    hours_schedule(t(1, 9), 8 * IceCube::ONE_HOUR) do |s|
      s.add_recurrence_rule IceCube::Rule.daily
    end
  end

  def free_intervals(available:, busy: [], duration: 45 * IceCube::ONE_MINUTE, window: [t(2, 0), t(3, 0)], **options)
    IceCube::Availability.new(available: available, busy: busy, duration: duration, **options)
      .free_intervals(*window)
  end

  describe "subtracting busy intervals from business hours" do
    it "returns the gaps around a busy occurrence with exact endpoints" do
      lunch = hours_schedule(t(2, 12), IceCube::ONE_HOUR)
      intervals = free_intervals(available: business_hours, busy: [lunch])
      expect(intervals).to eq [t(2, 9)...t(2, 12), t(2, 13)...t(2, 17)]
    end

    it "returns the whole available block when there is nothing busy" do
      intervals = free_intervals(available: business_hours)
      expect(intervals).to eq [t(2, 9)...t(2, 17)]
    end

    it "ignores busy occurrences outside the window" do
      busy = hours_schedule(t(5, 12), IceCube::ONE_HOUR)
      intervals = free_intervals(available: business_hours, busy: [busy])
      expect(intervals).to eq [t(2, 9)...t(2, 17)]
    end

    it "drops gaps shorter than the requested duration" do
      busy = hours_schedule(t(2, 9), 7 * IceCube::ONE_HOUR + 16 * IceCube::ONE_MINUTE)
      intervals = free_intervals(available: business_hours, busy: [busy])
      expect(intervals).to eq []
    end

    it "keeps a gap exactly as long as the requested duration" do
      busy = hours_schedule(t(2, 9), 7 * IceCube::ONE_HOUR + 15 * IceCube::ONE_MINUTE)
      intervals = free_intervals(available: business_hours, busy: [busy])
      expect(intervals).to eq [t(2, 16, 15)...t(2, 17)]
    end
  end

  describe "merging before subtracting" do
    it "unions overlapping available schedules" do
      morning = hours_schedule(t(2, 9), 4 * IceCube::ONE_HOUR)
      afternoon = hours_schedule(t(2, 12), 5 * IceCube::ONE_HOUR)
      busy = hours_schedule(t(2, 10), IceCube::ONE_HOUR)
      intervals = free_intervals(available: [morning, afternoon], busy: [busy])
      expect(intervals).to eq [t(2, 9)...t(2, 10), t(2, 11)...t(2, 17)]
    end

    it "unions touching available schedules into a single interval" do
      morning = hours_schedule(t(2, 9), 3 * IceCube::ONE_HOUR)
      afternoon = hours_schedule(t(2, 12), 5 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: [morning, afternoon], duration: 2 * IceCube::ONE_HOUR)
      expect(intervals).to eq [t(2, 9)...t(2, 17)]
    end

    it "unions overlapping busy schedules before subtracting" do
      first = hours_schedule(t(2, 10), 2 * IceCube::ONE_HOUR)
      second = hours_schedule(t(2, 11), 2 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: business_hours, busy: [first, second])
      expect(intervals).to eq [t(2, 9)...t(2, 10), t(2, 13)...t(2, 17)]
    end

    it "lets a busy interval abutting another one block the whole span" do
      first = hours_schedule(t(2, 10), 2 * IceCube::ONE_HOUR)
      second = hours_schedule(t(2, 12), 2 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: business_hours, busy: [first, second])
      expect(intervals).to eq [t(2, 9)...t(2, 10), t(2, 14)...t(2, 17)]
    end
  end

  describe "window clipping" do
    it "clips an available occurrence that starts before the window" do
      available = hours_schedule(t(1, 20), 30 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: available)
      expect(intervals).to eq [t(2, 0)...t(3, 0)]
    end

    it "clips a busy occurrence that crosses midnight into the window" do
      available = hours_schedule(t(2, 0), 48 * IceCube::ONE_HOUR)
      busy = hours_schedule(t(1, 22), 4 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: available, busy: [busy])
      expect(intervals).to eq [t(2, 2)...t(3, 0)]
    end

    it "handles a busy occurrence crossing midnight inside the window" do
      available = hours_schedule(t(2, 0), 48 * IceCube::ONE_HOUR)
      busy = hours_schedule(t(2, 22), 4 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: available, busy: [busy], window: [t(2, 0), t(3, 12)])
      expect(intervals).to eq [t(2, 0)...t(2, 22), t(3, 2)...t(3, 12)]
    end

    it "clips an available occurrence that extends past the window" do
      available = hours_schedule(t(2, 12), 48 * IceCube::ONE_HOUR)
      intervals = free_intervals(available: available)
      expect(intervals).to eq [t(2, 12)...t(3, 0)]
    end
  end

  describe "zero-duration occurrences" do
    it "never blocks availability" do
      busy = IceCube::Schedule.new(t(2, 12))
      intervals = free_intervals(available: business_hours, busy: [busy])
      expect(intervals).to eq [t(2, 9)...t(2, 17)]
    end

    it "never provides availability" do
      available = IceCube::Schedule.new(t(2, 12))
      intervals = free_intervals(available: available)
      expect(intervals).to eq []
    end
  end

  describe "infinite rules" do
    it "truncates unbounded rules at the query window" do
      busy = hours_schedule(t(1, 12), IceCube::ONE_HOUR) do |s|
        s.add_recurrence_rule IceCube::Rule.daily
      end
      intervals = free_intervals(available: business_hours, busy: [busy], window: [t(2, 0), t(4, 0)])
      expect(intervals).to eq [
        t(2, 9)...t(2, 12), t(2, 13)...t(2, 17),
        t(3, 9)...t(3, 12), t(3, 13)...t(3, 17)
      ]
    end

    it "raises LimitExceeded when a schedule exceeds max_occurrences" do
      expect {
        free_intervals(available: business_hours, max_occurrences: 5, window: [t(1, 0), t(11, 0)])
      }.to raise_error(IceCube::Availability::LimitExceeded)
    end

    it "accepts schedules within max_occurrences" do
      intervals = free_intervals(available: business_hours, max_occurrences: 3, window: [t(1, 0), t(4, 0)])
      expect(intervals.size).to eq 3
    end
  end

  describe "returned intervals" do
    it "are sorted, non-overlapping, half-open and inside the window" do
      window = [t(1, 0), t(4, 0)]
      lunch = hours_schedule(t(1, 12), IceCube::ONE_HOUR) do |s|
        s.add_recurrence_rule IceCube::Rule.daily
      end
      intervals = free_intervals(available: business_hours, busy: [lunch], window: window)
      expect(intervals).to eq intervals.sort_by(&:begin)
      intervals.each do |interval|
        expect(interval.exclude_end?).to be true
        expect(interval.begin).to be >= window[0]
        expect(interval.end).to be <= window[1]
        expect(interval.end - interval.begin).to be >= 45 * IceCube::ONE_MINUTE
      end
      intervals.each_cons(2) do |previous, following|
        expect(previous.end).to be < following.begin
      end
    end
  end

  describe "validation" do
    it "requires at least one available schedule" do
      expect {
        IceCube::Availability.new(available: [], duration: IceCube::ONE_HOUR)
      }.to raise_error(ArgumentError)
    end

    it "requires a positive duration" do
      expect {
        IceCube::Availability.new(available: business_hours, duration: 0)
      }.to raise_error(ArgumentError)
    end

    it "requires a positive max_occurrences" do
      expect {
        IceCube::Availability.new(available: business_hours, duration: IceCube::ONE_HOUR, max_occurrences: 0)
      }.to raise_error(ArgumentError)
    end

    it "requires the window to close after it opens" do
      availability = IceCube::Availability.new(available: business_hours, duration: IceCube::ONE_HOUR)
      expect { availability.free_intervals(t(3, 0), t(2, 0)) }.to raise_error(ArgumentError)
      expect { availability.free_intervals(t(2, 0), t(2, 0)) }.to raise_error(ArgumentError)
    end
  end
end
