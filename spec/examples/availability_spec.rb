require "spec_helper"

module IceCube
  RSpec.describe Availability do
    let(:monday) { Time.utc(2020, 1, 6) }
    let(:tuesday) { Time.utc(2020, 1, 7) }

    def interval(start_time, end_time)
      Range.new(start_time, end_time, true)
    end

    def schedule_at(time, duration:)
      Schedule.new(time, duration: duration)
    end

    describe ".free_windows" do
      it "merges overlapping busy intervals first and subtracts them from open hours" do
        open = [schedule_at(monday + 8 * ONE_HOUR, duration: 8 * ONE_HOUR)]
        busy = [
          schedule_at(monday + 9 * ONE_HOUR, duration: ONE_HOUR),       # 09:00-10:00
          schedule_at(monday + 9 * ONE_HOUR + 30 * ONE_MINUTE, duration: ONE_HOUR), # 09:30-10:30
          schedule_at(monday + 15 * ONE_HOUR, duration: ONE_HOUR)       # 15:00-16:00
        ]

        result = described_class.free_windows(
          monday, tuesday,
          available_schedules: open,
          busy_schedules: busy
        )

        expect(result).to eq([
          interval(monday + 8 * ONE_HOUR, monday + 9 * ONE_HOUR),
          interval(monday + 10 * ONE_HOUR + 30 * ONE_MINUTE, monday + 15 * ONE_HOUR)
        ])
      end

      it "merges overlapping open schedules and clips them to the window" do
        open = [
          schedule_at(monday - ONE_HOUR, duration: 10 * ONE_HOUR),      # 23:00-09:00
          schedule_at(monday + 8 * ONE_HOUR, duration: 20 * ONE_HOUR)   # 08:00-04:00 next day
        ]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: []
        )

        expect(result).to eq([interval(monday, tuesday)])
      end

      it "treats touching intervals as non-overlapping at the boundary" do
        open = [schedule_at(monday + 8 * ONE_HOUR, duration: 8 * ONE_HOUR)] # 08:00-16:00
        busy = [
          schedule_at(monday + 10 * ONE_HOUR, duration: ONE_HOUR),         # 10:00-11:00
          schedule_at(monday + 11 * ONE_HOUR, duration: ONE_HOUR)          # 11:00-12:00, touches
        ]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: busy
        )

        expect(result).to eq([
          interval(monday + 8 * ONE_HOUR, monday + 10 * ONE_HOUR),
          interval(monday + 12 * ONE_HOUR, monday + 16 * ONE_HOUR)
        ])
      end

     it "handles a busy occurrence crossing midnight" do
        open = [
          schedule_at(monday + 22 * ONE_HOUR, duration: 4 * ONE_HOUR),    # Monday 22:00 - 02:00
          schedule_at(tuesday + 22 * ONE_HOUR, duration: 4 * ONE_HOUR)    # Tuesday 22:00 - 02:00
        ]
        busy = Schedule.new(tuesday - 30 * ONE_MINUTE, duration: ONE_HOUR) # 23:30-00:30

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: [busy]
        )

        # open [Mon 22:00, Tue 02:00) and busy [Mon 23:30, Tue 00:30) are
        # both clipped to the Mon-Tue window before subtracting
        expect(result).to eq([
          interval(monday + 22 * ONE_HOUR, monday + 23 * ONE_HOUR + 30 * ONE_MINUTE)
        ])
      end

      it "includes a single occurrence starting before the window and clips it" do
        open = [schedule_at(monday - 30 * ONE_MINUTE, duration: 90 * ONE_MINUTE)] # 23:30-01:00

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: []
        )

        expect(result).to eq([interval(monday, monday + ONE_HOUR)])
      end

      it "excludes an occurrence ending exactly at the window start (half-open)" do
        open = [schedule_at(monday - 2 * ONE_HOUR, duration: 2 * ONE_HOUR)]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: []
        )

        expect(result).to eq([])
      end

      it "clips an occurrence extending past the window end" do
        open = [schedule_at(tuesday - 30 * ONE_MINUTE, duration: 2 * ONE_HOUR)]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: []
        )

        expect(result).to eq([interval(tuesday - 30 * ONE_MINUTE, tuesday)])
      end

      it "ignores zero-duration occurrences on both sides" do
        open = [schedule_at(monday + 9 * ONE_HOUR, duration: 2 * ONE_HOUR)]
        busy = [schedule_at(monday + 10 * ONE_HOUR, duration: 0)]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: busy
        )

        expect(result).to eq([
          interval(monday + 9 * ONE_HOUR, monday + 11 * ONE_HOUR)
        ])
      end

      it "truncates infinite recurrence rules at the query window" do
        open = Schedule.new(monday, end_time: tuesday + ONE_DAY) do |schedule|
          schedule.add_recurrence_rule Rule.daily
        end
        busy = Schedule.new(monday + 12 * ONE_HOUR, duration: ONE_HOUR) do |schedule|
          schedule.add_recurrence_rule Rule.daily
        end

        result = described_class.free_windows(
          monday, tuesday + ONE_DAY,
          available_schedules: [open], busy_schedules: [busy]
        )

        expect(result).to eq([
          interval(monday, monday + 12 * ONE_HOUR),
          interval(monday + 13 * ONE_HOUR, tuesday + 12 * ONE_HOUR),
          interval(tuesday + 13 * ONE_HOUR, tuesday + ONE_DAY)
        ])
      end

      it "includes a recurring occurrence that starts before the window" do
        busy = Schedule.new(monday - 30 * ONE_MINUTE, duration: ONE_HOUR) do |schedule|
          schedule.add_recurrence_rule Rule.daily
        end
        open = [schedule_at(monday, duration: 4 * ONE_HOUR)]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: [busy]
        )

        expect(result).to eq([
          interval(monday + 30 * ONE_MINUTE, monday + 4 * ONE_HOUR)
        ])
      end

      it "returns half-open, sorted, disjoint ranges" do
        open = [
          schedule_at(monday + 14 * ONE_HOUR, duration: 2 * ONE_HOUR),
          schedule_at(monday + 8 * ONE_HOUR, duration: 2 * ONE_HOUR)
        ]

        result = described_class.free_windows(
          monday, tuesday, available_schedules: open, busy_schedules: []
        )

        expect(result.map(&:exclude_end?)).to all(be(true))
        expect(result).to eq(result.sort_by(&:begin))
        starts = result.map(&:begin)
        expect(starts).to eq(starts.uniq)
      end

      it "returns an empty array when nothing is available" do
        result = described_class.free_windows(monday, tuesday)

        expect(result).to eq([])
      end

      it "raises when a schedule exceeds the occurrences cap" do
        every_minute = Schedule.new(monday) do |schedule|
          schedule.add_recurrence_rule Rule.minutely
        end

        expect do
          described_class.free_windows(
            monday, tuesday, available_schedules: [], busy_schedules: [every_minute],
            max_occurrences: 10
          )
        end.to raise_error(TooManyOccurrences)
      end

      it "rejects an invalid query window" do
        expect do
          described_class.free_windows(tuesday, monday)
        end.to raise_error(ArgumentError, /window_end/)
      end
    end

    describe ".appointment_windows" do
      it "packs 45 minute appointments from the start of each free window" do
        open = [schedule_at(monday + 8 * ONE_HOUR, duration: 4 * ONE_HOUR)] # 08:00-12:00
        busy = [schedule_at(monday + 9 * ONE_HOUR, duration: 30 * ONE_MINUTE)] # 09:00-09:30

        result = described_class.appointment_windows(
          monday, tuesday, duration: 45 * ONE_MINUTE,
          available_schedules: open, busy_schedules: busy
        )

        expect(result).to eq([
          interval(monday + 8 * ONE_HOUR, monday + 8 * ONE_HOUR + 45 * ONE_MINUTE),
          interval(
            monday + 9 * ONE_HOUR + 30 * ONE_MINUTE,
            monday + 10 * ONE_HOUR + 15 * ONE_MINUTE
          ),
          interval(monday + 10 * ONE_HOUR + 15 * ONE_MINUTE, monday + 11 * ONE_HOUR),
          interval(monday + 11 * ONE_HOUR, monday + 11 * ONE_HOUR + 45 * ONE_MINUTE)
        ])
      end

      it "does not emit a slot crossing the free window end" do
        open = [schedule_at(monday + 8 * ONE_HOUR, duration: 60 * ONE_MINUTE)]

        result = described_class.appointment_windows(
          monday, tuesday, duration: 45 * ONE_MINUTE,
          available_schedules: open, busy_schedules: []
        )

        expect(result).to eq([
          interval(monday + 8 * ONE_HOUR, monday + 8 * ONE_HOUR + 45 * ONE_MINUTE)
        ])
      end

      it "rejects a non-positive duration" do
        expect do
          described_class.appointment_windows(monday, tuesday, duration: 0)
        end.to raise_error(ArgumentError, /duration/)
      end
    end

    describe ".merge_intervals" do
      it "merges overlapping and touching intervals and drops empty ones" do
        intervals = [
          interval(monday + 12 * ONE_HOUR, monday + 14 * ONE_HOUR),
          interval(monday + 13 * ONE_HOUR, monday + 15 * ONE_HOUR),
          interval(monday + 8 * ONE_HOUR, monday + 9 * ONE_HOUR),
          interval(monday + 9 * ONE_HOUR, monday + 10 * ONE_HOUR),
          interval(monday + 20 * ONE_HOUR, monday + 20 * ONE_HOUR)
        ]

        expect(described_class.merge_intervals(intervals)).to eq([
          [monday + 8 * ONE_HOUR, monday + 10 * ONE_HOUR],
          [monday + 12 * ONE_HOUR, monday + 15 * ONE_HOUR]
        ])
      end
    end
  end
end
