require File.dirname(__FILE__) + "/../spec_helper"
require "active_support/all"

module IceCube
  describe "RDATE periods" do
    let(:t0) { Time.utc(2020, 1, 1, 12, 0, 0) }

    describe "Ruby API" do
      it "accepts an end time and produces an occurrence with its own duration" do
        schedule = Schedule.new(t0)
        occ = schedule.add_recurrence_time(t0 + ONE_DAY, end_time: t0 + ONE_DAY + 2 * ONE_HOUR)

        expect(occ).to be_a(Occurrence)
        expect(occ.start_time).to eq(t0 + ONE_DAY)
        expect(occ.end_time).to eq(t0 + ONE_DAY + 2 * ONE_HOUR)
        expect(occ.duration).to eq(2 * ONE_HOUR)

        found = schedule.occurrences_between(t0, t0 + 2 * ONE_DAY)
          .find { |occ| occ.start_time == t0 + ONE_DAY }
        expect(found.end_time).to eq(t0 + ONE_DAY + 2 * ONE_HOUR)
      end

      it "accepts a duration in seconds" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, duration: 90 * ONE_MINUTE)

        found = schedule.occurrences(t0 + 2 * ONE_DAY).last
        expect(found.start_time).to eq(t0 + ONE_DAY)
        expect(found.end_time).to eq(t0 + ONE_DAY + 90 * ONE_MINUTE)
      end

      it "accepts an end time positionally" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, t0 + ONE_DAY + ONE_HOUR)

        found = schedule.all_occurrences.find { |occ| occ.start_time == t0 + ONE_DAY }
        expect(found.end_time).to eq(t0 + ONE_DAY + ONE_HOUR)
      end

      it "accepts end_time as an options hash" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, {end_time: t0 + ONE_DAY + ONE_HOUR})

        found = schedule.all_occurrences.find { |occ| occ.start_time == t0 + ONE_DAY }
        expect(found.end_time).to eq(t0 + ONE_DAY + ONE_HOUR)
      end

      it "accepts a Range" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time((t0 + ONE_DAY)..(t0 + ONE_DAY + ONE_HOUR))

        found = schedule.first(2).last
        expect(found.end_time).to eq(t0 + ONE_DAY + ONE_HOUR)
      end

      it "accepts an Occurrence" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(Occurrence.new(t0 + ONE_DAY, t0 + ONE_DAY + ONE_HOUR))

        found = schedule.all_occurrences.find { |occ| occ.start_time == t0 + ONE_DAY }
        expect(found.end_time).to eq(t0 + ONE_DAY + ONE_HOUR)
      end

      it "raises on a negative duration" do
        schedule = Schedule.new(t0)
        expect { schedule.add_recurrence_time(t0, duration: -1) }
          .to raise_error(ArgumentError)
      end

      it "raises on an end time before the start time" do
        schedule = Schedule.new(t0)
        expect { schedule.add_recurrence_time(t0, end_time: t0 - 1) }
          .to raise_error(ArgumentError)
      end

      it "raises when both end_time and duration are supplied" do
        schedule = Schedule.new(t0)
        expect {
          schedule.add_recurrence_time(t0, end_time: t0 + 60, duration: 60)
        }.to raise_error(ArgumentError)
      end

      it "treats a zero duration as a zero-length occurrence" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, duration: 0)

        expect(schedule.recurrence_occurrences.first.duration).to eq(0)
        expect(schedule.recurrence_occurrences.first.end_time).to eq(t0 + ONE_DAY)
      end

      it "aligns a mismatched end time zone to the start time zone" do
        schedule = Schedule.new(t0)
        start = Time.new(2020, 6, 1, 12, 0, 0, "+02:00")
        finish = Time.utc(2020, 6, 1, 11, 0, 0) # same instant, different zone
        schedule.add_recurrence_time(start, end_time: finish)

        expect(schedule.recurrence_occurrences.first.end_time.utc_offset).to eq(start.utc_offset)
      end
    end

    describe "deduping" do
      it "does not emit the same start time twice when rule and RDATE coincide" do
        schedule = Schedule.new(t0, duration: ONE_HOUR)
        schedule.add_recurrence_rule(Rule.daily.count(3))
        schedule.add_recurrence_time(t0 + ONE_DAY, end_time: t0 + ONE_DAY + 2 * ONE_HOUR)

        occurrences = schedule.all_occurrences
        starts = occurrences.map(&:start_time)
        expect(starts).to eq(starts.uniq)
        expect(occurrences.map { |o| [o.start_time, o.end_time] }).to eq([
          [t0, t0 + ONE_HOUR],
          [t0 + ONE_DAY, t0 + ONE_DAY + 2 * ONE_HOUR],
          [t0 + 2 * ONE_DAY, t0 + 2 * ONE_DAY + ONE_HOUR]
        ])
      end

      it "prefers the explicit period when a zero-length RDATE matches a rule" do
        schedule = Schedule.new(t0, duration: ONE_HOUR)
        schedule.add_recurrence_rule(Rule.daily.count(2))
        schedule.add_recurrence_time(t0 + ONE_DAY, end_time: t0 + ONE_DAY + 2 * ONE_HOUR)

        occ = schedule.occurrences(t0 + ONE_DAY + 1).last
        expect(occ.duration).to eq(2 * ONE_HOUR)
      end

      it "keeps the longer period deterministically when added twice" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0, duration: ONE_HOUR)
        schedule.add_recurrence_time(t0, duration: 2 * ONE_HOUR)

        expect(schedule.recurrence_occurrences.count).to eq(1)
        expect(schedule.first.duration).to eq(2 * ONE_HOUR)
      end
    end

    describe "spanning queries" do
      it "includes a long instance that begins before the window" do
        schedule = Schedule.new(t0 - 10 * ONE_DAY)
        schedule.add_recurrence_time(t0 - 6 * ONE_HOUR, end_time: t0 + 6 * ONE_HOUR)

        occs = schedule.occurrences_between(t0, t0 + ONE_DAY, spans: true)
        expect(occs.map(&:start_time)).to eq([t0 - 6 * ONE_HOUR])
      end

      it "does not include a period that ends before the window (spans)" do
        schedule = Schedule.new(t0 - 10 * ONE_DAY)
        schedule.add_recurrence_time(t0 - 2 * ONE_HOUR, end_time: t0 - ONE_HOUR)

        occs = schedule.occurrences_between(t0, t0 + ONE_DAY, spans: true)
        expect(occs).to be_empty
      end

      it "does not include the long instance in a start-based window" do
        schedule = Schedule.new(t0 - 10 * ONE_DAY)
        schedule.add_recurrence_time(t0 - 6 * ONE_HOUR, end_time: t0 + 6 * ONE_HOUR)

        occs = schedule.occurrences_between(t0, t0 + ONE_DAY)
        expect(occs).to be_empty
      end

      it "is occurring_at? a time inside an RDATE period" do
        schedule = Schedule.new(t0 - 10 * ONE_DAY)
        schedule.add_recurrence_time(t0 - ONE_HOUR, end_time: t0 + ONE_HOUR)

        expect(schedule.occurring_at?(t0)).to be_truthy
        expect(schedule.occurring_at?(t0 - 2 * ONE_HOUR)).to be_falsey
      end
    end

    describe "iCalendar" do
      it "emits and parses a period RDATE (start/end)" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, end_time: t0 + ONE_DAY + ONE_HOUR)

        ical = schedule.to_ical
        expect(ical).to include("RDATE;VALUE=PERIOD:20200102T120000Z/20200102T130000Z")

        restored = Schedule.from_ical(ical)
        occ = restored.first(2).last
        expect(occ.start_time).to eq(t0 + ONE_DAY)
        expect(occ.end_time).to eq(t0 + ONE_DAY + ONE_HOUR)
      end

      it "parses a period given as start/duration" do
        ical = "DTSTART:20200101T120000Z\n" \
               "RDATE;VALUE=PERIOD:20200102T120000Z/PT2H30M"
        schedule = Schedule.from_ical(ical)

        occ = schedule.first(2).last
        expect(occ.end_time).to eq(t0 + ONE_DAY + 2 * ONE_HOUR + 30 * ONE_MINUTE)
      end

      it "parses a period given as start/duration in days" do
        ical = "DTSTART:20200101T120000Z\n" \
               "RDATE;VALUE=PERIOD:20200102T120000Z/P1D"
        schedule = Schedule.from_ical(ical)

        expect(schedule.first(2).last.end_time).to eq(t0 + 2 * ONE_DAY)
      end

      it "rejects an invalid period duration" do
        ical = "DTSTART:20200101T120000Z\n" \
               "RDATE;VALUE=PERIOD:20200102T120000Z/XYZ"
        expect { Schedule.from_ical(ical) }.to raise_error(ArgumentError)
      end

      it "rejects a malformed period value" do
        ical = "DTSTART:20200101T120000Z\nRDATE;VALUE=PERIOD:not-a-period"
        expect { Schedule.from_ical(ical) }.to raise_error(ArgumentError)
      end

      it "rejects malformed duration values" do
        expect { IcalBuilder.ical_duration_to_seconds("P") }.to raise_error(ArgumentError)
        expect { IcalBuilder.ical_duration_to_seconds("PT") }.to raise_error(ArgumentError)
      end

      it "rejects a negative period duration" do
        ical = "DTSTART:20200101T120000Z\n" \
               "RDATE;VALUE=PERIOD:20200102T120000Z/-PT1H"
        expect { Schedule.from_ical(ical) }.to raise_error(ArgumentError)
      end

      it "supports multiple comma-separated periods on one line" do
        ical = "DTSTART:20200101T120000Z\n" \
               "RDATE;VALUE=PERIOD:20200102T120000Z/20200102T130000Z," \
               "20200103T120000Z/20200103T140000Z"
        schedule = Schedule.from_ical(ical)

        expect(schedule.recurrence_occurrences.map(&:duration)).to eq([ONE_HOUR, 2 * ONE_HOUR])
      end

      it "parses a zero-duration period without inventing a duration" do
        ical = "DTSTART:20200101T120000Z\n" \
               "RDATE;VALUE=PERIOD:20200102T120000Z/PT0S"
        schedule = Schedule.from_ical(ical)

        occ = schedule.all_occurrences.find { |o| o.start_time == t0 + ONE_DAY }
        expect(occ.duration).to eq(0)
        expect(occ.end_time).to eq(t0 + ONE_DAY)
      end

      it "round-trips start and end through iCalendar" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, duration: ONE_HOUR)
        schedule.add_recurrence_time(t0 + 2 * ONE_DAY, end_time: t0 + 2 * ONE_DAY + 2 * ONE_HOUR)

        restored = Schedule.from_ical(schedule.to_ical)
        expect(restored.to_ical).to eq(schedule.to_ical)
        expect(restored.recurrence_occurrences).to eq(schedule.recurrence_occurrences)
      end

      it "round-trips local-time periods with a TZID parameter" do
        ical = "DTSTART;TZID=America/Denver:20130731T143000\n" \
               "RDATE;VALUE=PERIOD;TZID=America/Denver:20130807T143000/20130807T163000"
        schedule = Schedule.from_ical(ical)
        occ = schedule.recurrence_occurrences.first

        expect(occ.start_time).to eq(Time.new(2013, 8, 7, 14, 30, 0, "-06:00"))
        expect(occ.end_time).to eq(Time.new(2013, 8, 7, 16, 30, 0, "-06:00"))
        expect(schedule.to_ical).to include("RDATE;VALUE=PERIOD;TZID=America/Denver:20130807T143000/20130807T163000")
      end
    end

    describe "Hash round-trip" do
      it "keeps start and end consistent" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, end_time: t0 + ONE_DAY + 90 * ONE_MINUTE)

        restored = Schedule.from_hash(schedule.to_hash)
        expect(restored.recurrence_occurrences).to eq(schedule.recurrence_occurrences)
        expect(restored.to_hash).to eq(schedule.to_hash)
      end

      it "supports a duration key in the rtime hash" do
        hash = {
          start_time: t0,
          rtimes: [{time: t0 + ONE_DAY, duration: ONE_HOUR}]
        }
        schedule = Schedule.from_hash(hash)
        expect(schedule.recurrence_occurrences.first.duration).to eq(ONE_HOUR)
      end

      it "round-trips start and end through YAML" do
        schedule = Schedule.new(t0)
        schedule.add_recurrence_time(t0 + ONE_DAY, duration: ONE_HOUR)

        restored = Schedule.from_yaml(schedule.to_yaml)
        expect(restored.recurrence_occurrences).to eq(schedule.recurrence_occurrences)
      end
    end

    describe "equality" do
      it "treats periods with different durations as different schedules" do
        one = Schedule.new(t0)
        two = Schedule.new(t0)
        one.add_recurrence_time(t0 + ONE_DAY, duration: ONE_HOUR)
        two.add_recurrence_time(t0 + ONE_DAY, duration: 2 * ONE_HOUR)

        expect(one).not_to eq(two)
        expect(two).to eq(Schedule.from_hash(two.to_hash))
      end
    end
  end
end
