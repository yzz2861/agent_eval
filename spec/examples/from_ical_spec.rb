require File.dirname(__FILE__) + "/../spec_helper"
require "active_support"
require "active_support/time"

module IceCube
  describe Rule, "from_ical" do
    it "should return a IceCube DailyRule class for a basic daily rule" do
      rule = IceCube::Rule.from_ical "FREQ=DAILY"
      expect(rule.class).to eq(IceCube::DailyRule)
    end

    it "should return a IceCube WeeklyRule class for a basic monthly rule" do
      rule = IceCube::Rule.from_ical "FREQ=WEEKLY"
      expect(rule.class).to eq(IceCube::WeeklyRule)
    end

    it "should return a IceCube MonthlyRule class for a basic monthly rule" do
      rule = IceCube::Rule.from_ical "FREQ=MONTHLY"
      expect(rule.class).to eq(IceCube::MonthlyRule)
    end

    it "should return a IceCube YearlyRule class for a basic yearly rule" do
      rule = IceCube::Rule.from_ical "FREQ=YEARLY"
      expect(rule.class).to eq(IceCube::YearlyRule)
    end

    it "should be able to parse a .day rule" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYDAY=MO,TU")
      expect(rule).to eq(IceCube::Rule.daily.day(:monday, :tuesday))
    end

    it "should be able to parse a .day_of_week rule" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYDAY=-1TU,-2TU")
      expect(rule).to eq(IceCube::Rule.daily.day_of_week(tuesday: [-1, -2]))
    end

    it "should be able to parse both .day and .day_of_week rules" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYDAY=MO,-1TU,-2TU")
      expect(rule).to eq(IceCube::Rule.daily.day_of_week(tuesday: [-1, -2]).day(:monday))
    end

    it "should be able to parse a .day_of_month rule" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYMONTHDAY=23")
      expect(rule).to eq(IceCube::Rule.daily.day_of_month(23))
    end

    it "should be able to parse a .day_of_year rule" do
      rule = IceCube::Rule.from_ical("FREQ=YEARLY;BYYEARDAY=100,200")
      expect(rule).to eq(IceCube::Rule.yearly.day_of_year(100, 200))
    end

    it "should be able to serialize a .month_of_year rule" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYMONTH=1,4")
      expect(rule).to eq(IceCube::Rule.daily.month_of_year(:january, :april))
    end

    it "should be able to split to a combination of day_of_week and day (day_of_week has priority)" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYDAY=TU,MO,1MO,-1MO")
      expect(rule).to eq(IceCube::Rule.daily.day(:tuesday).day_of_week(monday: [1, -1]))
    end

    it "should be able to parse of .day_of_week rule with multiple days" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;BYDAY=WE,1MO,-1MO,2TU")
      expect(rule).to eq(IceCube::Rule.daily.day_of_week(monday: [1, -1], tuesday: [2]).day(:wednesday))
    end

    it "should be able to parse a rule with an until date" do
      t = Time.now.utc
      rule = IceCube::Rule.from_ical("FREQ=WEEKLY;UNTIL=#{t.strftime("%Y%m%dT%H%M%SZ")}")
      expect(rule.to_s).to eq(IceCube::Rule.weekly.until(t).to_s)
    end

    it "should be able to parse a rule with a count date" do
      rule = IceCube::Rule.from_ical("FREQ=WEEKLY;COUNT=5")
      expect(rule).to eq(IceCube::Rule.weekly.count(5))
    end

    it "should be able to parse a rule with an interval" do
      rule = IceCube::Rule.from_ical("FREQ=DAILY;INTERVAL=2")
      expect(rule).to eq(IceCube::Rule.daily.interval(2))
    end

    it "should be able to parse week start (WKST)" do
      rule = IceCube::Rule.from_ical("FREQ=WEEKLY;INTERVAL=2;WKST=MO")
      expect(rule).to eq(IceCube::Rule.weekly(2, :monday))
    end

    it "should be able to parse by_set_pos start (BYSETPOS)" do
      rule = IceCube::Rule.from_ical("FREQ=MONTHLY;BYDAY=MO,WE;BYSETPOS=-1,1")
      expect(rule).to eq(IceCube::Rule.monthly.day(:monday, :wednesday).by_set_pos([-1, 1]))
    end

    it "should preserve by_set_pos in a to_hash/from_hash round trip" do
      rule = IceCube::Rule.monthly.day(:monday, :wednesday).by_set_pos([-1, 1])
      expect(IceCube::Rule.from_hash(rule.to_hash)).to eq(rule)
    end

    it "should raise when by_set_pos is out of range (BYSETPOS)" do
      expect {
        IceCube::Rule.from_ical("FREQ=MONTHLY;BYDAY=MO,WE;BYSETPOS=-367")
      }.to raise_error(/Expecting number in \[-366, -1\] or \[1, 366\]/)

      expect {
        IceCube::Rule.from_ical("FREQ=MONTHLY;BYDAY=MO,WE;BYSETPOS=367")
      }.to raise_error(/Expecting number in \[-366, -1\] or \[1, 366\]/)

      expect {
        IceCube::Rule.from_ical("FREQ=MONTHLY;BYDAY=MO,WE;BYSETPOS=0")
      }.to raise_error(/Expecting number in \[-366, -1\] or \[1, 366\]/)
    end

    it "should return no occurrences after daily interval with count is over" do
      schedule = IceCube::Schedule.new(Time.now)
      schedule.add_recurrence_rule(IceCube::Rule.from_ical("FREQ=DAILY;COUNT=5"))
      expect(schedule.occurrences_between(Time.now + (IceCube::ONE_DAY * 7), Time.now + (IceCube::ONE_DAY * 14)).count).to eq(0)
    end
  end

  describe Schedule, "from_ical" do
    ical_string = <<-ICAL.gsub(/^\s*/, "")
  DTSTART:20130314T201500Z
  DTEND:20130314T201545Z
  RRULE:FREQ=WEEKLY;BYDAY=TH;UNTIL=20130531T100000Z
    ICAL

    ical_string_with_multiple_exdates_and_rdates = <<-ICAL.gsub(/^\s*/, "")
  DTSTART;TZID=America/Denver:20130731T143000
  DTEND;TZID=America/Denver:20130731T153000
  RRULE:FREQ=WEEKLY;UNTIL=20140730T203000Z;BYDAY=MO,WE,FR
  EXDATE;TZID=America/Denver:20130823T143000
  EXDATE;TZID=America/Denver:20130812T143000
  EXDATE;TZID=America/Denver:20130807T143000
  RDATE;TZID=America/Denver:20150812T143000
  RDATE;TZID=America/Denver:20150807T143000
    ICAL

    ical_string_with_multiple_rules = <<-ICAL.gsub(/^\s*/, "")
  DTSTART;TZID=CDT:20151005T195541
  RRULE:FREQ=WEEKLY;BYDAY=MO,TU
  RRULE:FREQ=WEEKLY;INTERVAL=2;WKST=SU;BYDAY=FR
    ICAL

    def sorted_ical(ical)
      ical.split("\n").sort.map { |field|
        k, v = field.split(":")
        v = v.split(";").sort.join(";") if k == "RRULE"

        "#{k}:#{v}"
      }.join("\n")
    end

    describe "instantiation" do
      it "loads an ICAL string" do
        expect(IceCube::Schedule.from_ical(ical_string)).to be_a(IceCube::Schedule)
      end
    end

    describe "daily frequency" do
      it "matches simple daily" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.daily)

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles counts" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.daily.count(4))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.daily(4))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals and counts" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.daily(4).count(10))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles until dates" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.daily.until(start_time + (IceCube::ONE_DAY * 15)))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end
    end

    describe "weekly frequency" do
      it "matches simple weekly" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.weekly)

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles weekdays" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.weekly.day(:monday, :thursday))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.weekly(2))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals and counts" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.weekly(2).count(4))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals and counts on given weekdays" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.weekly(2).day(:monday, :wednesday).count(4))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end
    end

    describe "monthly frequency" do
      it "matches simple monthly" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.monthly)

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.monthly(2))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals and counts" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.monthly(2).count(5))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals and counts on specific days" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.monthly(2).day_of_month(1, 15).count(5))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end
    end

    describe "yearly frequency" do
      it "matches simple yearly" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly)

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles intervals" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly(2))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles a specific day" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly.day_of_year(15))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles specific days" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly.day_of_year(1, 15, -1))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles counts" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly.count(5))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles specific months" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly.month_of_year(:january, :december))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles specific months and counts" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.yearly.month_of_year(:january, :december).count(15))

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end
    end

    describe "exceptions" do
      it "handles single EXDATE lines, single RDATE lines" do
        start_time = Time.now

        schedule = IceCube::Schedule.new(start_time)
        schedule.add_recurrence_rule(IceCube::Rule.daily)
        schedule.add_exception_time(Time.now + (IceCube::ONE_DAY * 2))
        schedule.add_recurrence_time(Time.now + IceCube::ONE_DAY * 4)

        ical = schedule.to_ical
        expect(sorted_ical(IceCube::Schedule.from_ical(ical).to_ical)).to eq(sorted_ical(ical))
      end

      it "handles multiple EXDATE / RDATE lines" do
        schedule = IceCube::Schedule.from_ical ical_string_with_multiple_exdates_and_rdates
        expect(schedule.exception_times.count).to eq(3)
        expect(schedule.recurrence_times.count).to eq(2)
      end

      it "should raise ArgumentError when parsing an invalid rule type" do
        str = "FREQ=FAKE"
        expect { Rule.from_ical(str) }.to raise_error(ArgumentError, "Invalid rule frequency type: Fake")
      end

      it "should raise ArgumentError when parsing an invalid validation type" do
        str = "FREQ=DAILY;FAKE=23"
        expect { Rule.from_ical(str) }.to raise_error(ArgumentError, "Invalid rule validation type: FAKE")
      end
    end

    describe "multiple rules" do
      it "handles multiple recurrence rules" do
        schedule = IceCube::Schedule.from_ical ical_string_with_multiple_rules
        expect(schedule.recurrence_rules.count).to eq(2)
      end
    end

    describe "invalid ical data" do
      shared_examples_for("an invalid ical string") do
        it do
          expect {
            IceCube::Schedule.from_ical(ical_str)
          }.to raise_error(ArgumentError) # TODO replace with real ad
        end
      end

      describe "empty rules" do
        let(:ical_str) { "RRULE::" }
        it_behaves_like "an invalid ical string"
      end

      describe "invalid rules" do
        let(:ical_str) { "RRULE::A" }
        it_behaves_like "an invalid ical string"
      end

      describe "incomplete rule" do
        let(:ical_str) { "RRULE:FREQ" }
        it_behaves_like "an invalid ical string"
      end

      describe "invalid rule with invalid sensitive key" do
        let(:ical_str) { "RRULE:FREQ=WEKLY;WKST=SU" }
        it_behaves_like "an invalid ical string"
      end

      describe "invalid rule with invalid value" do
        let(:ical_str) { "RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;WKST=SE" }
        it_behaves_like "an invalid ical string"
      end

      describe "invalid rule with invalid key" do
        let(:ical_str) { "RRULE:FREQ=WEEKLY;BDAY=MO,WE,FR;WKST=SU" }
        it_behaves_like "an invalid ical string"
      end

      describe "invalid rule with attempt to execute code" do
        let(:ical_str) { "RRULE:FREQ=to_yaml" }
        it_behaves_like "an invalid ical string"
      end
    end

    describe "ical data with wrapping" do
      it "matches simple daily" do
        ical_string = "DTSTART:20130314T201500Z\nDTEND:20130314T201545Z\nRRULE:FREQ=WEEKLY;BYDAY=TH;UNT\n  IL=20130531T100000Z\nDESCRIPTION:This is a test event\nSUMMARY:Test Event\n"
        schedule = IceCube::Schedule.from_ical(ical_string)
        expect(schedule.to_ical.split("\n").find { |x| x =~ /RRULE/ }).to eq("RRULE:FREQ=WEEKLY;UNTIL=20130531T100000Z;BYDAY=TH")
      end
    end

    describe "custom VTIMEZONE rules" do
      let(:custom_vtimezone) do
        <<~ICAL
          BEGIN:VTIMEZONE
          TZID:Custom/TwoHour
          BEGIN:STANDARD
          DTSTART:19700601T000000
          TZOFFSETFROM:+0300
          TZOFFSETTO:+0200
          RRULE:FREQ=YEARLY;BYMONTH=6;BYMONTHDAY=1
          END:STANDARD
          BEGIN:DAYLIGHT
          DTSTART:19700101T000000
          TZOFFSETFROM:+0200
          TZOFFSETTO:+0300
          RRULE:FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1
          END:DAYLIGHT
          END:VTIMEZONE
        ICAL
      end

      it "round-trips a small custom DST calendar without machine zone dependence" do
        ical = custom_vtimezone + <<~ICAL
          DTSTART;TZID=Custom/TwoHour:20240115T100000
          RRULE:FREQ=DAILY;COUNT=169
          EXDATE;TZID=Custom/TwoHour:20240601T100000
          RDATE;TZID=Custom/TwoHour:20240630T100000
        ICAL

        schedule = IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)
        occurrences = schedule.all_occurrences

        expect {
          IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)
        }.not_to change { ENV["TZ"] }
        expect {
          Time.find_zone!("Custom/TwoHour")
        }.to raise_error(ArgumentError)
        expect(schedule.start_time).to eq(Time.new(2024, 1, 15, 10, 0, 0, "+03:00"))
        expect(schedule.start_time.dst?).to eq(true)
        expect(schedule.start_time.utc).to eq(Time.utc(2024, 1, 15, 7, 0, 0))
        expect(occurrences.first.utc).to eq(Time.utc(2024, 1, 15, 7, 0, 0))
        expect(occurrences.last).to eq(Time.new(2024, 7, 1, 10, 0, 0, "+02:00"))
        expect(occurrences.last.dst?).to eq(false)
        expect(occurrences.last.utc).to eq(Time.utc(2024, 7, 1, 8, 0, 0))
        expect(occurrences.count).to eq(168)
        expect(schedule.occurrences_between(Time.utc(2024, 5, 31, 6, 30), Time.utc(2024, 5, 31, 7, 30)).map(&:utc))
          .to eq([Time.utc(2024, 5, 31, 7)])
        expect(schedule.occurrences_between(Time.utc(2024, 6, 2, 7, 30), Time.utc(2024, 6, 2, 8, 30)).map(&:utc))
          .to eq([Time.utc(2024, 6, 2, 8)])
        expect(schedule.to_ical).to eq(<<~ICAL.chomp)
          DTSTART;TZID=Custom/TwoHour:20240115T100000
          RRULE:FREQ=DAILY;COUNT=169
          RDATE;TZID=Custom/TwoHour:20240630T100000
          EXDATE;TZID=Custom/TwoHour:20240601T100000
        ICAL
      end

      it "keeps floating and UTC times separate from TZID times" do
        ical = <<~ICAL
          DTSTART:20240301T090000
          RDATE:20240302T090000
          EXDATE:20240303T090000
          DTEND:20240301T100000Z
        ICAL

        schedule = IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)

        expect(schedule.start_time).to be_floating
        expect(schedule.start_time.utc_offset).to eq(0)
        expect(schedule.end_time).to be_utc
        expect(schedule.recurrence_times.first).to be_floating
        expect(schedule.exception_times.first).to be_floating
        expect(schedule.to_ical).to eq(ical.chomp)
      end

      it "raises for a TZID without a matching embedded VTIMEZONE" do
        ical = "DTSTART;TZID=Unknown/Zone:20240301T090000\n"

        expect {
          IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)
        }.to raise_error(ArgumentError, 'unknown TZID "Unknown/Zone"')
      end

      it "raises when an occurrence is outside the caller's year range" do
        ical = custom_vtimezone + "DTSTART;TZID=Custom/TwoHour:20250101T000000\n"

        expect {
          IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)
        }.to raise_error(ArgumentError, /only supported for years 2024 through 2024/)
      end

      it "raises for unsupported VTIMEZONE observations" do
        ical = <<~ICAL
          BEGIN:VTIMEZONE
          TZID:Custom/Bad
          BEGIN:STANDARD
          DTSTART:19700601T000000
          TZOFFSETFROM:+0300
          TZOFFSETTO:+0200
          RRULE:FREQ=MONTHLY;BYMONTH=6;BYMONTHDAY=1
          END:STANDARD
          BEGIN:DAYLIGHT
          DTSTART:19700101T000000
          TZOFFSETFROM:+0200
          TZOFFSETTO:+0300
          RRULE:FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1
          END:DAYLIGHT
          END:VTIMEZONE
          DTSTART;TZID=Custom/Bad:20240101T000000
        ICAL

        expect {
          IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)
        }.to raise_error(ArgumentError, /only supports yearly observations/)
      end

      it "raises for conflicting observations" do
        ical = <<~ICAL
          BEGIN:VTIMEZONE
          TZID:Custom/Conflict
          BEGIN:STANDARD
          DTSTART:19700101T000000
          TZOFFSETFROM:+0300
          TZOFFSETTO:+0200
          RRULE:FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1
          END:STANDARD
          BEGIN:DAYLIGHT
          DTSTART:19700101T000000
          TZOFFSETFROM:+0200
          TZOFFSETTO:+0300
          RRULE:FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1
          END:DAYLIGHT
          END:VTIMEZONE
          DTSTART;TZID=Custom/Conflict:20240101T000000
        ICAL

        expect {
          IceCube::Schedule.from_ical(ical, timezone_years: 2024..2024)
        }.to raise_error(ArgumentError, /conflicting observations/)
      end
    end
  end
end
