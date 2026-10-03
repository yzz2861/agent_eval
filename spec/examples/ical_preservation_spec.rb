require File.dirname(__FILE__) + "/../spec_helper"

module IceCube
  describe Schedule, "ical preservation" do
    let(:ical_with_vendor_properties) do
      [
        "DTSTART:20130314T201500Z",
        "DTEND:20130314T201545Z",
        "RRULE:FREQ=WEEKLY;BYDAY=TH;UNTIL=20130531T100000Z",
        "X-WR-CALNAME;CN=zh:团队日历",
        'X-VENDOR-THING;P1="quoted;value:with";P2=alpha\,beta,gamma:VALUE',
        "X-REPEATED:first",
        "X-REPEATED:second",
        'DESCRIPTION:周会\n含中文说明与转义逗号\, 以及换行'
      ].join("\n")
    end

    it "preserves unrecognized content lines and their parameters on a round trip" do
      schedule = Schedule.from_ical(ical_with_vendor_properties, preserve: true)
      output = schedule.to_ical
      expect(output).to include("X-WR-CALNAME;CN=zh:团队日历")
      expect(output).to include('X-VENDOR-THING;P1="quoted;value:with";P2=alpha\,beta,gamma:VALUE')
      expect(output).to include('DESCRIPTION:周会\n含中文说明与转义逗号\, 以及换行')
    end

    it "keeps repeated extension properties in their original order" do
      schedule = Schedule.from_ical(ical_with_vendor_properties, preserve: true)
      repeats = schedule.to_ical.split("\n").grep(/\AX-REPEATED/)
      expect(repeats).to eq(["X-REPEATED:first", "X-REPEATED:second"])
    end

    it "emits preserved properties after the modeled ones in input order" do
      schedule = Schedule.from_ical(ical_with_vendor_properties, preserve: true)
      lines = schedule.to_ical.split("\n")
      expect(lines.first).to start_with("DTSTART")
      rrule = lines.index { |l| l.start_with?("RRULE") }
      dtend = lines.index { |l| l.start_with?("DTEND") }
      calname = lines.index { |l| l.start_with?("X-WR-CALNAME") }
      vendor = lines.index { |l| l.start_with?("X-VENDOR-THING") }
      expect(rrule).to be < dtend
      expect(dtend).to be < calname
      expect(calname).to be < vendor
    end

    it "keeps vendor properties when a recurrence rule is modified" do
      schedule = Schedule.from_ical(ical_with_vendor_properties, preserve: true)
      schedule.remove_recurrence_rule(schedule.recurrence_rules.first)
      schedule.add_recurrence_rule(IceCube::Rule.daily.count(3))
      output = schedule.to_ical
      expect(output).to include("RRULE:FREQ=DAILY;COUNT=3")
      expect(output).to include("X-WR-CALNAME;CN=zh:团队日历")
      expect(output).to include("X-REPEATED:second")
    end

    it "does not treat a folded continuation as a new property" do
      folded = "DTSTART:20130314T201500Z\nX-LONG-PROP:第一部分\n 第二部分\n\t第三部分\nRRULE:FREQ=DAILY"
      schedule = Schedule.from_ical(folded, preserve: true)
      preserved = schedule.preserved_ical_properties
      expect(preserved.length).to eq(1)
      expect(preserved.first.name).to eq("X-LONG-PROP")
      expect(preserved.first.value).to eq("第一部分第二部分第三部分")
      expect(schedule.recurrence_rules.length).to eq(1)
    end

    it "handles CRLF line endings when unfolding" do
      schedule = Schedule.from_ical("DTSTART:20130314T201500Z\r\nX-A:one\r\n two\r\n", preserve: true)
      expect(schedule.preserved_ical_properties.first.value).to eq("onetwo")
    end

    it "folds long lines at 75 octets without splitting UTF-8 characters" do
      long_value = "很长的中文说明" * 20
      ical = "DTSTART:20130314T201500Z\nX-CHINESE:#{long_value}"
      schedule = Schedule.from_ical(ical, preserve: true)
      physical_lines = schedule.to_ical.split("\n")
      expect(physical_lines.length).to be > 2
      physical_lines.each do |line|
        expect(line.bytesize).to be <= 75
        expect(line.valid_encoding?).to be(true)
      end
      reparsed = Schedule.from_ical(schedule.to_ical, preserve: true)
      expect(reparsed.preserved_ical_properties.first.value).to eq(long_value)
    end

    it "parses quoted and escaped parameter values without corrupting them" do
      schedule = Schedule.from_ical(ical_with_vendor_properties, preserve: true)
      vendor = schedule.preserved_ical_properties.find { |p| p.name == "X-VENDOR-THING" }
      expect(vendor.params["P1"]).to eq(['"quoted;value:with"'])
      expect(vendor.params["P2"]).to eq(["alpha\\,beta", "gamma"])
      expect(vendor.to_s).to eq('X-VENDOR-THING;P1="quoted;value:with";P2=alpha\,beta,gamma:VALUE')
    end

    it "raises an error with the line number for malformed content" do
      ical = "DTSTART:20130314T201500Z\nX-BROKEN\nRRULE:FREQ=DAILY"
      expect { Schedule.from_ical(ical, preserve: true) }.to raise_error(InvalidIcalError, /line 2/)
    end

    it "raises an error with the position for an unterminated quote" do
      ical = 'X-BAD;P="oops:value'
      expect { Schedule.from_ical(ical, preserve: true) }.to raise_error(InvalidIcalError, /line 1, position 8/)
    end

    it "exposes line_number and position on the error" do
      error = nil
      begin
        Schedule.from_ical("DTSTART:20130314T201500Z\nGARBAGE", preserve: true)
      rescue InvalidIcalError => e
        error = e
      end
      expect(error.line_number).to eq(2)
      expect(error.position).to be_a(Integer)
    end

    it "still offers the plain concise output with preserve: false" do
      schedule = Schedule.from_ical(ical_with_vendor_properties, preserve: true)
      plain = schedule.to_ical(preserve: false)
      expect(plain).not_to include("X-WR-CALNAME")
      expect(plain).not_to include("DESCRIPTION")
      expect(plain.split("\n")).to eq([
        "DTSTART:20130314T201500Z",
        "RRULE:FREQ=WEEKLY;UNTIL=20130531T100000Z;BYDAY=TH",
        "DTEND:20130314T201545Z"
      ])
    end

    it "leaves default parsing and output untouched without the preserve option" do
      schedule = Schedule.from_ical(ical_with_vendor_properties)
      expect(schedule.preserved_ical_properties).to be_nil
      expect(schedule.to_ical.split("\n")).to eq([
        "DTSTART:20130314T201500Z",
        "RRULE:FREQ=WEEKLY;UNTIL=20130531T100000Z;BYDAY=TH",
        "DTEND:20130314T201545Z"
      ])
    end

    it "keeps EXRULE lines as preserved properties" do
      schedule = Schedule.from_ical("DTSTART:20130314T201500Z\nEXRULE:FREQ=WEEKLY;COUNT=2", preserve: true)
      expect(schedule.to_ical).to include("EXRULE:FREQ=WEEKLY;COUNT=2")
    end
  end
end
