require File.dirname(__FILE__) + "/../spec_helper"

describe IceCube, "iCalendar preservation mode" do
  it "preserves vendor lines, duplicate extensions, parameters and rule components" do
    ical = <<~ICAL
      BEGIN:VCALENDAR
      VERSION:2.0
      PRODID:test
      BEGIN:VEVENT
      UID:event-1
      DTSTART;X-VENDOR-CAT="中文,说明":20260101T090000Z
      RRULE;X-VENDOR-ROOM="会议室\\,A\\,一号":FREQ=WEEKLY;INTERVAL=1;X-VENDOR-COLOR=blue;X-VENDOR-TAG=中文
      X-VENDOR-REPEAT:first
      X-VENDOR-REPEAT:second
      DESCRIPTION:中文说明，里面的逗号不是分隔符，\\n也不是新属性
      END:VEVENT
      END:VCALENDAR
    ICAL
    schedule = IceCube::Schedule.from_ical(ical, preserve: true)
    schedule.recurrence_rules.first.interval(2)

    exported = schedule.to_ical(preserve: true)
    lines = exported.split("\n")

    unfolded_export = exported.gsub(/\r?\n[ \t]/, "")
    expect(unfolded_export).to include("RRULE;X-VENDOR-ROOM=\"会议室\\,A\\,一号\":FREQ=WEEKLY;INTERVAL=2;WKST=SU;X-VENDOR-COLOR=blue;X-VENDOR-TAG=中文")
    expect(unfolded_export).to include("DTSTART;X-VENDOR-CAT=\"中文,说明\":20260101T090000Z")
    expect(unfolded_export).to include("X-VENDOR-REPEAT:first")
    expect(unfolded_export).to include("X-VENDOR-REPEAT:second")
    expect(unfolded_export).to include("DESCRIPTION:中文说明，里面的逗号不是分隔符，\\n也不是新属性")
    expect(lines).to include("BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:test", "BEGIN:VEVENT", "UID:event-1")
    expect(lines.index("BEGIN:VEVENT")).to be < lines.index("UID:event-1")
    expect(lines.index { |line| line.start_with?("DTSTART;") }).to be < lines.index { |line| line.start_with?("RRULE;") }
    expect(lines.index { |line| line.start_with?("DESCRIPTION:") || line.start_with?(" ") }).to be < lines.index("END:VEVENT")
    ordered_subset = unfolded_export.split("\n").select do |line|
      line.start_with?("BEGIN:", "VERSION:", "PRODID:", "UID:", "DTSTART;", "RRULE;", "X-VENDOR-REPEAT:", "DESCRIPTION:", "END:")
    end
    expect(ordered_subset).to eq([
      "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:test", "BEGIN:VEVENT", "UID:event-1",
      "DTSTART;X-VENDOR-CAT=\"中文,说明\":20260101T090000Z",
      "RRULE;X-VENDOR-ROOM=\"会议室\\,A\\,一号\":FREQ=WEEKLY;INTERVAL=2;WKST=SU;X-VENDOR-COLOR=blue;X-VENDOR-TAG=中文",
      "X-VENDOR-REPEAT:first", "X-VENDOR-REPEAT:second",
      "DESCRIPTION:中文说明，里面的逗号不是分隔符，\\n也不是新属性",
      "END:VEVENT", "END:VCALENDAR"
    ])
  end

  it "keeps rule extensions only in the selected rule output mode" do
    rule = IceCube::Rule.from_ical("FREQ=DAILY;INTERVAL=1;X-VENDOR-SOURCE=calendar", preserve: true)
    rule.interval(3)

    expect(rule.to_ical(true)).to eq("FREQ=DAILY;INTERVAL=3;X-VENDOR-SOURCE=calendar")
    expect(rule.to_ical(false)).to eq("FREQ=DAILY;INTERVAL=3")
    expect(rule.to_ical).to eq("FREQ=DAILY;INTERVAL=3")
  end

  it "round trips rule extension metadata and params through YAML" do
    rule = IceCube::Rule.from_ical(
      "FREQ=DAILY;INTERVAL=2;X-VENDOR-SOURCE=calendar",
      preserve: true
    )
    ical = 'RRULE;X-VENDOR-ROOM="会议室\,一号":' + rule.to_ical(true)
    rule = IceCube::Schedule.from_ical(ical, preserve: true).recurrence_rules.first

    restored = IceCube::Rule.from_yaml(rule.to_yaml)
    expect(restored.to_ical(true)).to eq("FREQ=DAILY;INTERVAL=2;X-VENDOR-SOURCE=calendar")
    expect(restored.to_ical(false)).to eq("FREQ=DAILY;INTERVAL=2")
  end

  it "can still choose the normal compact representation" do
    ical = <<~ICAL
      BEGIN:VEVENT
      DTSTART:20260101T090000Z
      RRULE;X-VENDOR-ROOM="会议室":FREQ=WEEKLY;INTERVAL=1;X-VENDOR-COLOR=blue
      X-VENDOR-REPEAT:first
      END:VEVENT
    ICAL

    schedule = IceCube::Schedule.from_ical(ical, preserve: true)
    expect(schedule.to_ical).to include("X-VENDOR-ROOM")
    expect(schedule.to_ical(preserve: false)).to eq(
      "DTSTART:20260101T090000Z\nRRULE:FREQ=WEEKLY"
    )
  end

  it "keeps vendor parameters on model-managed time properties" do
    ical = <<~ICAL
      BEGIN:VEVENT
      DTSTART;TZID=America/Denver;X-VENDOR-CAT="中文,说明":20260101T090000
      EXDATE;TZID=America/Denver;X-VENDOR-REASON="不参加\,改期":20260102T090000
      END:VEVENT
    ICAL

    schedule = IceCube::Schedule.from_ical(ical, preserve: true)
    exported = schedule.to_ical(preserve: true)

    expect(exported).to include("X-VENDOR-CAT=\"中文,说明\"")
    expect(exported).to include("EXDATE;TZID=")
    expect(exported).to include("X-VENDOR-REASON=\"不参加,改期\"")
  end

  it "unfolds and refolds without splitting a UTF-8 character" do
    chinese = "中文说明" * 25
    continuation = chinese.each_char.each_slice(24).map(&:join).join("\n ")
    ical = "BEGIN:VEVENT\nDTSTART:20260101T090000Z\nX-VENDOR-NOTE:" << continuation << "\nEND:VEVENT\n"

    schedule = IceCube::Schedule.from_ical(ical, preserve: true)
    exported = schedule.to_ical(preserve: true)
    unfolded = exported.gsub(/\r?\n[ \t]/, "")

    expect(unfolded).to include("X-VENDOR-NOTE:#{chinese}")
    exported.split("\n").each do |line|
      expect(line.bytesize).to be <= 75
    end
    exported.gsub(/\r?\n[ \t]/, "").each_char.with_index do |_char, _index|
      expect(exported.dup.force_encoding("UTF-8")).to be_valid_encoding
    end
  end

  it "reports positions for malformed content lines and unclosed components" do
    malformed_parameter = "BEGIN:VEVENT\nRRULE;X-VENDOR-ROOM=:FREQ=WEEKLY\nEND:VEVENT\n"
    expect {
      IceCube::Schedule.from_ical(malformed_parameter, preserve: true)
    }.to raise_error(IceCube::IcalParser::ParseError, /line 2, column 20/)

    unclosed = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART:20260101T090000Z\n"
    expect {
      IceCube::Schedule.from_ical(unclosed, preserve: true)
    }.to raise_error(IceCube::IcalParser::ParseError, /unclosed VEVENT.*line 2, column 1/)
  end

  it "does not split escaped commas in values and reports invalid UTF-8" do
    ical = 'BEGIN:VEVENT
RDATE;X-VENDOR-NAME="供应商:\,日期":20260101T090000Z\,20260102T090000Z
END:VEVENT'
    schedule = IceCube::Schedule.from_ical(ical, preserve: true)
    expect(schedule.recurrence_times.count).to eq(1)

    invalid_utf8 = (["BEGIN:VEVENT\nX-VENDOR-NOTE:".b, "\xe4".b, "\n ".b, "\xb8".b, "\nEND:VEVENT\n".b]).join
    expect {
      IceCube::Schedule.from_ical(invalid_utf8, preserve: true)
    }.to raise_error(IceCube::IcalParser::ParseError, /Invalid UTF-8 sequence.*line 2, column 1/)
  end
end
