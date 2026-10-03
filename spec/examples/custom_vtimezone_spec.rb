require "spec_helper"

describe IceCube, "custom VTIMEZONE" do
  let(:ical) do
    <<~ICAL
      BEGIN:VTIMEZONE
      TZID:Custom/Daylight
      BEGIN:STANDARD
      DTSTART:19701101T020000
      RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU
      TZOFFSETFROM:-0100
      TZOFFSETTO:-0200
      END:STANDARD
      BEGIN:DAYLIGHT
      DTSTART:19700308T020000
      RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
      TZOFFSETFROM:-0200
      TZOFFSETTO:-0100
      END:DAYLIGHT
      END:VTIMEZONE
      DTSTART;TZID=Custom/Daylight:20200301T090000
      RRULE:FREQ=DAILY;COUNT=276
    ICAL
  end

  let(:floating_ical) do
    <<~ICAL
      DTSTART:20200301T090000
      RRULE:FREQ=DAILY;COUNT=2
    ICAL
  end

  let(:utc_ical) do
    <<~ICAL
      DTSTART:20200301T120000Z
      RRULE:FREQ=DAILY;COUNT=2
    ICAL
  end

  it "parses and exports a small daylight-saving calendar without process TZ" do
    schedule = IceCube::Schedule.from_ical(ical, years: 2020..2020)
    occurrences = schedule.occurrences_between(schedule.start_time, Time.utc(2021, 1, 1))

    expect(schedule.start_time).to be_a(IceCube::LocalTime)
    expect(schedule.start_time.utc).to eq(Time.utc(2020, 3, 1, 11))
    expect(occurrences[6].utc).to eq(Time.utc(2020, 3, 7, 11))
    expect(occurrences[7].utc).to eq(Time.utc(2020, 3, 8, 10))
    expect(occurrences[244].utc).to eq(Time.utc(2020, 10, 31, 10))
    expect(occurrences[245].utc).to eq(Time.utc(2020, 11, 1, 11))
    expect(occurrences.size).to eq(276)
    expect(schedule.to_ical).to eq(ical.chomp)
  end

  it "round-trips without relying on the machine time zone" do
    schedule = IceCube::Schedule.from_ical(ical, years: 2020..2020)
    round_trip = IceCube::Schedule.from_ical(schedule.to_ical, years: 2020..2020)
    closing_time = Time.utc(2021, 1, 1)

    expect(round_trip.start_time).to eq(schedule.start_time)
    expect(round_trip.occurrences_between(round_trip.start_time, closing_time)).to eq(
      schedule.occurrences_between(schedule.start_time, closing_time)
    )
  end

  it "keeps floating times separate from UTC and TZID times" do
    floating = IceCube::Schedule.from_ical(floating_ical, years: 2020..2020)
    utc_schedule = IceCube::Schedule.from_ical(utc_ical, years: 2020..2020)

    expect(floating.start_time).to be_a(IceCube::FloatingTime)
    expect(floating.start_time.utc?).to eq(false)
    expect(floating.start_time).to eq(Time.utc(2020, 3, 1, 9))
    expect(floating.to_ical).to eq(floating_ical.chomp)

    expect(utc_schedule.start_time).to be_a(Time)
    expect(utc_schedule.start_time).not_to be_a(IceCube::FloatingTime)
    expect(utc_schedule.start_time.utc?).to eq(true)
  end

  it "allows query boundaries to fall in adjacent years but rejects out-of-range occurrences" do
    schedule = IceCube::Schedule.from_ical(ical, years: 2020..2020)
    unbounded_ical = ical.sub("RRULE:FREQ=DAILY;COUNT=276", "RRULE:FREQ=DAILY")
    unbounded = IceCube::Schedule.from_ical(unbounded_ical, years: 2020..2020)

    expect(schedule.occurrences_between(Time.utc(2019, 12, 31), Time.utc(2020, 3, 2))).to eq([schedule.start_time])
    expect {
      unbounded.occurrences_between(Time.utc(2020, 12, 31), Time.utc(2021, 1, 5))
    }.to raise_error(IceCube::LocalTimeZone::UnsupportedYearError, /2021/)
  end

  it "validates the supplied range for UTC and floating times" do
    expect {
      IceCube::Schedule.from_ical(utc_ical, years: 2019..2019)
    }.to raise_error(IceCube::LocalTimeZone::UnsupportedYearError, /2020/)
    expect {
      IceCube::Schedule.from_ical(floating_ical, years: 2019..2019)
    }.to raise_error(IceCube::LocalTimeZone::UnsupportedYearError, /2020/)
  end

  it "raises when a referenced year is outside the supplied range" do
    expect {
      IceCube::Schedule.from_ical(ical, years: 2021..2021)
    }.to raise_error(IceCube::LocalTimeZone::UnsupportedYearError, /2020.*2021..2021/)
  end

  it "raises for an unknown TZID" do
    unknown = ical.sub("DTSTART;TZID=Custom/Daylight", "DTSTART;TZID=Missing/Zone")

    expect {
      IceCube::Schedule.from_ical(unknown, years: 2020..2020)
    }.to raise_error(IceCube::LocalTimeZone::InvalidTimezoneError, /unknown TZID/)
  end

  it "raises for unsupported VTIMEZONE observation rules" do
    unsupported = ical.sub("FREQ=YEARLY;BYMONTH=11;BYDAY=1SU", "FREQ=YEARLY;INTERVAL=2;BYMONTH=11;BYDAY=1SU")

    expect {
      IceCube::Schedule.from_ical(unsupported, years: 2020..2020)
    }.to raise_error(IceCube::LocalTimeZone::InvalidTimezoneError, /only yearly/)
  end

  it "raises for conflicting offset observations" do
    conflicting = ical.sub("TZOFFSETFROM:-0100\nTZOFFSETTO:-0200", "TZOFFSETFROM:-0100\nTZOFFSETTO:-0300")

    expect {
      IceCube::Schedule.from_ical(conflicting, years: 2020..2020)
    }.to raise_error(IceCube::LocalTimeZone::InvalidTimezoneError, /conflicting VTIMEZONE offsets/)
  end

  it "raises for nonexistent and ambiguous local times" do
    spring_target = "DTSTART;TZID=Custom/Daylight:20200308T023000"
    spring_gap = ical.sub("DTSTART;TZID=Custom/Daylight:20200301T090000", spring_target)
    fall_back = ical.sub("DTSTART;TZID=Custom/Daylight:20200301T090000", "DTSTART;TZID=Custom/Daylight:20201101T013000")

    expect {
      IceCube::Schedule.from_ical(spring_gap, years: 2020..2020)
    }.to raise_error(IceCube::LocalTimeZone::InvalidTimezoneError, /does not exist/)
    expect {
      IceCube::Schedule.from_ical(fall_back, years: 2020..2020)
    }.to raise_error(IceCube::LocalTimeZone::InvalidTimezoneError, /ambiguous/)
  end
end
