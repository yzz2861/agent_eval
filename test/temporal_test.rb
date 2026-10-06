require_relative "helper"
require "tempfile"

class TemporalTest < Minitest::Test
  def test_exact_mode_keeps_the_four_toml_temporal_kinds
    parsed = TomlRB.parse(TEMPORAL_TOML, exact_time_values: true)

    assert_instance_of TomlRB::Temporal::OffsetDateTime, parsed["odt"]
    assert_instance_of TomlRB::Temporal::LocalDateTime, parsed["ldt"]
    assert_instance_of TomlRB::Temporal::LocalDate, parsed["ld"]
    assert_instance_of TomlRB::Temporal::LocalTime, parsed["lt"]
  end

  def test_exact_mode_preserves_long_fractional_seconds_and_trailing_zeroes
    parsed = TomlRB.parse(LONG_FRACTION_TOML, exact_time_values: true)

    assert_equal 15, parsed["odt"].fraction_digits
    assert_equal Rational("0.123456789012345"), parsed["odt"].fractional_seconds
    assert_equal 15, parsed["ldt"].fraction_digits
    assert_equal Rational("0.123456789012345"), parsed["ldt"].fractional_seconds
    assert_equal 15, parsed["lt"].fraction_digits
    assert_equal Rational("0.123456789012345"), parsed["lt"].fractional_seconds

    short = TomlRB.parse("v = 10:30:00.00100", exact_time_values: true)["v"]
    assert_equal "10:30:00.00100", short.to_s
    assert_equal Rational("0.00100"), short.fractional_seconds
  end

  def test_exact_mode_round_trips_long_fractions_offsets_and_leap_day
    [
      "odt = 2024-02-29T23:59:59.123456789012345-05:00\n",
      "odt = 2024-02-29T23:59:59.123456789012345Z\n",
      "ldt = 2024-02-29T23:59:59.123456789012345\n",
      "ld = 2024-02-29\n",
      "lt = 23:59:59.123456789012345\n",
      "minute = 2024-02-29T10:30Z\n"
    ].each do |toml|
      parsed = TomlRB.parse(toml, exact_time_values: true)
      assert_equal toml, TomlRB.dump(parsed)
    end
    assert_raises(TomlRB::ParseError) do
      TomlRB.parse("ld = 2023-02-29", exact_time_values: true)
    end
  end

  def test_offset_values_convert_explicitly_and_compare_absolute_instants
    earlier = TomlRB.parse("v = 2024-02-29T23:30:00-05:00", exact_time_values: true)["v"]
    later = TomlRB.parse("v = 2024-03-01T10:30:00+05:00", exact_time_values: true)["v"]

    assert_equal(-1, earlier <=> later)
    assert_equal 1, later <=> earlier
    refute_equal earlier, later

    time = earlier.to_time(precision: 9, rounding: :raise)
    assert_instance_of Time, time
    assert_equal "-05:00", time.strftime("%:z")
    assert_equal Time.utc(2024, 3, 1, 4, 30, 0), time.getutc
    assert_equal time, earlier
    assert_equal earlier, time
    assert_equal time.hash, earlier.hash
    assert_equal 1, {time => :time, earlier => :temporal}.size
  end

  def test_explicit_conversion_requires_a_rounding_policy_for_sub_nanosecond_values
    value = TomlRB.parse("v = 2024-02-29T23:59:59.123456789012345Z", exact_time_values: true)["v"]

    assert_raises(ArgumentError) { value.to_time(precision: 12, rounding: :raise) }

    down = value.to_time(precision: 9, rounding: :down)
    assert_equal Time.utc(2024, 2, 29, 23, 59, Rational(59_123_456_789, 1_000_000_000)), down

    round_up = TomlRB.parse("v = 2024-02-29T23:59:59.600000000000000Z", exact_time_values: true)["v"]
    nearest = round_up.to_time(precision: 0, rounding: :nearest)
    assert_equal Time.utc(2024, 3, 1, 0, 0, 0), nearest
  end

  def test_local_values_require_a_time_zone_for_time_conversion
    parsed = TomlRB.parse(LOCAL_CONVERSION_TOML, exact_time_values: true)

    assert_raises(ArgumentError) { parsed["ldt"].to_time(precision: 9, rounding: :raise) }
    assert_raises(ArgumentError) { parsed["odt"].to_time(precision: 9) }
    assert_raises(ArgumentError) { parsed["ldt"].to_time(timezone: "Z", precision: 9) }
    assert_raises(ArgumentError) { parsed["ldt"].to_time(timezone: false, precision: 9, rounding: :raise) }

    ldt = parsed["ldt"].to_time(timezone: "+02:00", precision: 9, rounding: :down)
    assert_equal Time.new(2024, 2, 29, 23, 59, Rational(59_123_456_789, 1_000_000_000), "+02:00"), ldt

    date = parsed["ld"].to_time(timezone: "Z", precision: 9, rounding: :raise)
    assert_equal Time.utc(2024, 2, 29, 0, 0, 0), date

    time = parsed["lt"].to_time(timezone: "Z", precision: 0, rounding: :up)
    assert_equal Time.utc(1970, 1, 1, 0, 0, 0), time
  end

  def test_local_values_are_not_compared_or_converted_as_utc
    parsed = TomlRB.parse(LOCAL_CONVERSION_TOML, exact_time_values: true)
    ldt = parsed["ldt"]
    utc_time = Time.utc(2024, 2, 29, 23, 59, Rational(59_123_456_789, 1_000_000_000))

    assert_nil ldt <=> utc_time
    assert_nil utc_time <=> ldt
    refute_equal ldt, utc_time
    refute_equal utc_time, ldt
    assert_nil parsed["ld"] <=> parsed["ldt"]
    assert_nil parsed["lt"] <=> ldt
  end

  def test_local_values_compare_by_wall_time_without_zone_assumptions
    earlier = TomlRB.parse("v = 2024-02-29T23:59:59.123456789012345", exact_time_values: true)["v"]
    later = TomlRB.parse("v = 2024-03-01T00:00:00", exact_time_values: true)["v"]

    assert_equal(-1, earlier <=> later)
    assert_equal [earlier, later], [later, earlier].sort
  end

  def test_explicit_conversion_preserves_a_leap_second_wall_time
    parsed = TomlRB.parse("v = 2016-12-31T23:59:60.5Z", exact_time_values: true)["v"]
    time = parsed.to_time(precision: 9, rounding: :down)

    assert_equal "2016-12-31 23:59:60.5 UTC", time.inspect
    assert_equal 60, time.sec
    assert_equal Time.utc(2017, 1, 1, 0, 0, Rational(5, 10)), time.getutc
  end

  def test_dates_use_the_proleptic_gregorian_calendar
    assert_raises(TomlRB::ParseError) do
      TomlRB.parse("v = 1500-02-29T00:00:00Z", exact_time_values: true)
    end

    value = TomlRB.parse("v = 1500-02-28T23:59:59Z", exact_time_values: true)["v"]
    assert_equal Time.utc(1500, 2, 28, 23, 59, 59), value.to_time(precision: 9, rounding: :raise)
  end

  def test_default_reading_interface_remains_time_based_and_compatible
    parsed = TomlRB.parse(LONG_FRACTION_TOML)

    assert_instance_of Time, parsed["odt"]
    assert_instance_of TomlRB::LocalDateTime, parsed["ldt"]
    assert_instance_of TomlRB::LocalDate, parsed["ld"]
    assert_instance_of TomlRB::LocalTime, parsed["lt"]
    refute_kind_of TomlRB::Temporal::Value, parsed["odt"]
    assert_equal 123_456_789, parsed["odt"].nsec
    assert_equal 123_456_789, parsed["ldt"].nsec
    assert_equal 123_456_789, parsed["lt"].nsec

    expected = <<~TOML
      ld = 2024-02-29
      ldt = 2024-02-29T23:59:59.123456789
      lt = 23:59:59.123456789
      odt = 2024-02-29T23:59:59.123456789Z
    TOML
    assert_equal expected, TomlRB.dump(parsed)
  end

  def test_load_file_accepts_the_exact_time_option
    Tempfile.create(["temporal", ".toml"]) do |file|
      file.write(TEMPORAL_TOML)
      file.flush

      parsed = TomlRB.load_file(file.path, exact_time_values: true)
      assert_instance_of TomlRB::Temporal::OffsetDateTime, parsed["odt"]
    end
  end

  TEMPORAL_TOML = <<~TOML
    odt = 2024-02-29T23:59:59.123456789012345Z
    ldt = 2024-02-29T23:59:59.123456789012345
    ld = 2024-02-29
    lt = 23:59:59.123456789012345
  TOML

  LONG_FRACTION_TOML = <<~TOML
    odt = 2024-02-29T23:59:59.123456789012345Z
    ldt = 2024-02-29T23:59:59.123456789012345
    ld = 2024-02-29
    lt = 23:59:59.123456789012345
  TOML

  LOCAL_CONVERSION_TOML = <<~TOML
    odt = 2024-02-29T23:59:59.123456789012345Z
    ldt = 2024-02-29T23:59:59.123456789012345
    ld = 2024-02-29
    lt = 23:59:59.123456789012345
  TOML
end
