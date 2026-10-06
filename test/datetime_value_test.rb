require_relative "helper"
require "date"

class DatetimeValueTest < Minitest::Test
  def value_of(toml)
    TomlRB.parse("v = #{toml}")["v"]
  end

  def test_four_distinct_value_types
    parsed = TomlRB.parse(<<~TOML)
      odt = 1979-05-27T07:32:00Z
      ldt = 1979-05-27T07:32:00
      ld  = 1979-05-27
      lt  = 07:32:00
    TOML

    assert_instance_of(TomlRB::OffsetDateTime, parsed["odt"])
    assert_instance_of(TomlRB::LocalDateTime, parsed["ldt"])
    assert_instance_of(TomlRB::LocalDate, parsed["ld"])
    assert_instance_of(TomlRB::LocalTime, parsed["lt"])
    parsed.each_value do |value|
      refute_kind_of(Time, value)
    end
  end

  def test_components_are_exposed_without_a_time_zone
    ldt = value_of("1979-05-27T00:32:00.999999")
    components = [ldt.year, ldt.mon, ldt.day, ldt.hour, ldt.min, ldt.sec]
    assert_equal([1979, 5, 27, 0, 32, 0], components)
    assert_equal("999999", ldt.fraction)
    assert_equal(999_999r / 1_000_000, ldt.subsec)

    odt = value_of("1979-05-27T07:32Z")
    assert_nil(odt.sec)
    assert_nil(odt.fraction)
    assert_equal(0r, odt.subsec)
    assert_equal("Z", odt.offset)
    assert_equal(0, odt.utc_offset)
  end

  def test_long_fractional_seconds_keep_every_digit
    value = value_of("10:30:00.123456789012")
    assert_equal("123456789012", value.fraction)
    assert_equal(30_864_197_253r / 250_000_000_000, value.subsec)
    assert_equal("10:30:00.123456789012", value.to_s)

    ldt = value_of("2025-01-01T10:30:00.123456789012")
    assert_equal("2025-01-01T10:30:00.123456789012", ldt.to_s)

    odt = value_of("2025-01-01T10:30:00.000000000001-07:00")
    assert_equal("000000000001", odt.fraction)
    assert_equal("2025-01-01T10:30:00.000000000001-07:00", odt.to_s)
  end

  def test_local_values_require_a_zone_to_become_times
    ["1979-05-27T07:32:00", "1979-05-27", "07:32:00"].each do |toml|
      error = assert_raises(TomlRB::MissingTimeZoneError) { value_of(toml).to_time }
      assert_match(/zone/, error.message)
    end

    ldt = value_of("1979-05-27T07:32:00")
    assert_equal(Time.utc(1979, 5, 27, 7, 32, 0), ldt.to_time(zone: :utc))
    assert_equal(Time.new(1979, 5, 27, 7, 32, 0, "+09:00"), ldt.to_time(zone: "+09:00"))
    assert_equal(Time.new(1979, 5, 27, 7, 32, 0), ldt.to_time(zone: :local))

    ld = value_of("1979-05-27")
    assert_equal(Time.utc(1979, 5, 27), ld.to_time(zone: :utc))
    assert_equal(Date.new(1979, 5, 27), ld.to_date)

    lt = value_of("07:32:00")
    assert_equal(Time.utc(1979, 5, 27, 7, 32, 0),
      lt.to_time(date: Date.new(1979, 5, 27), zone: :utc))

    assert_raises(ArgumentError) { ldt.to_time(zone: ":30") }
  end

  def test_long_fractions_require_an_explicit_rounding_mode
    value = value_of("10:30:00.123456789012")
    assert_raises(TomlRB::PrecisionError) { value.to_time(zone: :utc) }
    assert_raises(ArgumentError) { value.to_time(zone: :utc, rounding: :nope) }
    assert_raises(ArgumentError) do
      value_of("10:30:00.5").to_time(zone: :utc, rounding: :nope)
    end

    assert_equal(Time.utc(1970, 1, 1, 10, 30, 0, 123_456_789r / 1000),
      value.to_time(zone: :utc, rounding: :truncate))
    assert_equal(Time.utc(1970, 1, 1, 10, 30, 0, 123_456_790r / 1000),
      value.to_time(zone: :utc, rounding: :ceil))
    assert_equal(Time.utc(1970, 1, 1, 10, 30, 0, 123_456_789r / 1000),
      value.to_time(zone: :utc, rounding: :round))
  end

  def test_ceil_rounding_can_carry_into_the_next_second_minute_hour_and_day
    carried = value_of("23:59:59.99999999999")
    assert_equal(Time.utc(1970, 1, 2, 0, 0, 0), carried.to_time(zone: :utc, rounding: :ceil))
    assert_equal(Time.utc(1970, 1, 1, 23, 59, 59, 999_999_999r / 1000),
      carried.to_time(zone: :utc, rounding: :floor))

    offset = value_of("2020-02-29T23:59:59.99999999999+09:00")
    assert_equal(Time.new(2020, 3, 1, 0, 0, 0, "+09:00"), offset.to_time(rounding: :ceil))
  end

  def test_offset_datetimes_convert_in_their_declared_offset
    odt = value_of("1979-05-27T00:32:00.999999-07:00")
    time = odt.to_time
    assert_instance_of(Time, time)
    assert_equal(-25_200, time.utc_offset)
    assert_equal(Time.utc(1979, 5, 27, 7, 32, 0, 999_999), time.getutc)
  end

  def test_offsets_that_cross_midnight_stay_the_same_instant
    ahead = value_of("2020-03-01T01:30:00+09:00")
    behind = value_of("2020-02-29T16:30:00Z")
    assert_equal(ahead, behind)
    assert_equal(ahead.to_time.getutc, behind.to_time)

    west = value_of("2020-02-29T23:00:00-05:00")
    assert_equal(Time.utc(2020, 3, 1, 4, 0, 0), west.to_time.getutc)
  end

  def test_comparisons_never_treat_local_values_as_utc
    local = value_of("1979-05-27T07:32:00")
    utc = value_of("1979-05-27T07:32:00Z")
    refute_equal(local, utc)
    refute_equal(local, Time.utc(1979, 5, 27, 7, 32, 0))
    assert_nil(local <=> utc)
    assert_raises(ArgumentError) { local < utc }

    earlier = value_of("2020-02-29T23:59:59")
    later = value_of("2020-03-01T00:00:00")
    assert(earlier < later)
    assert_equal([earlier, later], [later, earlier].sort)

    assert(value_of("2000-02-29") < value_of("2000-03-01"))
    assert(value_of("07:32:00.5") < value_of("07:32:00.500000001"))
    assert_equal(value_of("07:32:00.999"), value_of("07:32:00.999000"))
  end

  def test_offset_comparison_uses_the_instant_but_eql_keeps_identity
    plus = value_of("2020-03-01T02:30:00+09:00")
    minus = value_of("2020-03-01T01:30:00+08:00")
    assert_equal(0, plus <=> minus)
    assert_equal(plus, minus)
    refute(plus.eql?(minus))
    refute_equal(plus.hash, minus.hash)
  end

  def test_values_work_as_hash_keys
    a = value_of("1979-05-27")
    b = value_of("1979-05-27")
    hash = {a => 1}
    hash[b] = 2
    assert_equal(1, hash.size)
    assert_equal(2, hash[a])
  end

  def test_round_trip_preserves_exact_spelling
    [
      "odt = 1979-05-27T07:32:00Z\n",
      "odt = 2020-02-29T01:30:00+09:00\n",
      "odt = 2020-02-29T23:00:00-05:00\n",
      "long = 2020-02-29T23:59:59.123456789012345+09:00\n",
      "ldt = 1979-05-27T07:32\n",
      "ldt = 2020-02-29T00:32:00.000000000001\n",
      "ld = 2000-02-29\n",
      "lt = 00:32\n",
      "lt = 00:32:00.123456789012\n"
    ].each do |toml|
      parsed = TomlRB.parse(toml)
      assert_equal(toml, TomlRB.dump(parsed), toml)
      assert_equal(parsed, TomlRB.parse(TomlRB.dump(parsed)), toml)
    end
  end

  def test_leap_days
    assert_instance_of(TomlRB::LocalDate, value_of("2000-02-29"))
    assert_instance_of(TomlRB::LocalDate, value_of("2020-02-29"))
    ["2100-02-29", "2100-02-29T12:00:00", "2019-02-29"].each do |toml|
      assert_raises(TomlRB::ParseError) { value_of(toml) }
    end

    leap = value_of("2016-12-31T23:59:60.5Z")
    assert_equal(Time.utc(2017, 1, 1, 0, 0, 0.5r), leap.to_time)
  end

  def test_default_reading_interface_is_unchanged
    parsed = TomlRB.parse("d = 1979-05-27", symbolize_keys: true)
    assert_equal({d: TomlRB::LocalDate.new(1979, 5, 27)}, parsed)
    assert_instance_of(Hash, TomlRB.parse("a = 1"))
  end
end
