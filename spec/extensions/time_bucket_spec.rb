# frozen_string_literal: true
require_relative "spec_helper"

describe "time_bucket extension" do
  before(:all) do
    Sequel.extension :time_bucket
  end

  before do
    @origin = Time.utc(2024, 1, 1, 0, 7, 30)
  end

  it "creates separate fixed-second and calendar-month expressions" do
    seconds = Sequel.time_bucket(:created_at, 900)
    months = Sequel.month_bucket(:created_at, 3)

    seconds.must_be_kind_of Sequel::SQL::TimeBucket::Seconds
    months.must_be_kind_of Sequel::SQL::TimeBucket::Months
    seconds.interval.must_equal 900
    months.interval.must_equal 3
  end

  it "provides explicitly named fixed-second and calendar-month aliases" do
    Sequel.fixed_seconds_bucket(:created_at, 900).must_be_kind_of Sequel::SQL::TimeBucket::Seconds
    Sequel.calendar_month_bucket(:created_at, 3).must_be_kind_of Sequel::SQL::TimeBucket::Months
  end

  it "rejects non-integer and non-positive intervals without accepting unit strings" do
    proc{Sequel.time_bucket(:created_at, "900 seconds")}.must_raise Sequel::InvalidValue
    proc{Sequel.time_bucket(:created_at, 900.5)}.must_raise Sequel::InvalidValue
    proc{Sequel.month_bucket(:created_at, "3 months")}.must_raise Sequel::InvalidValue
    proc{Sequel.time_bucket(:created_at, 0)}.must_raise Sequel::InvalidValue
    proc{Sequel.month_bucket(:created_at, -1)}.must_raise Sequel::InvalidValue
  end

  it "rejects origins that are not date or time values" do
    proc{Sequel.time_bucket(:created_at, 900, origin: "2024-01-01")}.must_raise Sequel::InvalidValue
  end

  it "can be selected, grouped, ordered, and combined with other expressions" do
    db = Sequel.sqlite
    db.extension :time_bucket
    bucket = Sequel.time_bucket(:created_at, 900, origin: @origin).as(:bucket)
    ds = db[:events].
      select_group(bucket).
      select_append(Sequel.function(:count, Sequel.lit('*')).as(:count)).
      order(Sequel.desc(:bucket))

    ds.sql.must_include "GROUP BY sequel_time_bucket(`created_at`, 900, '"
    ds.sql.must_include "ORDER BY `bucket` DESC"
    db.literal(Sequel.time_bucket(:created_at, 900) + 1).must_match(/\+ 1\)\z/)
  end

  it "supports deep qualification of the timestamp expression" do
    bucket = Sequel.time_bucket(:created_at, 900)
    qualified = Sequel.deep_qualify(:events, bucket)
    qualified.expr.must_equal Sequel.qualify(:events, :created_at)
  end

  describe "SQLite" do
    before do
      @db = Sequel.sqlite
      @db.extension :time_bucket
      @db.create_table(:events) do
        Time :created_at
      end
      @values = [
        Time.utc(2023, 12, 31, 23, 52, 29),
        Time.utc(2024, 1, 1, 0, 14, 59),
        Time.utc(2024, 1, 1, 0, 22, 30),
        nil
      ]
      @db[:events].multi_insert(@values.map{|value| {:created_at => value}})
    end

    after do
      @db.disconnect
    end

    def buckets(expression)
      @db[:events].order(:created_at).select_map(expression.as(:bucket))
    end

    it "floors timestamps before and after the origin to fixed physical-second buckets" do
      expression = Sequel.time_bucket(:created_at, 900, origin: @origin)
      buckets(expression).must_equal [
        nil,
        "2023-12-31 23:37:30.000000",
        "2024-01-01 00:07:30.000000",
        "2024-01-01 00:22:30.000000"
      ]
    end

    it "floors fractional seconds and timestamps before the Unix epoch" do
      @db.get(Sequel.time_bucket("2024-01-01 00:14:59.999999", 900, origin: Time.utc(2024))).
        must_equal "2024-01-01 00:00:00.000000"
      @db.get(Sequel.time_bucket("1969-12-31 23:44:59", 900, origin: Time.utc(1970))).
        must_equal "1969-12-31 23:30:00.000000"
    end

    it "keeps fixed buckets aligned across a spring-forward timezone transition" do
      @db[:events].delete
      @db[:events].insert(:created_at => Time.utc(2024, 3, 10, 7, 12))

      value = @db[:events].get(Sequel.time_bucket(
        :created_at,
        900,
        origin: Time.utc(2024),
        timezone: "America/New_York"
      ))

      value.must_equal "2024-03-10 07:00:00.000000"
    end

    it "keeps fixed buckets aligned during a fall-back timezone transition" do
      @db[:events].delete
      @db[:events].multi_insert([
        {:created_at => Time.utc(2024, 11, 3, 5, 52)},
        {:created_at => Time.utc(2024, 11, 3, 6, 0)}
      ])

      values = @db[:events].order(:created_at).select_map(Sequel.time_bucket(
        :created_at,
        900,
        origin: Time.utc(2024),
        timezone: "America/New_York"
      ).as(:bucket))

      values.must_equal [
        "2024-11-03 05:45:00.000000",
        "2024-11-03 05:00:00.000000"
      ]
    end

    it "floors leap days and cross-year dates to calendar-month buckets in a timezone" do
      @db[:events].delete
      [
        Time.utc(2024, 2, 29, 4, 59),
        Time.utc(2024, 3, 1, 5, 0),
        Time.utc(2025, 1, 1, 5, 0),
        Time.utc(2023, 2, 1, 5, 0)
      ].each{|value| @db[:events].insert(:created_at => value)}

      expression = Sequel.month_bucket(
        :created_at,
        3,
        origin: Time.utc(2023, 2, 15),
        timezone: "America/New_York"
      )

      buckets(expression).must_equal [
        "2023-02-01 05:00:00.000000",
        "2024-02-01 05:00:00.000000",
        "2024-02-01 05:00:00.000000",
        "2024-11-01 04:00:00.000000"
      ]
    end

    it "groups NULL timestamps as NULL" do
      expression = Sequel.time_bucket(:created_at, 900, origin: @origin).as(:bucket)
      rows = @db[:events].group_and_count(expression).order(Sequel.asc(:bucket, nulls: :last)).all

      rows.last[:bucket].must_be_nil
      rows.last[:count].must_equal 1
    end

    it "works in prepared statements using placeholder arguments and ordinary literals" do
      seconds = :$bucket_seconds
      origin = :$bucket_origin
      prepared = @db[:events].
        where(Sequel.time_bucket(:created_at, seconds, origin: origin) => :$bucket_start).
        prepare(:select, :time_bucket_select)

      prepared.prepared_sql.must_include "sequel_time_bucket(`created_at`, :bucket_seconds, :bucket_origin, 'UTC')"
      prepared.prepared_sql.must_include "= :bucket_start"

      rows = prepared.call(
        bucket_seconds: 900,
        bucket_origin: @origin,
        bucket_start: "2024-01-01 00:07:30.000000"
      )
      rows.length.must_equal 1
    end
  end

  describe "PostgreSQL SQL generation" do
    before do
      @db = Sequel.connect("mock://postgres")
      @db.extension :time_bucket
    end

    it "generates fixed-second date_bin SQL without interpolating unit text" do
      sql = @db.literal(Sequel.time_bucket(:created_at, 900, origin: Time.utc(2024)))

      sql.must_equal "date_bin(make_interval(secs := CAST(900 AS integer)), \"created_at\" AT TIME ZONE 'UTC', '2024-01-01 00:00:00.000000+0000' AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'"
    end

    it "generates calendar month SQL in the requested timezone" do
      sql = @db.literal(Sequel.month_bucket(
        :created_at,
        3,
        origin: Time.utc(2023, 2, 15),
        timezone: "America/New_York"
      ))

      sql.must_include '"created_at" AT TIME ZONE \'America/New_York\''
      sql.must_include "date_trunc('month'"
      sql.must_include "make_interval(months :="
      sql.must_include ") AT TIME ZONE 'America/New_York'"
      sql.wont_include "3 months"
    end

    it "literalizes timezone values as quoted data rather than SQL identifiers" do
      sql = @db.literal(Sequel.month_bucket(:created_at, timezone: "UTC', 'America/New_York"))

      sql.must_include "'UTC'', ''America/New_York'"
      sql.wont_include "AT TIME ZONE UTC"
    end
  end

  describe "unsupported adapters" do
    it "raises InvalidOperation" do
      db = Sequel.connect("mock://mysql")
      db.extension :time_bucket

      proc{db.literal(Sequel.time_bucket(:created_at, 900))}.must_raise Sequel::InvalidOperation
      proc{db.literal(Sequel.month_bucket(:created_at))}.must_raise Sequel::InvalidOperation
    end

    it "does not use SQLite SQL generation for JDBC or Amalgalite SQLite adapters" do
      db = Sequel.connect("mock://jdbc")
      def db.database_type
        :sqlite
      end
      db.extension :time_bucket

      proc{db.literal(Sequel.time_bucket(:created_at, 900))}.must_raise Sequel::InvalidOperation
    end
  end
end
