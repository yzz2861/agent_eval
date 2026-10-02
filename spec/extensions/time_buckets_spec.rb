# frozen_string_literal: true
require_relative "spec_helper"

Sequel.extension :time_buckets
require 'tzinfo'

describe "time_buckets extension" do
  before do
    @db = Sequel.sqlite
    @db.extension :time_buckets
    @db.timezone = :utc
  end

  it "buckets fixed intervals from an origin, including times before the origin" do
    origin = Time.utc(2024, 1, 1, 0, 7, 30)
    values = {
      Time.utc(2023, 12, 31, 23, 52, 29) => Time.utc(2023, 12, 31, 23, 37, 30),
      Time.utc(2024, 1, 1, 0, 7, 29)   => Time.utc(2023, 12, 31, 23, 52, 30),
      Time.utc(2024, 1, 1, 0, 7, 30)   => Time.utc(2024, 1, 1, 0, 7, 30),
      Time.utc(2024, 1, 1, 0, 22, 30)  => Time.utc(2024, 1, 1, 0, 22, 30),
    }

    values.each do |timestamp, expected|
      got = @db.get(Sequel.time_bucket(timestamp, 900, origin: origin))
      DateTime.parse(got).new_offset(0).to_time.must_equal expected
    end
  end

  it "preserves NULL values in fixed and month buckets" do
    @db.get(Sequel.time_bucket(nil, 900)).must_be_nil
    @db.get(Sequel.month_bucket(nil)).must_be_nil
  end

  it "supports fixed offsets and fixed-offset calendar months in SQLite" do
    timestamp = Time.new(2024, 3, 10, 23, 30, 0, '+00:00')

    @db.get(Sequel.time_bucket(timestamp, 3600, origin: Time.utc(2024, 3, 10, 12), timezone: '-05:00')).must_equal '2024-03-10 18:00:00.000000'
    @db.get(Sequel.month_bucket(timestamp, timezone: '-05:00')).must_equal '2024-03-01 00:00:00.000000'
  end

  it "handles leap days and year boundaries" do
    @db.get(Sequel.month_bucket(Time.utc(2024, 2, 29, 12))).must_equal '2024-02-01 00:00:00.000000'
    @db.get(Sequel.month_bucket(Time.utc(2023, 12, 31, 23))).must_equal '2023-12-01 00:00:00.000000'
  end

  it "can be selected, grouped, ordered, and composed" do
    @db.create_table(:events) do
      DateTime :occurred_at
      Integer :quantity
    end

    @db[:events].multi_insert([
      {occurred_at: Time.utc(2024, 1, 1, 0, 1), quantity: 2},
      {occurred_at: Time.utc(2024, 1, 1, 0, 14), quantity: 3},
      {occurred_at: Time.utc(2024, 1, 1, 0, 16), quantity: 5},
    ])

    bucket = Sequel.time_bucket(:occurred_at, 900)
    rows = @db[:events].
      select_group(bucket.as(:bucket)).
      select_append { sum(quantity).as(:total) }.
      order(bucket).
      all

    rows.map { |row| [DateTime.parse(row[:bucket]).new_offset(0).to_time, row[:total]] }.must_equal [
      [Time.utc(2024, 1, 1, 0, 0), 5],
      [Time.utc(2024, 1, 1, 0, 15), 5],
    ]
  end

  it "uses literals and bind paths for interval and timezone values" do
    db = Sequel.connect('mock://sqlite')
    db.extension :time_buckets
    ds = db[:t].with_quote_identifiers(false)

    ds.literal(Sequel.time_bucket(:t, 900, origin: Time.utc(2024, 1, 1), timezone: '-05:00')).
      must_equal "sequel_time_bucket(t, 900, '2024-01-01 00:00:00.000000', '-05:00')"

    ds.literal(Sequel.month_bucket(:t, timezone: '-05:00')).
      must_equal "sequel_month_bucket(t, '-05:00')"
  end

  it "generates PostgreSQL SQL for fixed and month buckets" do
    db = Sequel.connect('mock://postgres')
    db.extension :time_buckets
    ds = db[:t].with_quote_identifiers(false)

    ds.literal(Sequel.time_bucket(:t, 900, origin: Time.utc(2024, 1, 1), timezone: 'America/New_York')).
      must_equal "timezone('America/New_York', (CAST('2024-01-01 00:00:00.000000+0000' AS timestamptz) + CAST((CAST((floor(((extract(epoch FROM CAST(t AS timestamptz)) - extract(epoch FROM CAST('2024-01-01 00:00:00.000000+0000' AS timestamptz))) / 900.0)) * 900) AS text) || ' seconds') AS interval)))"

    ds.literal(Sequel.month_bucket(:t, timezone: 'America/New_York')).
      must_equal "date_trunc('month', timezone('America/New_York', CAST(t AS timestamptz)))"
  end

  it "generates PostgreSQL fixed buckets using absolute epoch arithmetic across DST changes" do
    db = Sequel.connect('mock://postgres')
    db.extension :time_buckets
    ds = db[:t].with_quote_identifiers(false)

    sql = ds.literal(Sequel.time_bucket(:t, 900, timezone: 'America/New_York'))
    sql.must_include "extract(epoch FROM CAST(t AS timestamptz))"
    sql.must_include "CAST((floor("
    sql.must_include "timezone('America/New_York'"
  end

  it "handles named timezones across spring-forward and fall-back transitions" do
    spring_forward = Time.utc(2024, 3, 10, 8, 14, 59)
    fall_back = Time.utc(2024, 11, 3, 6, 14, 59)

    @db.get(Sequel.time_bucket(spring_forward, 900, timezone: 'America/New_York')).
      must_equal '2024-03-10 04:00:00.000000'
    @db.get(Sequel.time_bucket(fall_back, 900, timezone: 'America/New_York')).
      must_equal '2024-11-03 01:00:00.000000'
  end

  it "determines calendar month boundaries in a named timezone" do
    @db.get(Sequel.month_bucket(Time.utc(2024, 3, 1, 4, 30), timezone: 'America/New_York')).
      must_equal '2024-02-01 00:00:00.000000'
  end

  it "supports bound variables for origin and timezone and treats timezone text as a value" do
    @db.create_table(:events) { DateTime :occurred_at }
    @db[:events].insert(occurred_at: Time.utc(2024, 1, 1, 0, 14, 59))

    statement = @db[:events].
      select(Sequel.time_bucket(:occurred_at, 900, origin: :$origin, timezone: :$timezone).as(:bucket)).
      prepare(:all, :time_bucket_bound)

    statement.call(origin: Time.utc(2024, 1, 1), timezone: 'UTC').
      must_equal [{bucket: '2024-01-01 00:00:00.000000'}]

    proc do
      @db.get(Sequel.month_bucket(Time.utc(2024, 1, 1), timezone: "UTC'); DROP TABLE events; --"))
    end.must_raise(TZInfo::InvalidTimezoneIdentifier)
    @db.table_exists?(:events).must_equal true
  end

  it "supports numeric SQLite timestamps and qualifies embedded columns" do
    @db.get(Sequel.time_bucket(0, 900)).must_equal '1970-01-01 00:00:00.000000'

    qualified = Sequel.deep_qualify(:events, Sequel.time_bucket(:occurred_at, 900))
    @db.literal(qualified).must_include '`events`.`occurred_at`'
  end

  it "raises on unsupported adapters" do
    db = Sequel.mock
    db.extend_datasets(Sequel::SQL::TimeBucket::DatasetMethods)

    proc { db.literal(Sequel.time_bucket(:t, 900)) }.must_raise Sequel::Error
    proc { db.literal(Sequel.month_bucket(:t)) }.must_raise Sequel::Error
  end

  it "rejects invalid fixed interval widths" do
    proc { Sequel.time_bucket(:t, 0) }.must_raise Sequel::InvalidValue
    proc { Sequel.time_bucket(:t, -900) }.must_raise Sequel::InvalidValue
    proc { Sequel.time_bucket(:t, 900.5) }.must_raise Sequel::InvalidValue
  end
end
