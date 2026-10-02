# frozen_string_literal: true
require_relative "spec_helper"

describe "bitemporal plugin" do
  before do
    @db = Sequel.sqlite
    @db.create_table(:prices) do
      primary_key :id
      Integer :product_id, null: false
      Integer :cents, null: false
      Integer :valid_start, null: false
      Integer :valid_end
      Integer :system_start, null: false
      Integer :system_end
    end

    @Price = Class.new(Sequel::Model(@db[:prices]))
    @Price.plugin :bitemporal, key: :product_id
  end

  after do
    @db.disconnect
  end

  def price_at(valid_time, system_time)
    @Price.bitemporal_as_of(valid_time, system_time).
      order(:valid_start).
      map(:cents)
  end

  it "inserts an initial open-ended business interval" do
    row = @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)

    row.cents.must_equal 100
    row.valid_end.must_be_nil
    row.system_end.must_be_nil
    row.must_be_instance_of @Price
  end

  it "splits an existing interval and preserves the old system view" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)

    price_at(11, 199).must_equal [100]
    price_at(12, 199).must_equal [100]
    price_at(14, 199).must_equal [100]
    price_at(15, 199).must_equal [100]

    price_at(12, 100).must_equal [100]
    price_at(14, 100).must_equal [100]
    price_at(15, 100).must_equal [100]

    price_at(11, 200).must_equal [100]
    price_at(12, 200).must_equal [90]
    price_at(14, 200).must_equal [90]
    price_at(15, 200).must_equal [100]

    current = @Price.bitemporal_as_of(nil, 200).order(:valid_start).all
    current.map{|row| [row.valid_start, row.valid_end, row.cents]}.must_equal [
      [10, 12, 100],
      [12, 15, 90],
      [15, nil, 100]
    ]

    [199, 200, 300].each do |system_time|
      rows = @Price.bitemporal_as_of(nil, system_time).order(:valid_start).all
      rows.each_cons(2) do |left, right|
        refute_nil left.valid_end
        assert_operator left.valid_end, :<=, right.valid_start
      end
    end
  end

  it "supports corrections that share a boundary without overlapping" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, valid_end: 20, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 20, valid_end: 30, recorded_at: 200)

    price_at(19, 200).must_equal [100]
    price_at(20, 200).must_equal [90]
    price_at(30, 200).must_equal []
  end

  it "isolates overlapping intervals by business key" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(2, {cents: 200},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)

    @Price.bitemporal_as_of(13, 200).
      where(product_id: 1).map(:cents).must_equal [90]
    @Price.bitemporal_as_of(13, 200).
      where(product_id: 2).map(:cents).must_equal [200]
  end

  it "treats both interval ends as exclusive" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, valid_end: 20, recorded_at: 100)

    price_at(9, 99).must_equal []
    price_at(10, 100).must_equal [100]
    price_at(19, 100).must_equal [100]
    price_at(20, 100).must_equal []
  end

  it "allows backfilling an interval that was previously missing" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 20, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 80},
      valid_start: 10, valid_end: 20, recorded_at: 200)

    price_at(15, 199).must_equal []
    price_at(15, 200).must_equal [80]
    price_at(20, 200).must_equal [100]
  end

  it "supports custom interval and key column names" do
    @db.create_table(:custom_prices) do
      primary_key :custom_id
      String :sku, null: false
      Integer :amount, null: false
      Integer :effective_from, null: false
      Integer :effective_to
      Integer :known_from, null: false
      Integer :known_to
    end

    custom_price = Class.new(Sequel::Model(@db[:custom_prices]))
    custom_price.plugin :bitemporal,
      key: :sku,
      valid_start: :effective_from,
      valid_end: :effective_to,
      system_start: :known_from,
      system_end: :known_to

    custom_price.record_bitemporal("A", {amount: 100},
      valid_start: 10, recorded_at: 100)
    custom_price.record_bitemporal("A", {amount: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)

    custom_price.bitemporal_as_of(13, 199).map(:amount).must_equal [100]
    custom_price.bitemporal_as_of(13, 200).map(:amount).must_equal [90]
  end

  it "rejects a late system version for a known business interval" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 20, recorded_at: 200)

    proc do
      @Price.record_bitemporal(1, {cents: 80},
        valid_start: 20, recorded_at: 100)
    end.must_raise Sequel::Plugins::Bitemporal::Error
  end

  it "supports repeated corrections of the same business interval" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)
    @Price.record_bitemporal(1, {cents: 80},
      valid_start: 12, valid_end: 15, recorded_at: 300)

    price_at(13, 199).must_equal [100]
    price_at(13, 200).must_equal [90]
    price_at(13, 299).must_equal [90]
    price_at(13, 300).must_equal [80]
    price_at(16, 300).must_equal [100]
  end

  it "makes an identical correction at the same system time idempotent" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)

    @Price.bitemporal_as_of(13, 200).count.must_equal 1
    @Price.count.must_equal 4
  end

  it "rejects a different correction at the same system time" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)
    @Price.record_bitemporal(1, {cents: 90},
      valid_start: 12, valid_end: 15, recorded_at: 200)

    proc do
      @Price.record_bitemporal(1, {cents: 80},
        valid_start: 12, valid_end: 15, recorded_at: 200)
    end.must_raise Sequel::Plugins::Bitemporal::Error
  end

  it "rejects empty business intervals" do
    proc do
      @Price.record_bitemporal(1, {cents: 100},
        valid_start: 10, valid_end: 10, recorded_at: 100)
    end.must_raise Sequel::Plugins::Bitemporal::Error
  end

  it "rolls back all writes when a correction fails after closing old rows" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)

    begin
      @Price.record_bitemporal(1, {cents: nil},
        valid_start: 12, valid_end: 15, recorded_at: 200)
    rescue Sequel::DatabaseError
    end

    @Price.bitemporal_as_of(13, 200).map(:cents).must_equal [100]
    row = @Price.bitemporal_as_of(10, 200).first
    row.valid_start.must_equal 10
    row.valid_end.must_be_nil
    row.system_end.must_be_nil
    @Price.count.must_equal 1
  end

  it "rolls back a correction inside an existing transaction" do
    @Price.record_bitemporal(1, {cents: 100},
      valid_start: 10, recorded_at: 100)

    begin
      @db.transaction do
        @Price.record_bitemporal(1, {cents: nil},
          valid_start: 12, valid_end: 15, recorded_at: 200,
          transaction: false)
      end
    rescue Sequel::DatabaseError
    end

    @Price.count.must_equal 1
  end
end
