# frozen_string_literal: true
require_relative "spec_helper"

begin
  require 'sqlite3'
rescue LoadError
  warn "Skipping test of bitemporal plugin: can't load sqlite3"
else
describe "bitemporal plugin" do
  before do
    @old_application_timezone = Sequel.application_timezone
    @old_database_timezone = Sequel.database_timezone
    Sequel.default_timezone = :utc
    @db = Sequel.sqlite
    @db.create_table(:prices) do
      primary_key :id
      String :key
      Integer :amount
      Time :valid_from
      Time :valid_to, :null=>true
      Time :system_from
      Time :system_to, :null=>true
    end
    @c = Class.new(Sequel::Model(@db[:prices]))
    @c.plugin :bitemporal
    @c.class_eval do
      def validate
        super
        errors.add(:amount, "must be positive") if amount && amount <= 0
      end
    end
    @t1 = Time.utc(2026, 9, 1)
    @t2 = Time.utc(2026, 9, 10)
    @t3 = Time.utc(2026, 9, 20)
    @s1 = Time.utc(2026, 10, 1, 9)
    @s2 = Time.utc(2026, 10, 2, 9)
    @s3 = Time.utc(2026, 10, 3, 9)
  end

  after do
    @db.disconnect
    Sequel.application_timezone = @old_application_timezone
    Sequel.database_timezone = @old_database_timezone
  end

  it "should record a revision with the given validity interval and system time" do
    r = @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t2, system_time: @s1)
    r.must_be_kind_of @c
    r.key.must_equal 'sku-1'
    r.amount.must_equal 100
    r.valid_from.must_equal @t1
    r.valid_to.must_equal @t2
    r.system_from.must_equal @s1
    r.system_to.must_be_nil
    r.must_be :current_system_version?
  end

  it "should use the :system_time option proc for the system time by default" do
    now = @s1
    c = Class.new(Sequel::Model(@db[:prices]))
    c.plugin :bitemporal, system_time: proc{now}
    r = c.record_revision('sku-1', {amount: 100}, valid_from: @t1)
    r.system_from.must_equal @s1
  end

  it "should support custom column names via plugin options" do
    @db.create_table(:prices2) do
      primary_key :id
      String :sku
      Integer :amount
      Time :eff_from
      Time :eff_to, :null=>true
      Time :rec_from
      Time :rec_to, :null=>true
    end
    c = Class.new(Sequel::Model(@db[:prices2]))
    c.plugin :bitemporal, key: :sku, valid_from: :eff_from, valid_to: :eff_to,
      system_from: :rec_from, system_to: :rec_to
    r = c.record_revision('sku-1', {amount: 100}, valid_from: @t1, system_time: @s1)
    r.eff_from.must_equal @t1
    r.rec_from.must_equal @s1
    c.as_of(@t1, @s1).count.must_equal 1
  end

  it "should treat validity and system intervals as half-open in as_of queries" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t2, system_time: @s1)
    @c.as_of(@t1, @s1).count.must_equal 1
    @c.as_of(@t1 - 1, @s1).count.must_equal 0
    @c.as_of(@t2 - 1, @s1).count.must_equal 1
    @c.as_of(@t2, @s1).count.must_equal 0
    @c.as_of(@t1, @s1 - 1).count.must_equal 0
    @c.as_of(@t1, @s1 + 1).count.must_equal 1
  end

  it "should treat a NULL valid_to as open-ended" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, system_time: @s1)
    @c.as_of(Time.utc(2036, 1, 1), @s1).count.must_equal 1
  end

  it "should allow adjacent validity intervals in the same system view" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t2, system_time: @s1)
    @c.record_revision('sku-1', {amount: 200}, valid_from: @t2, valid_to: @t3, system_time: @s1)
    @c.as_of(@t2 - 1, @s1).first.amount.must_equal 100
    @c.as_of(@t2, @s1).first.amount.must_equal 200
    @c.current_system_view.count.must_equal 2
  end

  it "should split the existing interval when recording a correction, preserving old system versions" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    r = @c.record_revision('sku-1', {amount: 120}, valid_from: @t2, valid_to: @t2 + 86400, system_time: @s2)
    r.amount.must_equal 120

    # The current system view shows three adjacent segments.
    rows = @c.current_system_view.order(:valid_from).all
    rows.map{|p| [p.valid_from, p.valid_to, p.amount]}.must_equal [
      [@t1, @t2, 100],
      [@t2, @t2 + 86400, 120],
      [@t2 + 86400, @t3, 100]
    ]
    rows.each{|p| p.system_from.must_equal @s2}

    # The old system version is closed but still queryable.
    old = @c.system_as_of(@s1).all
    old.count.must_equal 1
    old.first.amount.must_equal 100
    old.first.valid_from.must_equal @t1
    old.first.valid_to.must_equal @t3
    old.first.system_to.must_equal @s2
    old.first.wont_be :current_system_version?

    # as_of with the old system time still answers what the system showed then.
    @c.as_of(@t2, @s1).first.amount.must_equal 100
    @c.as_of(@t2, @s2).first.amount.must_equal 120
  end

  it "should not insert carry-over revisions when the correction covers the whole interval" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t2, system_time: @s1)
    @c.record_revision('sku-1', {amount: 120}, valid_from: @t1, valid_to: @t2, system_time: @s2)
    @c.current_system_view.count.must_equal 1
    @c.current_system_view.first.amount.must_equal 120
    @c.as_of(@t1, @s1).first.amount.must_equal 100
  end

  it "should swallow the tail of existing intervals for open-ended corrections" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    @c.record_revision('sku-1', {amount: 120}, valid_from: @t2, system_time: @s2)
    rows = @c.current_system_view.order(:valid_from).all
    rows.map{|p| [p.valid_from, p.valid_to, p.amount]}.must_equal [
      [@t1, @t2, 100],
      [@t2, nil, 120]
    ]
  end

  it "should support repeated corrections, keeping each system view queryable" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    @c.record_revision('sku-1', {amount: 120}, valid_from: @t2, valid_to: @t3, system_time: @s2)
    @c.record_revision('sku-1', {amount: 130}, valid_from: @t2 + 86400, valid_to: @t3, system_time: @s3)

    @c.as_of(@t2 + 86400, @s1).first.amount.must_equal 100
    @c.as_of(@t2 + 86400, @s2).first.amount.must_equal 120
    @c.as_of(@t2 + 86400, @s3).first.amount.must_equal 130
    @c.as_of(@t1 + 1, @s3).first.amount.must_equal 100

    rows = @c.current_system_view.order(:valid_from).all
    rows.map{|p| [p.valid_from, p.valid_to, p.amount]}.must_equal [
      [@t1, @t2, 100],
      [@t2, @t2 + 86400, 120],
      [@t2 + 86400, @t3, 130]
    ]
    @c.count.must_equal 5
  end

  it "should only affect revisions for the same business key" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    @c.record_revision('sku-2', {amount: 50}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    @c.record_revision('sku-1', {amount: 120}, valid_from: @t1, valid_to: @t3, system_time: @s2)
    @c.as_of(@t1, @s2).where(key: 'sku-2').first.amount.must_equal 50
    @c.as_of(@t1, @s2).where(key: 'sku-1').first.amount.must_equal 120
  end

  it "should prevent overlapping validity intervals in the same system view" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    proc do
      @c.create(key: 'sku-1', amount: 200, valid_from: @t2, valid_to: @t3 + 86400,
        system_from: @s1, system_to: nil)
    end.must_raise Sequel::ValidationFailed

    # Overlaps in a closed system version are not rechecked.
    closed = @c.system_as_of(@s1).first
    closed.update(system_to: @s2)
    closed.current_system_version?.must_equal false
  end

  it "should reject empty validity intervals" do
    proc{@c.record_revision('sku-1', {amount: 100}, valid_from: @t2, valid_to: @t1)}.
      must_raise Sequel::InvalidValue
    proc{@c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t1)}.
      must_raise Sequel::InvalidValue
    proc{@c.create(key: 'sku-1', amount: 100, valid_from: @t1, valid_to: @t1, system_from: @s1)}.
      must_raise Sequel::ValidationFailed
  end

  it "should roll back the whole correction when it fails partway through" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t3, system_time: @s1)
    before = @c.all

    proc do
      @c.record_revision('sku-1', {amount: -5}, valid_from: @t2, valid_to: @t2 + 86400, system_time: @s2)
    end.must_raise Sequel::ValidationFailed

    @c.count.must_equal before.count
    rows = @c.current_system_view.all
    rows.count.must_equal 1
    rows.first.amount.must_equal 100
    rows.first.valid_from.must_equal @t1
    rows.first.valid_to.must_equal @t3
    rows.first.system_to.must_be_nil
  end

  it "should expose valid_as_of, system_as_of, and current_system_view dataset methods" do
    @c.record_revision('sku-1', {amount: 100}, valid_from: @t1, valid_to: @t2, system_time: @s1)
    @c.record_revision('sku-1', {amount: 120}, valid_from: @t1, valid_to: @t2, system_time: @s2)
    @c.valid_as_of(@t1).count.must_equal 2
    @c.system_as_of(@s1).count.must_equal 1
    @c.system_as_of(@s2).count.must_equal 1
    @c.current_system_view.count.must_equal 1
    @c.dataset.as_of(@t1, @s1).first.amount.must_equal 100
  end
end
end
