require 'flipper'
require 'zlib'

RSpec.describe Flipper::Adapters::RolloutSchedule do
  let(:clock) { Clock.new(Time.iso8601('2026-01-01T00:00:00Z')) }
  let(:memory) { Flipper::Adapters::Memory.new }
  let(:adapter) { described_class.new(memory, clock: clock) }
  let(:flipper) { Flipper.new(adapter) }
  let(:feature) { flipper[:search] }

  let(:points) do
    [
      ['2026-01-01T00:00:00Z', 10],
      ['2026-01-02T00:00:00Z', 50],
    ]
  end

  before { adapter.add_schedule(:search, points, mode: :linear) }

  class Clock
    def initialize(time)
      @time = time
    end

    def call
      @time
    end

    def travel_to(string)
      @time = Time.iso8601(string)
    end
  end

  def bucket_open?(actor_value, percentage)
    Zlib.crc32("search#{actor_value}") % 100_000 < percentage * 1_000
  end

  it 'passes through features without schedules unchanged' do
    flipper[:other].enable
    expect(flipper.enabled?(:other)).to be(true)
  end

  describe 'scheduled percentage at boundaries' do
    it 'is off for everyone before the first point' do
      clock.travel_to('2025-12-31T23:59:59Z')
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(0)
      expect(flipper.enabled?(:search, Flipper::Actor.new('1'))).to be(false)
    end

    it 'starts at 10% exactly on the first point' do
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(10)
    end

    it 'holds 50% at and after the last point (plan does not snap off)' do
      clock.travel_to('2026-01-02T00:00:00Z')
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(50)
      clock.travel_to('2027-06-01T00:00:00Z')
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(50)
    end

    it 'drives the same stable actor bucketing as a static percentage gate' do
      clock.travel_to('2026-01-01T00:00:00Z')
      (1..200).each do |n|
        actor = Flipper::Actor.new(n.to_s)
        expect(flipper.enabled?(:search, actor)).to be(bucket_open?(n.to_s, 10))
      end

      clock.travel_to('2026-01-02T00:00:00Z')
      (1..200).each do |n|
        actor = Flipper::Actor.new(n.to_s)
        expect(flipper.enabled?(:search, actor)).to be(bucket_open?(n.to_s, 50))
      end
    end

    it 'never re-buckets an actor while the percentage is unchanged' do
      actor = Flipper::Actor.new('42')
      first = flipper.enabled?(:search, actor)
      5.times { expect(flipper.enabled?(:search, actor)).to be(first) }
    end

    it 'tracks roughly the right population size mid-window' do
      clock.travel_to('2026-01-01T12:00:00Z') # 30%
      enabled = (1..10_000).count do |n|
        flipper.enabled?(:search, Flipper::Actor.new(n.to_s))
      end
      expect(enabled).to be_within(150).of(3_000)
    end
  end

  describe 'step mode' do
    let(:adapter) { described_class.new(memory, clock: clock) }

    before do
      adapter.add_schedule(:stepwise, points, mode: :step)
    end

    it 'holds 10% until the instant before the last point, then 50%' do
      clock.travel_to('2026-01-01T23:59:59Z')
      expect(adapter.get(flipper[:stepwise])[:percentage_of_actors]).to eq(10)
      clock.travel_to('2026-01-02T00:00:00Z')
      expect(adapter.get(flipper[:stepwise])[:percentage_of_actors]).to eq(50)
    end
  end

  describe 'manual kill switch precedence' do
    it 'forces fully off even at 100% schedule and overrides enabled actors' do
      feature.enable_actor(Flipper::Actor.new('1'))
      clock.travel_to('2027-01-01T00:00:00Z')
      expect(flipper.enabled?(:search, Flipper::Actor.new('1'))).to be(true)

      adapter.disable_rollout(:search)
      expect(adapter.rollout_disabled?(:search)).to be(true)
      expect(flipper.enabled?(:search, Flipper::Actor.new('1'))).to be(false)
      expect(flipper.enabled?(:search)).to be(false)

      adapter.enable_rollout(:search)
      expect(flipper.enabled?(:search, Flipper::Actor.new('1'))).to be(true)
    end

    it 'is exposed on the DSL' do
      flipper.disable_rollout(:search)
      expect(flipper.enabled?(:search, Flipper::Actor.new('1'))).to be(false)
      flipper.enable_rollout(:search)
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(10)
    end

    it 'does not leak the kill switch into the wrapped adapter' do
      adapter.disable_rollout(:search)
      expect(memory.get(feature)[:boolean]).to be_nil
    end
  end

  describe 'overlapping windows' do
    it 'rejects overlapping schedules for the same feature at configuration' do
      overlapping = [
        ['2026-01-01T12:00:00Z', 0],
        ['2026-01-03T00:00:00Z', 10],
      ]
      expect { adapter.add_schedule(:search, overlapping) }
        .to raise_error(described_class::InvalidScheduleError, /overlaps/)
    end

    it 'allows schedules that touch at an endpoint (one ends when another starts)' do
      next_points = [
        ['2026-01-02T00:00:00Z', 50],
        ['2026-01-03T00:00:00Z', 80],
      ]
      expect { adapter.add_schedule(:search, next_points) }.not_to raise_error
    end

    it 'hands off to the newer schedule exactly at the shared endpoint and holds its final value' do
      next_points = [
        ['2026-01-02T00:00:00Z', 50],
        ['2026-01-03T00:00:00Z', 80],
      ]
      adapter.add_schedule(:search, next_points)

      clock.travel_to('2026-01-02T00:00:00Z')
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(50)
      clock.travel_to('2026-01-03T00:00:00Z')
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(80)
      clock.travel_to('2026-12-31T00:00:00Z')
      expect(adapter.get(feature)[:percentage_of_actors]).to eq(80)
    end

    it 'rejects reverse intervals inside a schedule at configuration' do
      reverse = [
        ['2026-01-02T00:00:00Z', 50],
        ['2026-01-01T00:00:00Z', 10],
      ]
      expect { adapter.add_schedule(:search, reverse) }
        .to raise_error(Flipper::RolloutSchedule::InvalidSchedule)
    end

    it 'allows independent schedules for different features' do
      expect { adapter.add_schedule(:other, points) }.not_to raise_error
    end
  end

  describe 'interaction with other gates' do
    it 'lets explicit boolean-on win regardless of the schedule' do
      feature.enable
      clock.travel_to('2025-01-01T00:00:00Z')
      expect(flipper.enabled?(:search)).to be(true)
    end

    it 'lets explicitly enabled actors win' do
      feature.enable_actor(Flipper::Actor.new('special'))
      clock.travel_to('2025-01-01T00:00:00Z')
      expect(flipper.enabled?(:search, Flipper::Actor.new('special'))).to be(true)
    end

    it 'writes nothing to the wrapped adapter over time' do
      snapshot = memory.get(feature)
      clock.travel_to('2026-01-01T00:00:00Z')
      adapter.get(feature)
      clock.travel_to('2026-01-02T00:00:00Z')
      adapter.get(feature)
      expect(memory.get(feature)).to eq(snapshot)
    end
  end

  describe 'get_multi' do
    it 'applies schedules to every feature in the batch' do
      adapter.add_schedule(:other, points)
      features = [feature, flipper[:other]]
      result = adapter.get_multi(features)
      expect(result['search'][:percentage_of_actors]).to eq(10)
      expect(result['other'][:percentage_of_actors]).to eq(10)
    end
  end

  describe 'DSL without the wrapper' do
    it 'raises a helpful error when adding a schedule' do
      plain = Flipper.new(Flipper::Adapters::Memory.new)
      expect { plain.add_rollout_schedule(:x, points) }
        .to raise_error(ArgumentError, /RolloutSchedule/)
    end
  end
end
