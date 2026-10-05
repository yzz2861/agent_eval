require 'zlib'

RSpec.describe Flipper::RolloutSchedule do
  let(:starts_at) { '2026-10-05T10:00:00+08:00' }
  let(:ends_at) { '2026-10-05T18:00:00+08:00' }

  def time(offset)
    Time.iso8601("2026-10-05T#{offset}+08:00")
  end

  def linear_schedule(after_end: :hold, **overrides)
    window = {
      starts_at: starts_at,
      ends_at: ends_at,
      from_percentage: 10,
      to_percentage: 50,
      mode: :linear
    }.merge(overrides)
    described_class.new(windows: [window], after_end: after_end)
  end

  describe '#percentage (linear)' do
    subject(:schedule) { linear_schedule }

    it 'is 0 before the first window' do
      expect(schedule.percentage(time('09:59:59'))).to eq(0)
    end

    it 'equals from_percentage exactly at starts_at' do
      expect(schedule.percentage(time('10:00:00'))).to eq(10)
    end

    it 'interpolates linearly inside the window' do
      expect(schedule.percentage(time('12:00:00'))).to eq(20)
      expect(schedule.percentage(time('14:00:00'))).to eq(30)
      expect(schedule.percentage(time('16:00:00'))).to eq(40)
    end

    it 'supports fractional percentages at sub-second offsets' do
      # 40% spread over 8h = 5%/h. 36 minutes in => 13.0%; 10800.5s in
      # => 25.000694...%, floored at 3-decimal scaling.
      now = time('10:00:00') + (3 * 3600 + 0.5)
      expect(schedule.percentage(now)).to eq(25)
    end

    it 'equals to_percentage exactly at ends_at and keeps holding afterwards' do
      expect(schedule.percentage(time('18:00:00'))).to eq(50)
      expect(schedule.percentage(time('23:59:59'))).to eq(50)
    end

    it 'holds the previous ending percentage in a gap between windows' do
      schedule = described_class.new(windows: [
        { starts_at: '2026-10-05T10:00:00+08:00', ends_at: '2026-10-05T12:00:00+08:00',
          from_percentage: 10, to_percentage: 20 },
        { starts_at: '2026-10-05T14:00:00+08:00', ends_at: '2026-10-05T16:00:00+08:00',
          from_percentage: 30, to_percentage: 40 }
      ])
      expect(schedule.percentage(time('13:00:00'))).to eq(20)
      expect(schedule.percentage(time('14:00:00'))).to eq(30)
    end

    it 'drops to 0 after the final window when after_end is :off' do
      schedule = linear_schedule(after_end: :off)
      expect(schedule.percentage(time('18:00:00'))).to eq(50)
      one_nanosecond = 1.0 / 1_000_000_000
      expect(schedule.percentage(time('18:00:00') + one_nanosecond)).to eq(0)
    end
  end

  describe '#percentage (step)' do
    subject(:schedule) do
      described_class.new(windows: [{
        starts_at: starts_at, ends_at: ends_at,
        from_percentage: 10, to_percentage: 50,
        mode: :step, step_percentage: 10
      }])
    end

    it 'holds each step until the step boundary, inclusive' do
      expect(schedule.percentage(time('10:00:00'))).to eq(10)
      expect(schedule.percentage(time('11:59:59'))).to eq(10)
      expect(schedule.percentage(time('12:00:00'))).to eq(20)
      expect(schedule.percentage(time('15:59:59'))).to eq(30)
      expect(schedule.percentage(time('16:00:00'))).to eq(40)
      expect(schedule.percentage(time('18:00:00'))).to eq(50)
    end
  end

  describe 'stable actor bucketing' do
    subject(:schedule) { linear_schedule }

    it 'uses the same crc32(feature name + flipper_id) bucketing as the gate' do
      actor = Flipper::Actor.new('User;42')
      expected_bucket = Zlib.crc32("search#{actor.flipper_id}") % 100_000
      expect(schedule.bucket_for(actor, :search)).to eq(expected_bucket)
    end

    it 'enables the same actors on every evaluation for a fixed time' do
      actor = Flipper::Actor.new('User;42')
      now = time('14:00:00')
      results = Array.new(10) { schedule.enabled?(actor, feature_name: :search, now: now) }
      expect(results.uniq).to eq([schedule.enabled?(actor, feature_name: :search, now: now)])
    end

    it 'rolls out roughly the configured fraction of actors' do
      now = time('18:00:00')
      enabled = (1..10_000).count do |n|
        schedule.enabled?(Flipper::Actor.new("User;#{n}"), feature_name: :search, now: now)
      end
      expect(enabled.to_f / 10_000).to be_within(0.02).of(0.50)
    end

    it 'is monotonic per actor as time advances' do
      actors = (1..200).map { |n| Flipper::Actor.new("User;#{n}") }
      timestamps = ['10:00:00', '12:00:00', '14:00:00', '16:00:00', '18:00:00']
      results = timestamps.map do |stamp|
        actors.map { |actor| schedule.enabled?(actor, feature_name: :search, now: time(stamp)) }
      end
      results.each_cons(2) do |earlier, later|
        earlier.zip(later).each do |before, after|
          # booleans: false may become true, but an enabled actor never turns off
          expect(after ? true : !before).to eq(true)
        end
      end
    end
  end

  describe 'time zones' do
    it 'treats explicit offsets as the same instant' do
      schedule = described_class.new(windows: [{
        starts_at: '2026-10-05T10:00:00+08:00',
        ends_at: '2026-10-05T18:00:00+08:00',
        from_percentage: 10, to_percentage: 50
      }])
      same_instant_in_utc = Time.iso8601('2026-10-05T02:00:00Z')
      expect(schedule.percentage(same_instant_in_utc)).to eq(10)
    end
  end

  describe 'validation' do
    def window(**overrides)
      {
        starts_at: starts_at, ends_at: ends_at,
        from_percentage: 10, to_percentage: 50
      }.merge(overrides)
    end

    it 'requires at least one window' do
      expect { described_class.new(windows: []) }
        .to raise_error(ArgumentError, /at least one window/)
    end

    it 'requires an explicit UTC offset on string times' do
      expect { described_class.new(windows: [window(starts_at: '2026-10-05T10:00:00')]) }
        .to raise_error(ArgumentError, /explicit offset/)
    end

    it 'rejects a reversed window' do
      expect {
        described_class.new(windows: [window(
          starts_at: '2026-10-05T18:00:00+08:00',
          ends_at: '2026-10-05T10:00:00+08:00'
        )])
      }.to raise_error(ArgumentError, /must be after starts_at/)
    end

    it 'rejects overlapping windows' do
      expect {
        described_class.new(windows: [
          window,
          window(starts_at: '2026-10-05T17:00:00+08:00',
                 ends_at: '2026-10-05T20:00:00+08:00',
                 from_percentage: 50, to_percentage: 60)
        ])
      }.to raise_error(ArgumentError, /overlap/)
    end

    it 'allows exactly touching windows' do
      expect {
        described_class.new(windows: [
          window,
          window(starts_at: '2026-10-05T18:00:00+08:00',
                 ends_at: '2026-10-05T20:00:00+08:00',
                 from_percentage: 50, to_percentage: 60)
        ])
      }.not_to raise_error
    end

    it 'rejects percentages outside 0..100' do
      expect { described_class.new(windows: [window(from_percentage: -1)]) }
        .to raise_error(ArgumentError, /between 0 and 100/)
      expect { described_class.new(windows: [window(to_percentage: 101)]) }
        .to raise_error(ArgumentError, /between 0 and 100/)
    end

    it 'requires step_percentage for step mode' do
      expect { described_class.new(windows: [window(mode: :step)]) }
        .to raise_error(ArgumentError, /step_percentage/)
    end

    it 'rejects a step range that does not divide evenly' do
      expect {
        described_class.new(windows: [window(mode: :step, step_percentage: 15)])
      }.to raise_error(ArgumentError, /divisible/)
    end

    it 'rejects an unknown after_end behavior' do
      expect { described_class.new(windows: [window], after_end: :wat) }
        .to raise_error(ArgumentError, /after_end/)
    end
  end

  describe '.build DSL' do
    it 'accepts a block with explicit-offset times' do
      schedule = described_class.define do |s|
        s.window '2026-10-05T10:00:00+08:00', '2026-10-05T18:00:00+08:00',
                 from: 10, to: 50, mode: :linear
        s.after_end :hold
      end
      expect(schedule.percentage(time('14:00:00'))).to eq(30)
      expect(schedule.to_h['after_end']).to eq('hold')
    end
  end

  describe '.build from JSON-like config' do
    it 'accepts string keys and string percentages' do
      schedule = described_class.build(
        'windows' => [{
          'starts_at' => '2026-10-05T10:00:00Z',
          'ends_at' => '2026-10-05T18:00:00Z',
          'from_percentage' => '10',
          'to_percentage' => '50'
        }],
        'after_end' => 'hold'
      )
      now = Time.iso8601('2026-10-05T14:00:00Z')
      expect(schedule.percentage(now)).to eq(30)
    end
  end
end
