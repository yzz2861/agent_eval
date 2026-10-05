require 'flipper'

RSpec.describe Flipper::RolloutSchedule do
  let(:t0) { '2026-01-01T00:00:00+00:00' }
  let(:t1) { '2026-01-02T00:00:00+00:00' }

  def schedule(mode: :linear, points:)
    described_class.new(:search, points, mode: mode)
  end

  def at(string)
    Time.iso8601(string)
  end

  describe '#percentage_at with :linear' do
    let(:points) { [[t0, 10], [t1, 50]] }

    it 'is 0 before the first point' do
      expect(schedule(points: points).percentage_at(at('2025-12-31T23:59:59+00:00'))).to eq(0)
    end

    it 'is the first percentage exactly at the first point' do
      expect(schedule(points: points).percentage_at(at(t0))).to eq(10)
    end

    it 'interpolates linearly in the middle' do
      subject = schedule(points: points)
      # 10% at start, 50% at end: halfway floor is 29 (40% over half = 20).
      expect(subject.percentage_at(at('2026-01-01T12:00:00+00:00'))).to eq(30)
      # A quarter of the way: 10 + 10 = 20.
      expect(subject.percentage_at(at('2026-01-01T06:00:00+00:00'))).to eq(20)
    end

    it 'holds the final percentage at and after the last point' do
      subject = schedule(points: points)
      expect(subject.percentage_at(at(t1))).to eq(50)
      expect(subject.percentage_at(at('2027-01-01T00:00:00+00:00'))).to eq(50)
    end

    it 'floors fractional percentages without flipping early' do
      # 90% of one hour past a 10->50 day: 10 + 1.5 = 11.5 => 11.
      expect(schedule(points: points).percentage_at(at('2026-01-01T00:54:00+00:00'))).to eq(11)
    end
  end

  describe '#percentage_at with :step' do
    let(:points) { [[t0, 10], [t1, 50]] }

    it 'holds the lower percentage until the next point is reached' do
      subject = schedule(mode: :step, points: points)
      expect(subject.percentage_at(at(t0))).to eq(10)
      expect(subject.percentage_at(at('2026-01-01T23:59:59+00:00'))).to eq(10)
    end

    it 'jumps exactly at the next point' do
      subject = schedule(mode: :step, points: points)
      expect(subject.percentage_at(at(t1))).to eq(50)
      expect(subject.percentage_at(at('2027-01-01T00:00:00+00:00'))).to eq(50)
    end
  end

  describe 'multi-point schedules' do
    let(:points) do
      [
        ['2026-01-01T00:00:00+00:00', 10],
        ['2026-01-03T00:00:00+00:00', 30],
        ['2026-01-05T00:00:00+00:00', 50],
      ]
    end

    it 'interpolates each segment independently' do
      subject = schedule(points: points)
      expect(subject.percentage_at(at('2026-01-02T00:00:00+00:00'))).to eq(20)
      expect(subject.percentage_at(at('2026-01-04T00:00:00+00:00'))).to eq(40)
    end
  end

  describe 'explicit time zone offsets' do
    let(:points) do
      [
        ['2026-01-01T08:00:00+08:00', 10],
        ['2026-01-02T08:00:00+08:00', 50],
      ]
    end

    it 'treats offset-bearing points as absolute instants' do
      subject = schedule(points: points)
      # 08:00+08:00 is 00:00Z.
      expect(subject.percentage_at(at('2026-01-01T00:00:00Z'))).to eq(10)
      expect(subject.percentage_at(at('2025-12-31T23:59:59Z'))).to eq(0)
    end

    it 'accepts Time objects carrying an offset' do
      points = [[Time.iso8601('2026-01-01T08:00:00+08:00'), 10],
                [Time.iso8601('2026-01-02T08:00:00+08:00'), 50]]
      expect(schedule(points: points).percentage_at(at('2026-01-01T00:00:00Z'))).to eq(10)
    end
  end

  describe 'configuration validation' do
    it 'requires at least two points' do
      expect { described_class.new(:search, [[t0, 10]]) }
        .to raise_error(described_class::InvalidSchedule, /at least two points/)
    end

    it 'rejects reverse and equal-time intervals' do
      expect { described_class.new(:search, [[t1, 10], [t0, 50]]) }
        .to raise_error(described_class::InvalidSchedule, /increasing time order/)
      expect { described_class.new(:search, [[t0, 10], [t0, 50]]) }
        .to raise_error(described_class::InvalidSchedule, /distinct, increasing/)
    end

    it 'rejects out-of-range and non-integer percentages' do
      expect { described_class.new(:search, [[t0, -1], [t1, 50]]) }
        .to raise_error(described_class::InvalidSchedule)
      expect { described_class.new(:search, [[t0, 10], [t1, 101]]) }
        .to raise_error(described_class::InvalidSchedule)
      expect { described_class.new(:search, [[t0, 10.5], [t1, 50]]) }
        .to raise_error(described_class::InvalidSchedule)
    end

    it 'rejects unknown modes' do
      expect { described_class.new(:search, [[t0, 10], [t1, 50]], mode: :exponential) }
        .to raise_error(described_class::InvalidSchedule, /mode/)
    end

    it 'rejects offset-less ISO 8601 strings' do
      expect { described_class.new(:search, [['2026-01-01T00:00:00', 10], [t1, 50]]) }
        .to raise_error(described_class::InvalidSchedule, /offset/)
    end

    it 'rejects malformed point shapes' do
      expect { described_class.new(:search, [t0, t1]) }
        .to raise_error(described_class::InvalidSchedule, /pair/)
    end
  end

  describe 'injected clock' do
    it 'computes the percentage from the clock when no time is given' do
      current = [at('2026-01-01T06:00:00+00:00')]
      subject = described_class.new(:search, [[t0, 10], [t1, 50]], clock: -> { current.first })
      expect(subject.percentage_at).to eq(20)
      current[0] = at('2026-01-02T00:00:00+00:00')
      expect(subject.percentage_at).to eq(50)
    end
  end
end
