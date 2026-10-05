RSpec.describe 'Flipper rollout schedule integration' do
  let(:flipper) { Flipper.new(Flipper::Adapters::Memory.new, clock: clock, memoize: false) }
  let(:clock) { double('clock') }
  let(:actors) { (1..200).map { |n| Flipper::Actor.new("User;#{n}") } }

  let(:window) do
    {
      starts_at: '2026-10-05T10:00:00+08:00',
      ends_at: '2026-10-05T18:00:00+08:00',
      from_percentage: 10,
      to_percentage: 50,
      mode: :linear
    }
  end

  def time(timestamp)
    Time.iso8601("2026-10-05T#{timestamp}+08:00")
  end

  before do
    flipper.set_rollout_schedule(:search, windows: [window])
  end

  it 'does nothing before the schedule starts' do
    allow(clock).to receive(:call).and_return(time('09:59:59'))
    expect(flipper.enabled?(:search, actors.first)).to be(false)
  end

  it 'rolls out at precise boundary times without sleeping' do
    schedule = flipper.rollout_schedule(:search)
    expect(flipper.feature(:search).enabled_gate_names).to eq([])

    { '10:00:00' => 0.10, '14:00:00' => 0.30, '18:00:00' => 0.50 }.each do |timestamp, fraction|
      boundary = time(timestamp)
      allow(clock).to receive(:call).and_return(boundary)
      enabled = actors.count { |actor| flipper.enabled?(:search, actor) }
      expect(schedule.percentage(boundary)).to eq((fraction * 100).to_i)
      expect(enabled.to_f / actors.size).to be_within(0.08).of(fraction)
    end
  end

  it 'holds the final percentage after the plan ends (default behavior)' do
    allow(clock).to receive(:call).and_return(time('23:59:59'))
    enabled = actors.count { |actor| flipper.enabled?(:search, actor) }
    expect(enabled.to_f / actors.size).to be_within(0.08).of(0.50)
  end

  context 'manual kill switch' do
    before do
      allow(clock).to receive(:call).and_return(time('18:00:00'))
      flipper.enable_actor(:search, actors.first)
    end

    it 'overrides the schedule, actor, group and percentage gates' do
      expect(flipper.enabled?(:search, actors.first)).to be(true)
      flipper.disable_rollout(:search)
      expect(flipper.rollout_disabled?(:search)).to be(true)
      expect(flipper.enabled?(:search, actors.first)).to be(false)
      expect(flipper.enabled?(:search, actors.last)).to be(false)
    end

    it 'is cleared by enable_rollout without changing the schedule' do
      flipper.disable_rollout(:search)
      flipper.enable_rollout(:search)
      expect(flipper.enabled?(:search, actors.first)).to be(true)
      expect(flipper.rollout_schedule(:search).to_h['windows'].size).to eq(1)
    end

    it 'is cleared when a new schedule is configured' do
      flipper.disable_rollout(:search)
      flipper.set_rollout_schedule(:search, windows: [window])
      expect(flipper.rollout_disabled?(:search)).to be(false)
    end

    it 'does not override a full boolean enable' do
      flipper.disable_rollout(:search)
      flipper.enable(:search)
      expect(flipper.enabled?(:search, actors.first)).to be(true)
    end

    it 'raises when disabling a feature without a schedule' do
      expect { flipper.disable_rollout(:nope) }
        .to raise_error(ArgumentError, /no rollout schedule/)
    end
  end

  context 'after_end: :off' do
    it 'returns to fully off once the final window ends' do
      flipper.set_rollout_schedule(:search, windows: [window], after_end: :off)
      allow(clock).to receive(:call).and_return(time('17:59:59'))
      expect(actors.count { |actor| flipper.enabled?(:search, actor) }).to be > 0
      allow(clock).to receive(:call).and_return(time('18:00:01'))
      expect(actors.count { |actor| flipper.enabled?(:search, actor) }).to eq(0)
    end
  end

  it 'returns false when checked without an actor, like percentage_of_actors' do
    allow(clock).to receive(:call).and_return(time('18:00:00'))
    expect(flipper.enabled?(:search)).to be(false)
  end

  it 'does not require a clock and falls back to Time.now' do
    natural = Flipper.new(Flipper::Adapters::Memory.new, memoize: false)
    natural.set_rollout_schedule(:search, windows: [window])
    expect { natural.enabled?(:search, actors.first) }.not_to raise_error
  end

  it 'opens when any of several actors is in the rollout bucket' do
    allow(clock).to receive(:call).and_return(time('18:00:00'))
    bucketed_in = actors.find do |actor|
      flipper.rollout_schedule(:search).bucket_for(actor, :search) < 50_000
    end
    expect(bucketed_in).not_to be_nil
    expect(flipper.enabled?(:search, actors.last, bucketed_in)).to be(true)
  end

  it 'instruments the gate name for schedule hits and kill switches' do
    allow(clock).to receive(:call).and_return(time('18:00:00'))
    events = []
    instrumenter = Object.new
    instrumenter.define_singleton_method(:instrument) do |_name, payload, &block|
      result = block.call(payload)
      events << [payload[:operation], payload[:gate_name], result]
      result
    end
    observed = Flipper.new(Flipper::Adapters::Memory.new,
                            clock: clock, memoize: false, instrumenter: instrumenter)
    observed.set_rollout_schedule(:search, windows: [window])
    observed.enable(:search)
    observed.enabled?(:search, actors.first)
    observed.disable(:search)
    observed.disable_rollout(:search)
    observed.enabled?(:search, actors.first)
    enabled_checks = events.select { |operation, _gate_name, _result| operation == :enabled? }
    expect(enabled_checks.map { |event| event[1..] }).to eq([
      [:boolean, true], [:rollout_schedule_kill_switch, false]
    ])
  end

  it 'removes the schedule and kill switch' do
    flipper.disable_rollout(:search)
    flipper.remove_rollout_schedule(:search)
    expect(flipper.rollout_schedule(:search)).to be_nil
    expect(flipper.rollout_disabled?(:search)).to be(false)
  end
end
