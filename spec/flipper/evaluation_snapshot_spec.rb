require 'flipper/dsl'

RSpec.describe Flipper::DSL, '#with_evaluation_snapshot' do
  subject(:flipper) { Flipper.new(Flipper::Adapters::Memory.new) }

  it 'evaluates multiple checks against one feature configuration version' do
    flipper.enable(:search)
    flipper.disable(:billing)

    result = flipper.with_evaluation_snapshot do
      search_before = flipper.enabled?(:search)
      billing_before = flipper.enabled?(:billing)

      flipper.disable(:search)
      flipper.enable(:billing)

      [
        search_before,
        billing_before,
        flipper.enabled?(:search),
        flipper.enabled?(:billing),
      ]
    end

    expect(result).to eq([true, false, true, false])
    expect(flipper.enabled?(:search)).to be(false)
    expect(flipper.enabled?(:billing)).to be(true)
  end

  it 'applies writes to live configuration without changing the active snapshot' do
    flipper.enable(:search)
    feature = flipper.feature(:search)

    result = flipper.with_snapshot do
      flipper.disable(:search)
      [feature.enabled?, flipper.exist?(:search)]
    end

    expect(result).to eq([true, true])
    expect(flipper.enabled?(:search)).to be(false)
  end

  it 'captures configuration through the snapshot protocol when the scope starts' do
    backend = Flipper::Adapters::Memory.new
    flipper = Flipper.new(backend, memoize: false)
    flipper.enable(:search)
    flipper.enable(:billing)

    expect(backend).to receive(:snapshot).once.and_call_original

    flipper.with_evaluation_snapshot do
      flipper.enabled?(:search)
      flipper.enabled?(:billing)
      flipper.enabled?(:new_feature)
    end
  end

  it 'captures a fresh live version for nested scopes and restores the outer scope' do
    flipper.enable(:search)

    flipper.with_evaluation_snapshot do
      flipper.disable(:search)

      expect(flipper.enabled?(:search)).to be(true)

      flipper.with_evaluation_snapshot do
        expect(flipper.enabled?(:search)).to be(false)
        flipper.enable(:search)
        expect(flipper.enabled?(:search)).to be(false)
      end

      expect(flipper.enabled?(:search)).to be(true)
    end

    expect(flipper.enabled?(:search)).to be(true)
  end

  it 'does not freeze external actor state' do
    actor = Actor.new('1', false)
    Flipper.register(:admins) { |member| member.admin? }
    flipper.enable_group(:search, :admins)

    flipper.with_evaluation_snapshot do
      expect(flipper.enabled?(:search, actor)).to be(false)
      actor.admin = true
      expect(flipper.enabled?(:search, actor)).to be(true)
    end
  end

  it 'returns the block result and removes the scope after an exception' do
    expect do
      flipper.with_evaluation_snapshot { raise 'boom' }
    end.to raise_error('boom')

    flipper.enable(:search)
    expect(flipper.enabled?(:search)).to be(true)
  end

  context 'with eventual consistency' do
    it 'does not pin reads and works without snapshot support' do
      adapter = Class.new { include Flipper::Adapter }.new
      flipper = Flipper.new(adapter, memoize: false)

      flipper.with_evaluation_snapshot(consistency: :eventual) do
        expect(adapter).to receive(:get).twice.and_return(
          Flipper::Adapters::Memory.default_config,
          Flipper::Adapters::Memory.default_config.merge(boolean: 'true')
        )

        expect(flipper.enabled?(:search)).to be(false)
        expect(flipper.enabled?(:search)).to be(true)
      end
    end
  end

  it 'rejects strong consistency when the visible adapter cannot snapshot' do
    adapter = Class.new { include Flipper::Adapter }.new
    flipper = Flipper.new(adapter, memoize: false)

    expect do
      flipper.with_evaluation_snapshot { }
    end.to raise_error(Flipper::SnapshotNotSupported, /does not support consistent evaluation snapshots/)
  end

  it 'rejects an unknown consistency value' do
    expect do
      flipper.with_evaluation_snapshot(consistency: :unsafe) { }
    end.to raise_error(ArgumentError, 'consistency must be :strong or :eventual')
  end

  it 'requires a block' do
    expect do
      flipper.with_evaluation_snapshot
    end.to raise_error(ArgumentError, 'a block is required to define the evaluation snapshot scope')
  end

  it 'allows transparent instrumentation to delegate snapshot support' do
    instrumenter = Flipper::Instrumenters::Memory.new
    adapter = Flipper::Adapters::Instrumented.new(Flipper::Adapters::Memory.new, instrumenter: instrumenter)
    flipper = Flipper.new(adapter, memoize: false)
    flipper.enable(:search)

    flipper.with_evaluation_snapshot do
      flipper.disable(:search)
      expect(flipper.enabled?(:search)).to be(true)
    end
  end

  class Actor
    attr_accessor :flipper_id, :admin

    def initialize(flipper_id, admin)
      @flipper_id = flipper_id
      @admin = admin
    end

    def admin?
      @admin
    end
  end
end

RSpec.describe Flipper::Adapters::Memory, '#snapshot' do
  subject(:adapter) { described_class.new }

  let(:feature) { Flipper::Feature.new(:search, adapter) }

  before do
    adapter.add(feature)
    adapter.enable(feature, feature.gate(:boolean), Flipper::Types::Boolean.new(true))
  end

  it 'supports snapshots' do
    expect(adapter).to be_supports_snapshot
  end

  it 'returns a read-only point-in-time copy' do
    snapshot = adapter.snapshot

    expect(snapshot).to be_read_only
    expect(snapshot.get(feature)).to eq(adapter.get(feature))

    adapter.disable(feature, feature.gate(:boolean), Flipper::Types::Boolean.new(false))

    expect(snapshot.get(feature)[:boolean]).to eq('true')
    expect(adapter.get(feature)[:boolean]).to be_nil
  end

  it 'deep copies mutable gate values from live configuration' do
    actor_gate = feature.gate(:actor)
    adapter.enable(feature, actor_gate, Flipper::Types::Actor.new(Flipper::Actor.new('1')))
    snapshot = adapter.snapshot

    adapter.disable(feature, actor_gate, Flipper::Types::Actor.new(Flipper::Actor.new('1')))

    expect(snapshot.get(feature)[:actors]).to eq(Set['1'])
  end

  it 'freezes snapshot configuration' do
    snapshot = adapter.snapshot

    expect { snapshot.enable(feature, feature.gate(:boolean), Flipper::Types::Boolean.new(false)) }
      .to raise_error(Flipper::Adapters::ReadOnly::WriteAttempted)
    expect(snapshot.get(feature)).to be_frozen
  end
end
