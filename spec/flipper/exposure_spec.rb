require 'flipper/exposure'

RSpec.describe Flipper::Exposure do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:collector) { Flipper::Exposure::Collectors::Memory.new }
  let(:flipper) { Flipper.new(adapter, exposure_collector: collector) }
  let(:actor) { Flipper::Actor.new('User;1') }

  describe 'DSL#evaluate' do
    it 'returns a decision matching the enabled check' do
      flipper.enable(:search)

      expect(flipper.evaluate(:search).enabled?).to be(true)
      expect(flipper.evaluate(:other).enabled?).to be(false)
    end

    it 'binds feature, actor identity, decision and config version' do
      flipper.enable_actor(:search, actor)

      decision = flipper.evaluate(:search, actor)

      expect(decision.feature_name).to eq(:search)
      expect(decision.actor_id).to eq('User;1')
      expect(decision.enabled?).to be(true)
      expect(decision.config_version).to match(/[0-9a-f]{64}/)
      expect(decision.credential_id).not_to be_nil
    end

    it 'uses a nil actor identity when evaluating without actors' do
      expect(flipper.evaluate(:search).actor_id).to be_nil
    end

    it 'changes config version when gate values change' do
      before = flipper.evaluate(:search).config_version
      flipper.enable(:search)
      after = flipper.evaluate(:search).config_version

      expect(after).not_to eq(before)
    end

    it 'records nothing until confirmed, even when pre-read but unused' do
      # Simulates a request that pre-reads several features but the page only
      # ends up using one of them.
      decisions = flipper.preload([:search, :banner]).map do |feature|
        feature.evaluate(actor)
      end

      expect(collector.events).to be_empty

      decisions.first.confirm

      expect(collector.events.size).to eq(1)
      expect(collector.events.first.feature_name).to eq(:search)
    end
  end

  describe 'Decision#confirm' do
    it 'submits an exposure event with the bound attributes' do
      flipper.enable_actor(:search, actor)
      decision = flipper.evaluate(:search, actor)

      expect(decision.confirm).to be(true)
      expect(decision.confirmed?).to be(true)

      event = collector.events.first
      expect(event.credential_id).to eq(decision.credential_id)
      expect(event.feature_name).to eq(:search)
      expect(event.actor_id).to eq('User;1')
      expect(event.enabled).to be(true)
      expect(event.config_version).to eq(decision.config_version)
    end

    it 'never re-evaluates, so attribution cannot drift' do
      decision = flipper.evaluate(:search, actor)
      flipper.enable(:search)

      decision.confirm

      event = collector.events.first
      expect(event.enabled).to be(false)
      expect(event.config_version).to eq(decision.config_version)
    end

    it 'does not double count repeated confirms of the same decision' do
      decision = flipper.evaluate(:search, actor)

      decision.confirm
      expect(decision.confirm).to be(false)

      expect(collector.events.size).to eq(1)
    end

    it 'dedupes on the caller supplied idempotency key' do
      one = flipper.evaluate(:search, actor)
      two = flipper.evaluate(:search, actor)

      expect(one.confirm(idempotency_key: 'request-1')).to be(true)
      expect(two.confirm(idempotency_key: 'request-1')).to be(false)
      expect(two.confirm(idempotency_key: 'request-2')).to be(true)

      expect(collector.events.size).to eq(2)
      expect(collector.events.map(&:idempotency_key)).to eq(%w[request-1 request-2])
    end

    it 'does not raise or corrupt the decision when the collector fails' do
      failing = Class.new do
        def record(_event)
          raise 'collector is down'
        end
      end.new
      flipper = Flipper.new(adapter, exposure_collector: failing)
      flipper.enable(:search)

      decision = flipper.evaluate(:search, actor)

      expect(decision.confirm).to be(false)
      expect(decision.confirmed?).to be(false)
      expect(decision.enabled?).to be(true)
    end
  end

  describe Flipper::Exposure::Collectors::Memory do
    it 'is the default exposure collector' do
      expect(Flipper.new(adapter).exposure_collector)
        .to be_a(Flipper::Exposure::Collectors::Memory)
    end

    it 'clears recorded events and idempotency keys' do
      decision = flipper.evaluate(:search, actor)
      decision.confirm(idempotency_key: 'request-1')
      collector.clear

      expect(collector.events).to be_empty
      expect(flipper.evaluate(:search, actor).confirm(idempotency_key: 'request-1')).to be(true)
    end
  end
end
