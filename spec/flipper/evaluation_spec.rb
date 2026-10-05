RSpec.describe Flipper::Evaluation do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:actor) { Flipper::Actor.new('User;1', 'plan' => 'basic', 'secret' => 'hidden') }

  before do
    Flipper.unregister_groups
  end

  describe 'Flipper::Feature#evaluate_with_explanation' do
    subject(:feature) { Flipper::Feature.new(:search, adapter) }

    it 'evaluates each applicable gate from one real evaluation' do
      feature.enable_actor actor

      expect(feature).not_to receive(:enabled?)
      expect(feature).to receive(:gate_values).once.and_call_original

      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.result).to be(true)
      expect(evaluation.enabled?).to be(true)
      expect(evaluation.gate).to eq(:actor)
      expect(evaluation.hit_gate).to eq(:actor)
      expect(evaluation.matched_gate).to eq(:actor)
      expect(evaluation.config_version).to eq(1)
      expect(evaluation.configuration_version).to eq(1)
      expect(evaluation.version).to eq(1)
      expect(evaluation[:gate]).to eq(:actor)

      statuses = evaluation.gates.map { |gate| [gate.name, gate.status] }.to_h
      expect(statuses).to eq(
        boolean: :executed,
        expression: :executed,
        actor: :executed,
        percentage_of_actors: :skipped,
        percentage_of_time: :skipped,
        group: :skipped
      )
      expect(evaluation.gates.map(&:reason).compact).to eq(%i[gate_open gate_open gate_open])
      actor_branch = evaluation.gates.find { |branch| branch.gate == :actor }
      expect(actor_branch.executed).to be(true)
      expect(actor_branch.skipped).to be(false)
    end

    it 'executes all applicable gates when none open' do
      feature.disable

      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.result).to be(false)
      expect(evaluation.gate).to be_nil
      expect(evaluation.gates).to all(be_executed)
      expect(evaluation.gates.map(&:result)).to all(be(false))
    end

    it 'represents a missing actor without calling actor-only gates' do
      feature.enable_group :staff
      calls = 0
      Flipper.register(:staff) { calls += 1; true }

      evaluation = feature.evaluate_with_explanation

      expect(evaluation.result).to be(false)
      expect(evaluation.actor_present?).to be(false)
      expect(evaluation.actors).to eq([])
      expect(calls).to eq(0)

      skipped = evaluation.gates.select(&:skipped?).map(&:name)
      expect(skipped).to eq(%i[actor percentage_of_actors group])
      expect(evaluation.gates.select(&:skipped?).map(&:reason)).to all(eq(:actor_missing))
    end

    it 'does not call custom groups after an earlier gate opens' do
      feature.enable
      feature.enable_group :staff
      calls = 0
      Flipper.register(:staff) { calls += 1; true }

      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.result).to be(true)
      expect(evaluation.gate).to eq(:boolean)
      expect(calls).to eq(0)
      group_branch = evaluation.gates.find { |gate| gate.name == :group }
      expect(group_branch).to be_skipped
      expect(group_branch.reason).to eq(:gate_open)
    end

    it 'calls a matching custom group only once' do
      feature.enable_group :staff
      calls = 0
      Flipper.register(:staff) do |group_actor|
        calls += 1
        group_actor.flipper_id == actor.flipper_id
      end

      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.result).to be(true)
      expect(evaluation.gate).to eq(:group)
      expect(calls).to eq(1)
    end

    it 'captures a gate exception and skips remaining gates' do
      feature.enable_group :broken
      Flipper.register(:broken) { raise RuntimeError, 'boom' }

      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.result).to be(false)
      expect(evaluation.error).to eq(
        type: :gate_error,
        class: 'RuntimeError',
        message: 'boom'
      )

      group_branch = evaluation.gates.find { |gate| gate.name == :group }
      expect(group_branch).to be_error
      expect(group_branch.error).to eq(evaluation.error)
      expect(evaluation.gates.map(&:status)).to eq(
        %i[executed executed executed executed executed error]
      )
    end

    it 'captures an adapter exception without re-running gates' do
      allow(adapter).to receive(:get).and_raise(RuntimeError, 'adapter down')

      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.result).to be(false)
      expect(evaluation.error).to eq(
        type: :evaluation_error,
        class: 'RuntimeError',
        message: 'adapter down'
      )
      expect(evaluation.gates.map(&:status)).to all(eq(:skipped))
      expect(evaluation.gates.map(&:reason)).to all(eq(:evaluation_error))
    end

    it 'represents an invalid actor without inspecting the whole object' do
      invalid_actor = Object.new
      evaluation = feature.evaluate_with_explanation(invalid_actor)

      expect(evaluation.result).to be(false)
      expect(evaluation.error).to eq(type: :invalid_actor, class: 'ArgumentError')
      expect(evaluation.actors).to eq([])
      expect(evaluation.gates.map(&:reason)).to all(eq(:invalid_actor))
      expect(evaluation.to_h.to_s).not_to include(invalid_actor.inspect)
    end

    it 'includes only flipper_id by default' do
      evaluation = feature.evaluate_with_explanation(actor)

      expect(evaluation.actors).to eq([{ flipper_id: 'User;1' }])
      expect(evaluation.actor).to eq(flipper_id: 'User;1')
    end

    it 'allows selected flipper properties' do
      evaluation = feature.evaluate_with_explanation(actor, actor_properties: %i[plan])

      expect(evaluation.actors).to eq([
        flipper_id: 'User;1',
        properties: { 'plan' => 'basic' }
      ])
    end

    it 'allows all flipper properties' do
      evaluation = feature.evaluate_with_explanation(actor, actor_properties: true)

      expect(evaluation.actors.first[:properties]).to eq(
        'plan' => 'basic',
        'secret' => 'hidden'
      )
    end

    it 'allows application-provided actor diagnostics' do
      received_actor = nil
      evaluation = feature.evaluate_with_explanation(actor) do |raw_actor|
        received_actor = raw_actor
        { id: raw_actor.flipper_id }
      end

      expect(evaluation.actors).to eq([
        flipper_id: 'User;1',
        properties: { id: 'User;1' }
      ])
      expect(received_actor).to be(actor)
    end

    it 'does not inspect an actor missing flipper_properties in warnings' do
      feature.enable_expression(Flipper.property(:plan).eq('basic'))
      raw_actor = Object.new
      def raw_actor.flipper_id
        'User;2'
      end

      expect {
        feature.evaluate_with_explanation(raw_actor)
      }.not_to output(raw_actor.inspect).to_stderr
    end

    it 'is available through the DSL and Flipper module' do
      flipper = Flipper.new(adapter)
      feature.enable_actor actor

      dsl_evaluation = flipper.evaluate_with_explanation(:search, actor) do |raw_actor|
        { id: raw_actor.flipper_id }
      end
      expect(dsl_evaluation.gate).to eq(:actor)
      expect(dsl_evaluation.actors.first[:properties]).to eq(id: 'User;1')

      Flipper.configuration = Flipper::Configuration.new
      Flipper.configuration.default { flipper }
      expect(Flipper.evaluate_with_explanation(:search, actor).gate).to eq(:actor)
    end
  end
end
