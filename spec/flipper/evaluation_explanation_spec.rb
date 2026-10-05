require 'flipper/feature'
require 'flipper/instrumenters/memory'

RSpec.describe Flipper::EvaluationExplanation do
  subject(:feature) { Flipper::Feature.new(:search, adapter) }

  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:actor) { Flipper::Actor.new("User;1") }

  def gate_evaluation(explanation, name)
    explanation.gates.detect { |gate| gate.name == name }
  end

  describe "Feature#evaluate_with_explanation" do
    context "with a fully disabled feature and no actor" do
      it "returns false with no matched gate" do
        explanation = feature.evaluate_with_explanation

        expect(explanation.result).to be(false)
        expect(explanation.enabled?).to be(false)
        expect(explanation.gate_name).to be_nil
        expect(explanation.matched_gate).to be_nil
      end

      it "executes gates that do not need an actor" do
        explanation = feature.evaluate_with_explanation

        [:boolean, :expression, :percentage_of_time].each do |name|
          gate = gate_evaluation(explanation, name)
          expect(gate.status).to be(:executed), "expected #{name} to be executed"
          expect(gate.open?).to be(false)
        end
      end

      it "explicitly skips gates that need an actor" do
        explanation = feature.evaluate_with_explanation

        [:actor, :percentage_of_actors, :group].each do |name|
          gate = gate_evaluation(explanation, name)
          expect(gate.status).to be(:skipped), "expected #{name} to be skipped"
          expect(gate.reason).to be(:no_actor)
          expect(gate.open?).to be(false)
        end
      end

      it "does not invoke custom group blocks" do
        calls = 0
        Flipper.register(:admins) { |*| calls += 1 }
        feature.enable_group(:admins)

        feature.evaluate_with_explanation

        expect(calls).to eq(0)
      end
    end

    context "with the boolean gate enabled" do
      it "reports the boolean gate as the match and short-circuits the rest" do
        feature.enable

        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.result).to be(true)
        expect(explanation.gate_name).to be(:boolean)
        expect(gate_evaluation(explanation, :boolean).open?).to be(true)

        explanation.gates.drop(1).each do |gate|
          expect(gate.status).to be(:skipped)
          expect(gate.reason).to be(:short_circuit)
        end
      end

      it "never invokes custom group blocks" do
        calls = 0
        Flipper.register(:admins) { |*| calls += 1 }
        feature.enable
        feature.enable_group(:admins)

        feature.evaluate_with_explanation(actor)

        expect(calls).to eq(0)
      end
    end

    context "with the actor gate enabled" do
      it "reports the actor gate as the match" do
        feature.enable_actor(actor)

        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.result).to be(true)
        expect(explanation.gate_name).to be(:actor)
        expect(gate_evaluation(explanation, :boolean).open?).to be(false)
        expect(gate_evaluation(explanation, :actor).open?).to be(true)
        expect(gate_evaluation(explanation, :group).reason).to be(:short_circuit)
      end

      it "executes earlier gates and finds them closed for other actors" do
        feature.enable_actor(actor)

        explanation = feature.evaluate_with_explanation(Flipper::Actor.new("User;2"))

        expect(explanation.result).to be(false)
        expect(explanation.gate_name).to be_nil
        expect(gate_evaluation(explanation, :actor).status).to be(:executed)
        expect(gate_evaluation(explanation, :actor).open?).to be(false)
      end
    end

    context "with a custom group enabled" do
      it "invokes the group block only as many times as a real check" do
        calls = 0
        Flipper.register(:admins) do |user|
          calls += 1
          user.flipper_id == "User;2"
        end
        feature.enable_group(:admins)

        explanation = feature.evaluate_with_explanation(
          Flipper::Actor.new("User;1"),
          Flipper::Actor.new("User;2")
        )

        expect(explanation.result).to be(true)
        expect(explanation.gate_name).to be(:group)
        expect(calls).to eq(2)
      end

      it "invokes the group block exactly once for a single matching actor" do
        calls = 0
        Flipper.register(:admins) { |*| calls += 1; true }
        feature.enable_group(:admins)

        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.result).to be(true)
        expect(calls).to eq(1)
      end
    end

    context "when a group block raises" do
      it "represents the exception explicitly and keeps evaluating" do
        Flipper.register(:broken) { |*| raise "boom" }
        feature.enable_group(:broken)

        explanation = nil
        expect {
          explanation = feature.evaluate_with_explanation(actor)
        }.not_to raise_error

        group = gate_evaluation(explanation, :group)
        expect(group.status).to be(:error)
        expect(group.error?).to be(true)
        expect(group.open?).to be(false)
        expect(group.error).to eq(class: "RuntimeError", message: "boom")
        expect(explanation.result).to be(false)
      end
    end

    context "with percentage of time" do
      it "collects the evidence from a single evaluation" do
        feature.enable_percentage_of_time(50)
        allow_any_instance_of(Flipper::Gates::PercentageOfTime).
          to receive(:rand).and_return(0.99)

        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.result).to be(false)
        expect(gate_evaluation(explanation, :percentage_of_time).status).to be(:executed)
        expect(explanation.result).to eq(feature.enabled?(actor))
      end
    end

    describe "config_version" do
      it "is stable for the same configuration" do
        feature.enable_actor(actor)

        expect(feature.evaluate_with_explanation(actor).config_version).
          to eq(feature.evaluate_with_explanation(actor).config_version)
      end

      it "changes when the configuration changes" do
        before = feature.evaluate_with_explanation(actor).config_version
        feature.enable_actor(actor)

        expect(feature.evaluate_with_explanation(actor).config_version).
          not_to eq(before)
      end
    end

    describe "actor diagnostics" do
      let(:actor) do
        Flipper::Actor.new("User;1", plan: "pro", ssn: "123-45-6789")
      end

      it "includes only flipper_id by default" do
        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.actors).to eq([{ flipper_id: "User;1" }])
      end

      it "never inspects the whole actor" do
        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.actors.inspect).not_to include("123-45-6789")
        expect(explanation.to_h.inspect).not_to include("123-45-6789")
      end

      it "includes properties allowed by configuration" do
        Flipper.configuration.explanation_actor_properties = [:plan]

        explanation = feature.evaluate_with_explanation(actor)

        expect(explanation.actors).to eq([
          { flipper_id: "User;1", properties: { "plan" => "pro" } },
        ])
      end

      it "includes properties allowed per call, overriding configuration" do
        Flipper.configuration.explanation_actor_properties = [:ssn]

        explanation = feature.evaluate_with_explanation(actor, actor_properties: ["plan"])

        expect(explanation.actors).to eq([
          { flipper_id: "User;1", properties: { "plan" => "pro" } },
        ])
      end

      it "is empty when no actors are given" do
        expect(feature.evaluate_with_explanation.actors).to eq([])
      end
    end

    it "agrees with enabled? across configurations" do
      expect(feature.evaluate_with_explanation(actor).result).to eq(feature.enabled?(actor))

      feature.enable
      expect(feature.evaluate_with_explanation(actor).result).to eq(feature.enabled?(actor))

      feature.disable
      feature.enable_actor(actor)
      expect(feature.evaluate_with_explanation(actor).result).to eq(feature.enabled?(actor))
      expect(feature.evaluate_with_explanation(Flipper::Actor.new("User;2")).result).
        to eq(feature.enabled?(Flipper::Actor.new("User;2")))
    end

    it "instruments the evaluation" do
      instrumenter = Flipper::Instrumenters::Memory.new
      feature = Flipper::Feature.new(:search, adapter, instrumenter: instrumenter)
      feature.enable

      explanation = feature.evaluate_with_explanation(actor)

      event = instrumenter.events.last
      expect(event).not_to be_nil
      expect(event.payload[:operation]).to be(:evaluate_with_explanation)
      expect(event.payload[:feature_name]).to be(:search)
      expect(event.payload[:gate_name]).to be(:boolean)
      expect(event.payload[:result]).to be(explanation)
    end

    describe "#to_h" do
      it "returns a serializable summary" do
        feature.enable_actor(actor)

        expect(feature.evaluate_with_explanation(actor).to_h).to eq(
          feature: :search,
          result: true,
          gate: :actor,
          config_version: feature.evaluate_with_explanation(actor).config_version,
          actors: [{ flipper_id: "User;1" }],
          gates: [
            { name: :boolean, status: :executed, open: false },
            { name: :expression, status: :executed, open: false },
            { name: :actor, status: :executed, open: true },
            { name: :percentage_of_actors, status: :skipped, reason: :short_circuit },
            { name: :percentage_of_time, status: :skipped, reason: :short_circuit },
            { name: :group, status: :skipped, reason: :short_circuit },
          ]
        )
      end
    end
  end

  describe "Flipper.evaluate_with_explanation" do
    it "delegates to the default instance" do
      Flipper.enable_actor(:search, actor)

      explanation = Flipper.evaluate_with_explanation(:search, actor)

      expect(explanation).to be_a(described_class)
      expect(explanation.result).to be(true)
      expect(explanation.gate_name).to be(:actor)
    end

    it "passes actor_properties through the DSL" do
      actor = Flipper::Actor.new("User;1", plan: "pro")

      explanation = Flipper.evaluate_with_explanation(:search, actor, actor_properties: [:plan])

      expect(explanation.actors).to eq([
        { flipper_id: "User;1", properties: { "plan" => "pro" } },
      ])
    end
  end
end
