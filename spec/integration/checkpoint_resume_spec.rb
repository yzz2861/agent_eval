# frozen_string_literal: true

require "json"

RSpec.describe "Transaction checkpoints" do
  include_context "container"

  include Dry::Monads[:result]

  let(:calls) { [] }

  before do
    calls_ref = calls

    container.instance_exec do
      register("ops.validate", -> input {
        input[:email] ? Success(input) : Failure(:email_required)
      })
      register("ops.charge", -> input {
        calls_ref << :charge
        Success(input.merge(charged: true))
      })
      register("ops.notify", -> input {
        calls_ref << :notify
        Success(input.merge(notified: true))
      })
    end
  end

  let(:transaction_class) {
    Class.new do
      include Dry::Transaction(container: Test::Container)

      step :validate, with: "ops.validate"
      step :charge, with: "ops.charge", resumable: true
      step :notify, with: "ops.notify", resumable: true
    end
  }

  let(:transaction) { transaction_class.new }
  let(:input) { {email: "jane@doe.com"} }

  def collect_checkpoints
    checkpoints = []
    emit = ->(checkpoint) { checkpoints << checkpoint.to_h }
    [checkpoints, emit]
  end

  describe "forming checkpoints" do
    it "emits a checkpoint before each resumable step with that step's identity, definition version and input" do
      checkpoints, emit = collect_checkpoints

      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      expect(checkpoints.length).to eq 2

      expect(checkpoints[0]["step"]).to eq "charge"
      expect(checkpoints[0]["version"]).to eq transaction.definition_version
      expect(checkpoints[0]["input"]).to eq(email: "jane@doe.com")

      expect(checkpoints[1]["step"]).to eq "notify"
      expect(checkpoints[1]["input"]).to eq(email: "jane@doe.com", charged: true)
    end

    it "does not form checkpoints for steps not declared resumable" do
      transaction_class = Class.new do
        include Dry::Transaction(container: Test::Container)

        step :validate, with: "ops.validate"
        step :charge, with: "ops.charge"
        step :notify, with: "ops.notify", resumable: true
      end

      checkpoints, emit = collect_checkpoints
      transaction_class.new.call_with_checkpoints(input, on_checkpoint: emit)

      expect(checkpoints.map { |cp| cp["step"] }).to eq %w[notify]
    end

    it "produces plain data that survives a serialization round trip" do
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      data = JSON.parse(JSON.generate(checkpoints.first))
      checkpoint = Dry::Transaction::Checkpoint.from_h(data)

      expect(checkpoint.step_name).to eq :charge
      expect(checkpoint.input).to eq("email" => "jane@doe.com")
    end
  end

  describe "resuming" do
    it "resumes from the named step with the recorded input, without re-running earlier steps" do
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      calls.clear
      result = transaction.resume(checkpoints.first)

      expect(calls).to eq %i[charge notify]
      expect(result).to be_success
      expect(result.result.value!).to eq(email: "jane@doe.com", charged: true, notified: true)
    end

    it "recovers from a crash after an unconfirmed step" do
      checkpoints = []
      emit = ->(checkpoint) { checkpoints << checkpoint.to_h }

      allow(container["ops.notify"]).to receive(:call).and_raise(RuntimeError, "boom")
      expect { transaction.call_with_checkpoints(input, on_checkpoint: emit) }.to raise_error(RuntimeError, "boom")

      allow(container["ops.notify"]).to receive(:call).and_call_original
      calls.clear
      result = transaction.resume(checkpoints.last)

      expect(result.resumed_step).to eq :notify
      expect(calls).to eq %i[notify]
      expect(result).to be_success
    end

    it "returns a result requiring caller adjudication rather than claiming exactly-once execution" do
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      result = transaction.resume(checkpoints.first)

      expect(result).to be_requires_adjudication
      expect(result.resumed_step).to eq :charge
    end

    it "continues to emit checkpoints for the remaining resumable steps" do
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      further_checkpoints = []
      transaction.resume(
        checkpoints.first,
        on_checkpoint: ->(checkpoint) { further_checkpoints << checkpoint.to_h }
      )

      expect(further_checkpoints.map { |cp| cp["step"] }).to eq %w[notify]
    end

    it "wraps step failures from the remaining steps" do
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      allow(container["ops.charge"]).to receive(:call).and_return(Failure(:declined))

      result = transaction.resume(checkpoints.first)

      expect(result).to be_failure
      expect(result.result.failure).to eq :declined
    end
  end

  describe "definition version changes" do
    it "refuses to resume a checkpoint recorded against a different definition" do
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)

      changed_class = Class.new do
        include Dry::Transaction(container: Test::Container)

        step :validate, with: "ops.validate"
        step :charge, with: "ops.charge", resumable: true
        step :receipt, with: "ops.notify", resumable: true
      end

      expect {
        changed_class.new.resume(checkpoints.first)
      }.to raise_error(Dry::Transaction::DefinitionVersionMismatchError)
    end

    it "changes the version when resumable declarations change" do
      other_class = Class.new do
        include Dry::Transaction(container: Test::Container)

        step :validate, with: "ops.validate"
        step :charge, with: "ops.charge"
        step :notify, with: "ops.notify", resumable: true
      end

      expect(other_class.new.definition_version).not_to eq transaction.definition_version
    end
  end

  describe "corrupt or inconsistent checkpoint data" do
    let(:checkpoint_data) {
      checkpoints, emit = collect_checkpoints
      transaction.call_with_checkpoints(input, on_checkpoint: emit)
      checkpoints.first
    }

    it "rejects tampered input" do
      tampered = checkpoint_data.merge("input" => {email: "mallory@evil.com"})

      expect { transaction.resume(tampered) }
        .to raise_error(Dry::Transaction::CorruptCheckpointError, /digest/)
    end

    it "rejects data with missing keys" do
      incomplete = checkpoint_data.reject { |key, _| key == "input_digest" }

      expect { transaction.resume(incomplete) }
        .to raise_error(Dry::Transaction::CorruptCheckpointError, /missing/)
    end

    it "rejects non-Hash data" do
      expect { transaction.resume("charge") }
        .to raise_error(Dry::Transaction::CorruptCheckpointError)
    end

    it "rejects checkpoints naming an unknown step" do
      unknown = checkpoint_data.merge("step" => "refund")

      expect { transaction.resume(unknown) }
        .to raise_error(Dry::Transaction::UnknownCheckpointStepError, /refund/)
    end

    it "rejects checkpoints naming a step that is not resumable" do
      non_resumable = checkpoint_data.merge("step" => "validate")

      expect { transaction.resume(non_resumable) }
        .to raise_error(Dry::Transaction::NonResumableStepError, /validate/)
    end
  end
end
