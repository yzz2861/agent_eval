# frozen_string_literal: true

require "json"

RSpec.describe "Transaction checkpoints" do
  include Dry::Monads[:result]

  let(:log) { [] }
  let(:failures) { [] }

  let(:checkpointer_class) do
    Class.new do
      attr_reader :records

      def initialize
        @records = []
      end

      def save(record)
        @records << record
      end
    end
  end

  let(:checkpointer) { checkpointer_class.new }

  let(:transaction_class) do
    log = self.log
    failures = self.failures

    Class.new do
      include Dry::Transaction()

      step :prepare, resumable: true
      step :persist, resumable: true
      step :notify

      define_method :prepare do |input|
        log << :prepare
        Success(input.merge(prepared: true))
      end

      define_method :persist do |input|
        log << :persist
        if failures.include?(:persist)
          Failure(:persist_failed)
        else
          Success(input.merge(persisted: true))
        end
      end

      define_method :notify do |input|
        log << :notify
        Success(input.merge(notified: true))
      end
    end
  end

  let(:transaction) { transaction_class.new }
  let(:input) { {name: "Jane"} }

  def completed_record(step_name)
    checkpointer.records.reverse.find { |r| r["step"] == step_name.to_s && r["status"] == "completed" }
  end

  describe "checkpoint formation" do
    it "saves started and completed checkpoints for resumable steps only" do
      transaction.call(input, checkpointer)

      expect(checkpointer.records.map { |r| [r["step"], r["status"]] }).to eq [
        ["prepare", "started"],
        ["prepare", "completed"],
        ["persist", "started"],
        ["persist", "completed"]
      ]
    end

    it "records the definition version and the next step input as plain data" do
      transaction.call(input, checkpointer)

      record = completed_record(:prepare)

      expect(record["version"]).to eq transaction.checkpoint_version
      expect(record["input"]).to eq(name: "Jane", prepared: true)
      expect(record["input_digest"]).to eq Dry::Transaction::Checkpoint::Record.digest(record["input"])
    end

    it "does not save checkpoints for failed steps" do
      failures << :persist
      transaction.call(input, checkpointer)

      expect(checkpointer.records.map { |r| [r["step"], r["status"]] }).to eq [
        ["prepare", "started"],
        ["prepare", "completed"],
        ["persist", "started"]
      ]
    end
  end

  describe "resuming from a completed checkpoint" do
    before { failures << :persist }

    it "continues from the step after the checkpointed one" do
      expect(transaction.call(input, checkpointer)).to be_failure

      failures.delete(:persist)
      resumed_checkpointer = checkpointer_class.new
      outcome = transaction.resume(completed_record(:prepare), resumed_checkpointer)

      expect(outcome).to be_a Dry::Transaction::Checkpoint::Resumed
      expect(outcome).to be_success
      expect(outcome.result.value!).to eq(name: "Jane", prepared: true, persisted: true, notified: true)

      # :prepare ran only in the first process; resume did not re-run it
      expect(log).to eq %i[prepare persist persist notify]

      # remaining resumable steps keep emitting checkpoints
      expect(resumed_checkpointer.records.map { |r| [r["step"], r["status"]] }).to eq [
        ["persist", "started"],
        ["persist", "completed"]
      ]
    end

    it "wraps the failure when a later step fails" do
      transaction.call(input, checkpointer)

      outcome = transaction.resume(completed_record(:prepare))

      expect(outcome).to be_a Dry::Transaction::Checkpoint::Resumed
      expect(outcome).to be_failure
      expect(outcome.result).to eq Failure(:persist_failed)
    end

    it "continues with the steps after the last resumable step" do
      failures.delete(:persist)
      transaction.call(input, checkpointer)

      outcome = transaction.resume(completed_record(:persist))

      expect(outcome).to be_a Dry::Transaction::Checkpoint::Resumed
      expect(outcome.result.value!).to eq(name: "Jane", prepared: true, persisted: true, notified: true)
    end

    it "accepts caller data with symbol keys" do
      transaction.call(input, checkpointer)
      failures.delete(:persist)

      symbolized = completed_record(:prepare).to_h { |key, value| [key.to_sym, value] }
      outcome = transaction.resume(symbolized)

      expect(outcome).to be_a Dry::Transaction::Checkpoint::Resumed
      expect(outcome).to be_success
    end

    it "supports records persisted as JSON" do
      transaction.call(input, checkpointer)
      failures.delete(:persist)

      restored = JSON.parse(JSON.generate(completed_record(:prepare)))
      outcome = transaction.resume(restored)

      expect(outcome).to be_a Dry::Transaction::Checkpoint::Resumed
      expect(outcome).to be_success
    end
  end

  describe "resuming from an unconfirmed checkpoint" do
    it "returns an Ambiguous outcome for caller adjudication without running anything" do
      transaction.call(input, checkpointer)
      record = checkpointer.records.find { |r| r["step"] == "persist" && r["status"] == "started" }

      log.clear
      outcome = transaction.resume(record)

      expect(outcome).to be_a Dry::Transaction::Checkpoint::Ambiguous
      expect(outcome.step_name).to eq :persist
      expect(outcome.input).to eq(name: "Jane", prepared: true)
      expect(log).to be_empty
    end
  end

  describe "resuming with a changed definition" do
    let(:changed_transaction_class) do
      Class.new do
        include Dry::Transaction()

        step :prepare, resumable: true
        step :persist, resumable: true
        step :audit
        step :notify

        define_method(:prepare) { |input| Dry::Monads::Success(input) }
        define_method(:persist) { |input| Dry::Monads::Success(input) }
        define_method(:audit) { |input| Dry::Monads::Success(input) }
        define_method(:notify) { |input| Dry::Monads::Success(input) }
      end
    end

    it "returns a VersionMismatch outcome instead of guessing a position" do
      transaction.call(input, checkpointer)
      changed = changed_transaction_class.new

      outcome = changed.resume(completed_record(:prepare))

      expect(outcome).to be_a Dry::Transaction::Checkpoint::VersionMismatch
      expect(outcome.checkpoint_version).to eq transaction.checkpoint_version
      expect(outcome.current_version).to eq changed.checkpoint_version
      expect(outcome.checkpoint_version).not_to eq outcome.current_version
    end
  end

  describe "resuming with corrupted data" do
    before { transaction.call(input, checkpointer) }

    it "rejects non-hash data" do
      expect { transaction.resume("checkpoint") }
        .to raise_error(Dry::Transaction::CorruptedCheckpointError, /must be a Hash/)
    end

    it "rejects data with missing keys" do
      expect { transaction.resume({}) }
        .to raise_error(Dry::Transaction::CorruptedCheckpointError, /step identity/)

      expect { transaction.resume(completed_record(:prepare).reject { |k, _| k == "version" }) }
        .to raise_error(Dry::Transaction::CorruptedCheckpointError, /version/)
    end

    it "rejects an unknown status" do
      expect { transaction.resume(completed_record(:prepare).merge("status" => "done")) }
        .to raise_error(Dry::Transaction::CorruptedCheckpointError, /status/)
    end

    it "rejects tampered input" do
      tampered = completed_record(:prepare).merge("input" => {"name" => "Mallory"})

      expect { transaction.resume(tampered) }
        .to raise_error(Dry::Transaction::CorruptedCheckpointError, /integrity/)
    end

    it "rejects a checkpoint for an unknown step" do
      expect { transaction.resume(completed_record(:prepare).merge("step" => "unknown")) }
        .to raise_error(Dry::Transaction::UnresumableCheckpointError, /unknown/)
    end

    it "rejects a checkpoint for a step not declared resumable" do
      record = Dry::Transaction::Checkpoint::Record.build(
        step_name: :notify,
        version: transaction.checkpoint_version,
        status: :completed,
        input: {}
      ).to_h

      expect { transaction.resume(record) }
        .to raise_error(Dry::Transaction::UnresumableCheckpointError, /notify/)
    end
  end
end
