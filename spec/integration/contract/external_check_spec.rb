# frozen_string_literal: true

RSpec.describe Dry::Validation::Contract, ".external_check" do
  subject(:contract) { contract_class.new }

  let(:records) do
    { "D1" => { active: true }, "D2" => { active: false } }
  end

  let(:querier_calls) { [] }

  let(:querier) do
    calls = querier_calls
    store = records

    lambda do |keys, partition|
      calls << [keys, partition]
      store.slice(*keys)
    end
  end

  let(:contract_class) do
    department_querier = querier

    Class.new(Dry::Validation::Contract) do
      params do
        required(:department_code).filled(:string)
      end

      external_check :department,
                     on: :department_code,
                     normalize: ->(code) { code.to_s.strip.upcase },
                     partition: ->(context) { context[:tenant_id] },
                     query: department_querier,
                     condition: ->(department) { department[:active] }
    end
  end

  shared_examples "a department check" do
    it "passes when the record exists and satisfies the condition" do
      expect(validate("D1").errors.to_h).to be_empty
    end

    it "normalizes keys before querying" do
      validate(" d1 ")

      expect(querier_calls.last.first).to eql(%w[D1])
    end

    it "fails with the not_found message when no record exists" do
      expect(validate("D9").errors.to_h).to eql(department_code: ["does not exist"])
    end

    it "fails with the rejected message when the condition is not met" do
      expect(validate("D2").errors.to_h).to eql(department_code: ["is not valid"])
    end

    it "is skipped when the schema reports an error for the key" do
      expect(validate(nil).errors.to_h).to eql(department_code: ["must be filled"])
      expect(querier_calls).to be_empty
    end
  end

  context "without a batch session" do
    def validate(code, **context)
      contract.call({ department_code: code }, context)
    end

    include_examples "a department check"

    it "calls the querier once per validated input" do
      validate("D1")
      validate("D1")

      expect(querier_calls).to eql([[["D1"], nil], [["D1"], nil]])
    end

    it "passes the context partition to the querier" do
      validate("D1", tenant_id: "t1")

      expect(querier_calls).to eql([[["D1"], "t1"]])
    end

    it "freezes the result" do
      expect(validate("D1")).to be_frozen
    end
  end

  context "within a batch session" do
    let(:session) { Dry::Validation::Batch::Session.new }

    def validate(code, **context)
      session.call(contract, { department_code: code }, context).tap do
        session.finalize
      end
    end

    include_examples "a department check"

    it "merges duplicate normalized keys into one querier call" do
      results = [" d1 ", "D1", "D2", "d2", "D9"].map { |code|
        session.call(contract, department_code: code)
      }

      session.finalize

      expect(querier_calls).to eql([[["D1", "D2", "D9"], nil]])
      expect(results.map { |r| r.errors.to_h }).to eql(
        [
          {},
          {},
          { department_code: ["is not valid"] },
          { department_code: ["is not valid"] },
          { department_code: ["does not exist"] }
        ]
      )
    end

    it "passes keys to the querier in the order they were first seen" do
      %w[D2 D1 D2 D9 D1].each { |code| session.call(contract, department_code: code) }

      session.finalize

      expect(querier_calls).to eql([[["D2", "D1", "D9"], nil]])
    end

    it "does not merge keys from different context partitions" do
      session.call(contract, { department_code: "D1" }, tenant_id: "t1")
      session.call(contract, { department_code: "D1" }, tenant_id: "t2")
      session.call(contract, { department_code: "D2" }, tenant_id: "t1")

      session.finalize

      expect(querier_calls).to eql(
        [
          [["D1", "D2"], "t1"],
          [["D1"], "t2"]
        ]
      )
    end

    it "does not merge keys from different query definitions" do
      other_class = Class.new(Dry::Validation::Contract) do
        params do
          required(:department_code).filled(:string)
        end

        external_check :other_department,
                       on: :department_code,
                       query: ->(keys, _partition) { { "D1" => { active: true } } }
      end

      session.call(contract, department_code: "D1")
      session.call(other_class.new, department_code: "D1")

      session.finalize

      expect(querier_calls).to eql([[["D1"], nil]])
    end

    it "freezes the results when finalized" do
      result = session.call(contract, department_code: "D1")

      expect(result).not_to be_frozen

      session.finalize

      expect(result).to be_frozen
    end

    it "exposes the validated results in order" do
      first = session.call(contract, department_code: "D1")
      second = session.call(contract, department_code: "D2")

      expect(session.results).to eql([first, second])
    end

    it "raises when validating after finalization" do
      session.finalize

      expect { session.call(contract, department_code: "D1") }
        .to raise_error(Dry::Validation::Batch::FinalizedError, /finalized/)
    end

    it "is a no-op when finalized twice" do
      session.call(contract, department_code: "D1")

      session.finalize
      session.finalize

      expect(querier_calls.size).to be(1)
    end
  end

  context "when the querier fails" do
    let(:querier) do
      ->(_keys, _partition) { raise "connection refused" }
    end

    it "reports a base error instead of a not_found key error" do
      result = contract.call(department_code: "D9")

      expect(result.errors.to_h).to eql(nil => ["could not be verified"])
      expect(result.errors.filter(:base?).map(&:to_s)).to eql(["could not be verified"])
    end

    it "reports a base error for every affected result in a batch" do
      results = Dry::Validation.batch do |batch|
        2.times { batch.call(contract, department_code: "D9") }
      end.results

      expect(results.map { |r| r.errors.to_h }).to eql(
        [{ nil => ["could not be verified"] }, { nil => ["could not be verified"] }]
      )
    end
  end

  context "with custom messages" do
    let(:contract_class) do
      department_querier = querier

      Class.new(Dry::Validation::Contract) do
        params do
          required(:department_code).filled(:string)
        end

        external_check :department,
                       on: :department_code,
                       query: department_querier,
                       condition: ->(department) { department[:active] },
                       not_found: "department does not exist",
                       rejected: "department is not active",
                       unavailable: "department service is unavailable"
      end
    end

    it "uses the custom not_found message" do
      expect(contract.call(department_code: "D9").errors.to_h)
        .to eql(department_code: ["department does not exist"])
    end

    it "uses the custom rejected message" do
      expect(contract.call(department_code: "D2").errors.to_h)
        .to eql(department_code: ["department is not active"])
    end

    context "when the querier fails" do
      let(:querier) do
        ->(_keys, _partition) { raise "connection refused" }
      end

      it "uses the custom unavailable message" do
        expect(contract.call(department_code: "D1").errors.to_h)
          .to eql(nil => ["department service is unavailable"])
      end
    end
  end

  context "with a nested key" do
    let(:contract_class) do
      department_querier = querier

      Class.new(Dry::Validation::Contract) do
        params do
          required(:department).hash do
            required(:code).filled(:string)
          end
        end

        external_check :department,
                       on: { department: :code },
                       normalize: ->(code) { code.to_s.strip.upcase },
                       query: department_querier
      end
    end

    it "queries using the nested value" do
      contract.call(department: { code: " d1 " })

      expect(querier_calls).to eql([[["D1"], nil]])
    end

    it "reports errors under the nested path" do
      expect(contract.call(department: { code: "D9" }).errors.to_h)
        .to eql(department: { code: ["does not exist"] })
    end

    it "is skipped when the schema reports an error for the nested key" do
      expect(contract.call(department: { code: nil }).errors.to_h)
        .to eql(department: { code: ["must be filled"] })
      expect(querier_calls).to be_empty
    end
  end

  context "with ordinary rules" do
    let(:contract_class) do
      department_querier = querier

      Class.new(Dry::Validation::Contract) do
        params do
          required(:department_code).filled(:string)
        end

        rule(:department_code) do
          key.failure("must be uppercase") if value != value.upcase
        end

        external_check :department,
                       on: :department_code,
                       normalize: ->(code) { code.to_s.strip.upcase },
                       query: department_querier
      end
    end

    it "still applies rules within a batch session" do
      results = Dry::Validation.batch do |batch|
        batch.call(contract, department_code: "d1")
        batch.call(contract, department_code: "D1")
      end.results

      expect(results[0].errors.to_h).to eql(department_code: ["must be uppercase"])
      expect(results[1].errors.to_h).to be_empty
      expect(querier_calls).to eql([[["D1"], nil]])
    end
  end

  context "when a contract has no external checks" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:name).filled(:string)
        end
      end
    end

    it "can be validated within a batch session" do
      results = Dry::Validation.batch do |batch|
        batch.call(contract, name: "Jane")
      end.results

      expect(results.size).to be(1)
      expect(results.first).to be_success
      expect(results.first).to be_frozen
    end
  end
end
