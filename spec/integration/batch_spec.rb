# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Batch do
  subject(:batch) { described_class.new }

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      def self.name
        "ContractImport"
      end

      params do
        required(:department_id).filled(:string)
        optional(:reason).filled(:string)
      end

      rule(:reason) do
        next unless key?

        key.failure("reason is too long") if value.length > 5
      end

      rule(:department_id) do
        external(:department, values[:department_id]) do |outcome:|
          if outcome.missing?
            key.failure("department does not exist")
          elsif outcome.error?
            key.failure("could not verify department")
          elsif !outcome.record.fetch(:active)
            key.failure("department is not active")
          end
        end
      end
    end
  end

  let(:contract) { contract_class.new }

  describe "#register_query / #flush" do
    let(:calls) { [] }

    let(:lookup) do
      lambda { |keys|
        calls << keys.dup
        keys.to_h { |key| [key, {active: !key.start_with?("inactive:")}] }
      }
    end

    before do
      batch.register_query(:department, &lookup)
    end

    it "collects keys, calls the query once and replays the outcomes" do
      batch.call(contract, department_id: "D-1")
      batch.call(contract, department_id: "D-2")
      batch.call(contract, department_id: "D-1")
      batch.call(contract, department_id: "D-3")

      expect(calls).to eql([])

      results = batch.flush

      expect(calls).to eql([%w[D-1 D-2 D-3]])
      expect(results.map { |result| result.errors.to_h }).to eql([{}, {}, {}, {}])
      expect(results).to all(be_frozen)
      expect(batch).to be_flushed
    end

    it "registers queries through the constructor block and stays unfrozen until flush" do
      block_calls = []

      configured = described_class.new do |session|
        session.register_query(:department) { |keys|
          block_calls << keys.dup
          keys.to_h { [_1, {active: true}] }
        }
      end

      result = configured.call(contract, department_id: "D-1")

      expect(result).not_to be_frozen
      expect(block_calls).to eql([])

      configured.flush

      expect(block_calls).to eql([["D-1"]])
      expect(result).to be_frozen
    end

    it "deduplicates normalized keys while preserving input order" do
      region_calls = []

      batch.register_query(
        :region,
        normalize: ->(key) { key.to_s.strip.downcase }
      ) { |keys|
        region_calls << keys.dup
        keys.to_h { [_1, true] }
      }

      normalizing_contract = Class.new(Dry::Validation::Contract) do
        params { required(:region).filled(:string) }

        rule(:region) do
          external(:region, value) do |outcome:|
            key.failure("unknown region") unless outcome.found?
          end
        end
      end.new

      batch.call(normalizing_contract, region: " EU-West ")
      batch.call(normalizing_contract, region: "eu-west")
      batch.call(normalizing_contract, region: "APAC")
      batch.call(normalizing_contract, region: " apac ")
      batch.flush

      expect(region_calls).to eql([["eu-west", "apac"]])
    end

    it "distinguishes missing records from failed lookups" do
      failing_batch = described_class.new
      failing_batch.register_query(:department, partition: :tenant) do |keys, tenant|
        calls << [tenant, keys.dup]

        case tenant
        when "offline"
          raise ::IOError, "network unavailable"
        else
          keys.to_h { |key| key == "ghost" ? [key, nil] : [key, {active: true}] }
        end
      end

      network_error = failing_batch.call(contract, {department_id: "boom"}, tenant: "offline")
      missing = failing_batch.call(contract, {department_id: "ghost"}, tenant: "online")
      found = failing_batch.call(contract, {department_id: "real"}, tenant: "online")
      failing_batch.flush

      expect(calls).to eql([
        ["offline", ["boom"]],
        ["online", %w[ghost real]]
      ])
      expect(network_error.errors.to_h).to eql(department_id: ["could not verify department"])
      expect(missing.errors.to_h).to eql(department_id: ["department does not exist"])
      expect(found.errors.to_h).to eql({})
    end

    it "marks keys absent from the response as missing records" do
      partial_batch = described_class.new
      partial_batch.register_query(:department) do |_keys|
        {"known" => {active: true}}
      end

      result = partial_batch.call(contract, department_id: "unknown")
      partial_batch.flush

      expect(result.errors.to_h).to eql(
        department_id: ["department does not exist"]
      )
    end

    it "reports business-condition failures separately from missing records" do
      result = batch.call(contract, department_id: "inactive:9")
      batch.flush

      expect(result.errors.to_h).to eql(
        department_id: ["department is not active"]
      )
    end

    it "keeps ordinary rules running during the initial call" do
      result = batch.call(contract, department_id: "D-1", reason: "way too long")
      batch.flush

      expect(result.errors.to_h).to eql(reason: ["reason is too long"])
    end

    it "skips mergeable checks when schema checks failed" do
      batch.call(contract, department_id: nil)
      results = batch.flush

      expect(calls).to eql([])
      expect(results.first.errors.to_h).to eql(
        department_id: ["must be filled"]
      )
    end
  end

  describe "context partitions" do
    let(:calls) { [] }

    it "only merges keys within the same query and context partition" do
      batch.register_query(:department, partition: :tenant) do |keys, tenant|
        calls << [tenant, keys.dup]
        keys.to_h { |key| [key, {active: true}] }
      end

      batch.call(contract, {department_id: "A"}, tenant: "t1")
      batch.call(contract, {department_id: "B"}, tenant: "t2")
      batch.call(contract, {department_id: "A"}, tenant: "t1")
      batch.call(contract, {department_id: "A"}, tenant: "t2")
      batch.flush

      expect(calls).to eql([
        ["t1", ["A"]],
        ["t2", %w[B A]]
      ])
    end

    it "supports a callable partitioner and passes the context snapshot" do
      seen_contexts = []

      batch.register_query(
        :department,
        partition: ->(context) { context.fetch(:tenant).upcase }
      ) do |keys, _partition, context|
        seen_contexts << context.dup
        keys.to_h { [_1, {active: true}] }
      end

      batch.call(contract, {department_id: "A"}, tenant: "t1")
      batch.flush

      expect(seen_contexts).to eql([{tenant: "t1"}])
    end

    it "does not leak the batch session into the rule context" do
      batch.register_query(:department, partition: :tenant) do |keys, _partition|
        keys.to_h { [_1, {active: true}] }
      end

      result = batch.call(contract, {department_id: "A"}, tenant: "t1")
      batch.flush

      expect(result.context.each.to_h).to eql(tenant: "t1")
    end
  end

  describe "nested error paths" do
    let(:nested_contract_class) do
      Class.new(Dry::Validation::Contract) do
        def self.name
          "NestedContractImport"
        end

        params do
          required(:departments).array(:hash) do
            required(:id).filled(:string)
          end
        end

        rule(:departments).each do
          external(:department, value[:id]) do |outcome:|
            if outcome.missing? || outcome.error?
              key(path.keys + [:id]).failure("department does not exist")
            end
          end
        end
      end
    end

    it "replays failures on the nested paths with one merged call" do
      calls = []
      batch.register_query(:department) do |keys|
        calls << keys.dup
        keys.to_h { [_1, nil] }
      end

      result = batch.call(
        nested_contract_class.new,
        departments: [{id: "A"}, {id: "B"}, {id: "A"}]
      )
      batch.flush

      expect(calls).to eql([%w[A B]])
      expect(result.errors.to_h).to eql(
        departments: {
          0 => {id: ["department does not exist"]},
          1 => {id: ["department does not exist"]},
          2 => {id: ["department does not exist"]}
        }
      )
    end
  end

  describe "failure modes" do
    it "raises when a mergeable check runs without a batch session" do
      expect {
        contract.call(department_id: "A")
      }.to raise_error(
        Dry::Validation::MissingBatchSessionError,
        /mergeable external check :department requires an active Dry::Validation::Batch session/
      )
    end

    it "raises when the rule references an unregistered query" do
      orphan_batch = described_class.new

      expect {
        orphan_batch.call(contract, department_id: "A")
      }.to raise_error(
        Dry::Validation::UnknownQueryError,
        /query :department is not registered.*no queries are registered/
      )
    end

    it "raises when the query callable returns a non-Hash value" do
      batch.register_query(:department) { |_keys| %w[a b c] }

      batch.call(contract, department_id: "A")

      expect { batch.flush }.to raise_error(
        Dry::Validation::QueryResultError,
        /query must return a Hash of outcomes/
      )
    end

    it "refuses further calls and another flush after flushing" do
      batch.register_query(:department) { |keys| keys.to_h { [_1, {active: true}] } }
      batch.call(contract, department_id: "A")
      batch.flush

      expect { batch.flush }.to raise_error(Dry::Validation::BatchFlushedError)
      expect {
        batch.call(contract, department_id: "B")
      }.to raise_error(Dry::Validation::BatchFlushedError)
    end
  end

  describe Dry::Validation::Batch::Outcome do
    it "builds found, missing and error outcomes with exclusive predicates" do
      outcome_class = Dry::Validation::Batch::Outcome
      found = outcome_class.found(record = {active: true})
      missing = outcome_class.missing
      error = outcome_class.error(IOError.new("offline"))

      expect(found).to be_found
      expect(found.record).to be(record)
      expect(missing).to be_missing
      expect(error).to be_error
      expect(error.error.message).to eql("offline")
      [found, missing, error].each do |outcome|
        expect(outcome).to be_frozen
        expect([found, missing, error].count { |other| other.status == outcome.status }).to eql(1)
      end
    end
  end
end
