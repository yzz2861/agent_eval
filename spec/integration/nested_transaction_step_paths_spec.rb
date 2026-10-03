# frozen_string_literal: true

RSpec.describe "Nested transaction step paths" do
  include_context "container"

  include Dry::Monads[:result]

  # The sub-transaction's :validate step (aliased to the :check_input
  # operation) always fails with its input as the failure value
  let(:sub_transaction) {
    Class.new do
      include Dry::Transaction(container: Test::Container)

      step :validate, with: :check_input
    end
  }

  let(:transaction) {
    Class.new do
      include Dry::Transaction(container: Test::Container)

      step :process, with: :sub_transaction
    end.new
  }

  before do
    container.register :check_input, -> input { Dry::Monads::Failure(input) }
    container.register :sub_transaction, sub_transaction.new
  end

  it "returns the raw failure value when called without a block" do
    expect(transaction.call("invalid").failure).to eq "invalid"
  end

  it "keeps returning the raw failure value from the sub-transaction itself" do
    expect(sub_transaction.new.call("invalid").failure).to eq "invalid"
  end

  it "supports matching on the full step path" do
    results = []

    transaction.call("invalid") do |m|
      m.success {}

      m.failure [:process, :validate] do |value|
        results << "path failure: #{value}"
      end

      m.failure do |value|
        results << "catch-all: #{value}"
      end
    end

    expect(results).to eq ["path failure: invalid"]
  end

  it "supports matching on the outer step name" do
    results = []

    transaction.call("invalid") do |m|
      m.success {}

      m.failure :process do |value|
        results << "process failure: #{value}"
      end
    end

    expect(results).to eq ["process failure: invalid"]
  end

  it "supports matching on the innermost step name" do
    results = []

    transaction.call("invalid") do |m|
      m.success {}

      m.failure :validate do |value|
        results << "validate failure: #{value}"
      end
    end

    expect(results).to eq ["validate failure: invalid"]
  end

  it "does not match a different step path" do
    results = []

    transaction.call("invalid") do |m|
      m.success {}

      m.failure [:some_other_step, :validate] do |value|
        results << "other path: #{value}"
      end

      m.failure do |value|
        results << "catch-all: #{value}"
      end
    end

    expect(results).to eq ["catch-all: invalid"]
  end

  it "passes custom failure objects through untouched" do
    error = Class.new(StandardError).new("invalid")

    expect(transaction.call(error).failure).to be error

    matched = nil
    transaction.call(error) do |m|
      m.success {}
      m.failure([:process, :validate]) { |value| matched = value }
    end

    expect(matched).to be error
  end

  it "publishes step_failed for the enclosing step" do
    subscriber = Class.new do
      attr_reader :failed

      def initialize
        @failed = []
      end

      def on_step_failed(event)
        failed << {step_name: event[:step_name], value: event[:value]}
      end
    end.new

    transaction.subscribe(subscriber)
    transaction.call("invalid")

    expect(subscriber.failed).to eq [{step_name: :process, value: "invalid"}]
  end

  context "with the same sub-transaction reused by different outer steps" do
    let(:other_transaction) {
      Class.new do
        include Dry::Transaction(container: Test::Container)

        step :import, with: :sub_transaction
      end.new
    }

    it "distinguishes failures ending at the same step by their full path" do
      paths = []

      transaction.call("invalid") do |m|
        m.success {}
        m.failure([:process, :validate]) { paths << :process_path }
        m.failure([:import, :validate]) { paths << :import_path }
      end

      other_transaction.call("invalid") do |m|
        m.success {}
        m.failure([:process, :validate]) { paths << :process_path }
        m.failure([:import, :validate]) { paths << :import_path }
      end

      expect(paths).to eq [:process_path, :import_path]
    end
  end

  context "with three levels of nesting" do
    let(:transaction) {
      Class.new do
        include Dry::Transaction(container: Test::Container)

        step :run, with: :parent_transaction
      end.new
    }

    let(:parent_transaction) {
      Class.new do
        include Dry::Transaction(container: Test::Container)

        step :process, with: :sub_transaction
      end
    }

    before do
      container.register(:parent_transaction, parent_transaction.new)
    end

    it "carries the full path through every level" do
      results = []

      transaction.call("invalid") do |m|
        m.success {}

        m.failure [:run, :process, :validate] do |value|
          results << "path failure: #{value}"
        end
      end

      expect(results).to eq ["path failure: invalid"]
    end
  end

  context "with the same step name at multiple levels" do
    let(:transaction) {
      Class.new do
        include Dry::Transaction(container: Test::Container)

        step :validate, with: :sub_transaction
      end.new
    }

    it "tracks each nesting level in the path" do
      results = []

      transaction.call("invalid") do |m|
        m.success {}

        m.failure [:validate, :validate] do |value|
          results << "path failure: #{value}"
        end
      end

      expect(results).to eq ["path failure: invalid"]
    end
  end
end
