# frozen_string_literal: true

RSpec.describe "Nested transactions" do
  include Dry::Monads[:result]

  # A sub-transaction whose only step is named +validate+ (aliased to a
  # differently-named operation), reused across multiple outer transactions
  let(:validator_class) do
    Class.new do
      include Dry::Transaction

      step :validate, with: :check_valid
    end
  end

  let(:validator) { validator_class.new(validate: validate_operation) }

  let(:validate_operation) {
    -> input { input[:valid] ? Success(input) : Failure(failure_value) }
  }

  let(:failure_value) { :invalid }

  # Two outer transactions exposing the same sub-transaction instance
  # under different step names
  let(:user_transaction) {
    Class.new do
      include Dry::Transaction

      step :check_user
    end.new(check_user: validator)
  }

  let(:order_transaction) {
    Class.new do
      include Dry::Transaction

      step :check_order
    end.new(check_order: validator)
  }

  it "passes through successful nested results" do
    expect(user_transaction.call(valid: true)).to be_success
  end

  it "returns the unwrapped failure value from a direct call" do
    expect(user_transaction.call(valid: false).failure).to eq :invalid
  end

  it "exposes the failure path as structured data" do
    step_failure = user_transaction.as_step_operation.(valid: false).failure

    expect(step_failure.path).to eq [:check_user, :validate]
    expect(step_failure.path).to all be_a Symbol
  end

  it "uses the step name (alias), not the operation name, in the path" do
    step_failure = user_transaction.as_step_operation.(valid: false).failure

    expect(step_failure.path).not_to include :check_valid
  end

  it "distinguishes different paths that fail at the same step name" do
    matched = []

    user_transaction.call(valid: false) do |m|
      m.success {}

      m.failure([:check_user, :validate]) { matched << :user_path }
      m.failure([:check_order, :validate]) { matched << :order_path }
      m.failure { matched << :other }
    end

    order_transaction.call(valid: false) do |m|
      m.success {}

      m.failure([:check_user, :validate]) { matched << :user_path }
      m.failure([:check_order, :validate]) { matched << :order_path }
      m.failure { matched << :other }
    end

    expect(matched).to eq [:user_path, :order_path]
  end

  it "matches a failure by an outer step name" do
    matched = nil

    user_transaction.call(valid: false) do |m|
      m.success {}

      m.failure(:check_user) { |value| matched = value }
      m.failure { matched = :other }
    end

    expect(matched).to eq :invalid
  end

  it "matches a failure by the innermost step name" do
    matched = nil

    user_transaction.call(valid: false) do |m|
      m.success {}

      m.failure(:validate) { |value| matched = value }
      m.failure { matched = :other }
    end

    expect(matched).to eq :invalid
  end

  it "does not match a partial path" do
    matched = nil

    user_transaction.call(valid: false) do |m|
      m.success {}

      m.failure([:validate]) { matched = :partial }
      m.failure { matched = :catch_all }
    end

    expect(matched).to eq :catch_all
  end

  context "with multiple levels of nesting" do
    let(:enrollment_transaction) {
      Class.new do
        include Dry::Transaction

        step :enroll
      end.new(enroll: user_transaction)
    }

    it "carries the path through every level of nesting" do
      matched = nil

      enrollment_transaction.call(valid: false) do |m|
        m.success {}

        m.failure([:enroll, :check_user, :validate]) { matched = :full_path }
        m.failure { matched = :other }
      end

      expect(matched).to eq :full_path
    end
  end

  context "with same-named steps across nesting levels" do
    let(:same_named_transaction) {
      Class.new do
        include Dry::Transaction

        step :validate
      end.new(validate: validator)
    }

    it "keeps same-named steps as distinct path entries" do
      matched = nil

      same_named_transaction.call(valid: false) do |m|
        m.success {}

        m.failure([:validate, :validate]) { matched = :nested }
        m.failure([:validate]) { matched = :single }
        m.failure { matched = :other }
      end

      expect(matched).to eq :nested
    end
  end

  context "with a custom failure object" do
    let(:failure_value) { Struct.new(:code, :message).new(:invalid, "not valid") }

    it "returns the very same object from a direct call" do
      expect(user_transaction.call(valid: false).failure).to be failure_value
    end

    it "yields the very same object to matchers" do
      yielded = nil

      user_transaction.call(valid: false) do |m|
        m.success {}

        m.failure([:check_user, :validate]) { |value| yielded = value }
      end

      expect(yielded).to be failure_value
    end
  end
end
