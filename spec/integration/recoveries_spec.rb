# frozen_string_literal: true

RSpec.describe "Recovering from step failures" do
  include Dry::Monads[:result]

  let(:calls) { [] }

  let(:prepare) {
    -> input {
      calls << :prepare
      Success(input)
    }
  }

  let(:reserve) {
    -> input {
      calls << :reserve
      Failure(:out_of_stock)
    }
  }

  let(:send_order) {
    -> input {
      calls << :send_order
      Success(input)
    }
  }

  let(:switch_to_preorder) {
    -> failure, input {
      calls << [:switch_to_preorder, failure, input]
      Success(input.merge(preorder: true, failure: failure))
    }
  }

  let(:transaction_class) {
    Class.new do
      include Dry::Transaction

      step :prepare
      step :reserve
      step :send_order

      recover :reserve, on: :out_of_stock
    end
  }

  let(:transaction) {
    transaction_class.new(
      prepare: prepare,
      reserve: reserve,
      send_order: send_order,
      reserve_recovery: switch_to_preorder
    )
  }

  describe "successful recovery" do
    it "passes the failure and failed step input to the recovery and continues from the next step" do
      input = {order_id: 1}

      result = transaction.call(input)

      expect(result).to eql(Success(order_id: 1, preorder: true, failure: :out_of_stock))
      expect(calls).to eq [
        :prepare,
        :reserve,
        [:switch_to_preorder, :out_of_stock, input],
        :send_order
      ]
    end

    it "does not run steps before the recovered step again" do
      transaction.call(order_id: 1)

      expect(calls.count(:prepare)).to eq 1
      expect(calls.count(:reserve)).to eq 1
    end

    it "supports recovery operations declared with keyword arguments" do
      keyword_transaction = transaction_class.new(
        prepare: prepare,
        reserve: reserve,
        send_order: send_order,
        reserve_recovery: -> failure:, input: {
          Success(input.merge(preorder: true, failure: failure))
        }
      )

      expect(keyword_transaction.call(order_id: 1)).to eql(Success(
        order_id: 1,
        preorder: true,
        failure: :out_of_stock
      ))
    end

    it "publishes one failure for the failed step and one success for each following step" do
      subscriber = Class.new do
        attr_reader :started, :succeeded, :failed

        def initialize
          @started = []
          @succeeded = []
          @failed = []
        end

        def on_step(event)
          @started << event[:step_name]
        end

        def on_step_succeeded(event)
          @succeeded << event[:step_name]
        end

        def on_step_failed(event)
          @failed << event[:step_name]
        end
      end.new

      transaction.subscribe(subscriber)
      transaction.call(order_id: 1)

      expect(subscriber.started).to eq [:prepare, :reserve, :send_order]
      expect(subscriber.succeeded).to eq [:prepare, :send_order]
      expect(subscriber.failed).to eq [:reserve]
    end
  end

  describe "unmatched failures" do
    let(:reserve) {
      -> input {
        calls << :reserve
        Failure(:warehouse_closed)
      }
    }

    it "returns the original failure and does not call the recovery or later steps" do
      result = transaction.call(order_id: 1)

      expect(result).to eql(Failure(:warehouse_closed))
      expect(calls).to eq [:prepare, :reserve]
    end
  end

  describe "failed recovery" do
    let(:switch_to_preorder) {
      -> failure, input {
        calls << [:switch_to_preorder, failure, input]
        Failure(:preorder_unavailable)
      }
    }

    it "keeps both the original and recovery failure" do
      result = transaction.call(order_id: 1)

      aggregate_failures do
        expect(result).to be_failure
        expect(result.failure).to be_a Dry::Transaction::RecoveryFailure
        expect(result.failure.step.name).to eq :reserve
        expect(result.failure.recovery_operation.name).to eq :reserve_recovery
        expect(result.failure.value).to eq :out_of_stock
        expect(result.failure.original_failure).to eq :out_of_stock
        expect(result.failure.recovery_value).to eq :preorder_unavailable
        expect(result.failure.recovery_failure).to eq :preorder_unavailable
        expect(result.failure.to_h).to eq(
          original_failure: :out_of_stock,
          recovery_failure: :preorder_unavailable
        )
      end
      expect(calls).to eq [
        :prepare,
        :reserve,
        [:switch_to_preorder, :out_of_stock, {order_id: 1}]
      ]
    end

    it "matches the original step when using the result matcher" do
      matched_failure = nil

      transaction.call(order_id: 1) do |m|
        m.success {}
        m.failure(:reserve) { |failure| matched_failure = failure }
      end

      expect(matched_failure).to eq :out_of_stock
    end
  end

  describe "exceptions in recovery" do
    let(:recovery_error) { Class.new(StandardError) }

    let(:switch_to_preorder) {
      -> failure, input {
        calls << [:switch_to_preorder, failure, input]
        raise recovery_error, "preorder failed"
      }
    }

    it "raises the exception" do
      expect { transaction.call(order_id: 1) }.to raise_error(recovery_error, "preorder failed")
      expect(calls).to eq [:prepare, :reserve, [:switch_to_preorder, :out_of_stock, {order_id: 1}]]
    end
  end

  describe "recovery subtransactions" do
    let(:preorder_transaction) do
      Class.new do
        include Dry::Transaction

        step :mark_preorder
        step :confirm_preorder
      end.new(
        mark_preorder: -> payload {
          Success(payload[:input].merge(
            preorder: true,
            original_failure: payload[:failure]
          ))
        },
        confirm_preorder: -> input { Success(input.merge(confirmed: true)) }
      )
    end

    let(:transaction) {
      transaction_class.new(
        prepare: prepare,
        reserve: reserve,
        send_order: send_order,
        reserve_recovery: preorder_transaction
      )
    }

    it "passes the failure and input to the subtransaction and resumes the parent transaction" do
      result = transaction.call(order_id: 1)

      expect(result).to eql(Success(
        order_id: 1,
        preorder: true,
        original_failure: :out_of_stock,
        confirmed: true
      ))
    end
  end

  describe "multiple recoveries" do
    let(:warehouse_recovery) {
      -> failure, input {
        calls << [:warehouse_recovery, failure, input]
        Success(input.merge(reopened: true))
      }
    }

    let(:reserve) {
      -> input {
        calls << :reserve
        Failure(:warehouse_closed)
      }
    }

    let(:transaction_class) do
      Class.new do
        include Dry::Transaction

        step :prepare
        step :reserve
        step :send_order

        recover :switch_to_preorder, from: :reserve, with: :switch_to_preorder,
          on: :out_of_stock
        recover :reopen_warehouse, from: :reserve, with: :reopen_warehouse,
          on: :warehouse_closed
      end
    end

    let(:transaction) {
      transaction_class.new(
        prepare: prepare,
        reserve: reserve,
        send_order: send_order,
        switch_to_preorder: switch_to_preorder,
        reopen_warehouse: warehouse_recovery
      )
    }

    it "matches the declared failure for the specified step" do
      result = transaction.call(order_id: 1)

      expect(result).to eql(Success(order_id: 1, reopened: true))
      expect(calls).to eq [
        :prepare,
        :reserve,
        [:warehouse_recovery, :warehouse_closed, {order_id: 1}],
        :send_order
      ]
    end
  end

  describe "container operations" do
    it "resolves recovery operations with the declared operation key" do
      container = Class.new do
        extend Dry::Core::Container::Mixin

        register(:reserve, -> _input { Dry::Monads.Failure(:out_of_stock) })
        register(:switch_to_preorder, -> failure, input {
          Dry::Monads.Success(input.merge(preorder: true, failure: failure))
        })
      end

      transaction_class = Class.new do
        include Dry::Transaction(container: container)

        step :reserve, with: :reserve
        step :send_order, with: :send_order

        recover :reserve, with: :switch_to_preorder, on: :out_of_stock
      end

      transaction = transaction_class.new(
        send_order: -> input { Success(input) }
      )

      expect(transaction.call(order_id: 1)).to eql(Success(
        order_id: 1,
        preorder: true,
        failure: :out_of_stock
      ))
    end
  end

  describe "failure matching" do
    let(:recoverable_error) { Class.new(StandardError) }
    let(:other_recoverable_error) { Class.new(StandardError) }
    let(:unrecoverable_error) { Class.new(StandardError) }

    it "matches exception classes, arrays, and predicates against the failure value" do
      matched_by_class = build_matcher_transaction(recoverable_error, recoverable_error)
      matched_by_array = build_matcher_transaction(
        other_recoverable_error,
        [recoverable_error, other_recoverable_error]
      )
      matched_by_predicate = build_matcher_transaction(
        recoverable_error.new("predicate"),
        -> failure { failure.message == "predicate" }
      )
      unmatched = build_matcher_transaction(unrecoverable_error.new, [recoverable_error, other_recoverable_error])

      aggregate_failures do
        expect(matched_by_class.call(order: 1)).to be_success
        expect(matched_by_array.call(order: 1)).to be_success
        expect(matched_by_predicate.call(order: 1)).to be_success
        expect(unmatched.call(order: 1).failure).to be_a unrecoverable_error
      end
    end

    def build_matcher_transaction(failure, matcher)
      failure_matcher = matcher

      matcher_transaction_class = Class.new do
        include Dry::Transaction

        step :reserve
        step :finish

        recover :reserve, on: failure_matcher
      end

      matcher_transaction_class.new(
        reserve: -> _input { Failure(failure.is_a?(Class) ? failure.exception : failure) },
        reserve_recovery: -> failed_value, input { Success(input.merge(failure: failed_value)) },
        finish: -> input { Success(input) }
      )
    end
  end
end
