# frozen_string_literal: true

RSpec.describe "step recovery" do
  include Dry::Monads[:result]

  InventoryUnavailable = Class.new(StandardError)
  RecoveryRejected = Class.new(StandardError)
  RecoveryCrashed = Class.new(StandardError)
  RaisingMatcher = Object.new
  def RaisingMatcher.===(_value)
    raise RecoveryCrashed, "matcher crashed"
  end
  def build_transaction(reserve:, presell:, charge: -> input { Success(input.merge(charged: true)) },
    deliver: -> input { Success(input.merge(delivered: true)) }, failure: InventoryUnavailable)
    Class.new do
      include Dry::Transaction

      step :reserve
      recover :presell, from: :reserve, failure: failure
      step :charge
      step :deliver
    end.new(reserve: reserve, presell: presell, charge: charge, deliver: deliver)
  end

  let(:reserve) { -> input { Failure(InventoryUnavailable.new("no inventory")) } }
  let(:presell) { -> failure_value, input { Success(input.merge(presale: true, reason: failure_value)) } }
  let(:charge) { -> input { Success(input.merge(charged: true)) } }
  let(:deliver) { -> input { Success(input.merge(delivered: true)) } }
  let(:transaction) { build_transaction(reserve: reserve, presell: presell, charge: charge, deliver: deliver) }

  let(:listener) do
    Class.new do
      attr_reader :events

      def initialize
        @events = []
      end

      def on_step(event)
        events << [:step, event[:step_name], event[:args]]
      end

      def on_step_succeeded(event)
        events << [:succeeded, event[:step_name], event[:args], event[:value]]
      end

      def on_step_failed(event)
        events << [:failed, event[:step_name], event[:args], event[:value]]
      end
    end.new
  end

  it "continues after a matched failure without rerunning previous steps" do
    calls = []
    reserve = -> input { calls << [:reserve, input]; Failure(InventoryUnavailable.new) }
    presell = -> failure_value, input { calls << [:presell, failure_value, input]; Success(input.merge(presale: true)) }
    charge = -> input { calls << [:charge, input]; Success(input.merge(charged: true)) }

    local_deliver = -> input { Success(input.merge(delivered: true)) }

    result = build_transaction(
      reserve: reserve,
      presell: presell,
      charge: charge,
      deliver: local_deliver
    ).call(order_id: 1)

    expect(result).to eq Success(order_id: 1, presale: true, charged: true, delivered: true)
    expect(calls.values_at(0, 2)).to eq [
      [:reserve, order_id: 1],
      [:charge, order_id: 1, presale: true]
    ]
    expect(calls[1][0]).to eq :presell
    expect(calls[1][1]).to be_a InventoryUnavailable
    expect(calls[1][2]).to eq(order_id: 1)
  end

  it "calls a recovery subtransaction with the failure value and original input" do
    recovery_transaction = Class.new do
      include Dry::Transaction

      step :prepare_presale

      def prepare_presale(input)
        failure_value, order = input
        Success(order.merge(presale: true, reason: failure_value.message))
      end
    end.new

    result = build_transaction(
      reserve: -> input { Failure(InventoryUnavailable.new("no inventory")) },
      presell: recovery_transaction
    ).call(order_id: 2)

    expect(result).to eq Success(
      order_id: 2,
      presale: true,
      reason: "no inventory",
      charged: true,
      delivered: true
    )
  end

  it "calls ordinary recovery operations with the failure value and original input separately" do
    recovery_class = Class.new do
      include Dry::Monads[:result]

      def call(failure_value, input)
        Success([failure_value, input])
      end
    end
    recovery_operation = recovery_class.new

    transaction = build_transaction(
      reserve: -> input { Failure(:inventory_unavailable) },
      presell: recovery_operation,
      charge: -> input { Success(input) },
      deliver: -> input { Success(input) },
      failure: Symbol
    )

    expect(transaction.call(order_id: 19)).to eq Success([:inventory_unavailable, order_id: 19])
  end

  it "publishes events from inside a recovery subtransaction" do
    recovery_transaction = Class.new do
      include Dry::Transaction

      step :prepare_presale

      def prepare_presale(input)
        failure_value, order = input
        Success(order.merge(presale: true, reason: failure_value.message))
      end
    end.new

    transaction = build_transaction(
      reserve: -> input { Failure(InventoryUnavailable.new("no inventory")) },
      presell: recovery_transaction,
      charge: -> input { Success(input.merge(charged: true)) },
      deliver: -> input { Success(input.merge(delivered: true)) }
    )
    transaction.subscribe(listener)

    transaction.call(order_id: 10)

    expect(listener.events.map { |event| event.first(2) }).to eq [
      [:step, :reserve],
      [:failed, :reserve],
      [:step, :presell],
      [:step, :prepare_presale],
      [:succeeded, :prepare_presale],
      [:succeeded, :presell],
      [:step, :charge],
      [:succeeded, :charge],
      [:step, :deliver],
      [:succeeded, :deliver]
    ]
  end

  it "does not duplicate subtransaction events when a recovery is reused" do
    recovery_transaction = Class.new do
      include Dry::Transaction

      step :prepare_presale

      def prepare_presale(input)
        failure_value, order = input
        Success(order.merge(presale: true, reason: failure_value.message))
      end
    end.new

    transaction = build_transaction(
      reserve: -> input { Failure(InventoryUnavailable.new) },
      presell: recovery_transaction
    )
    transaction.subscribe(listener)

    transaction.call(order_id: 11)
    transaction.call(order_id: 12)

    expect(listener.events.count { |event| event[0..1] == [:step, :prepare_presale] }).to eq 2
    expect(listener.events.count { |event| event[0..1] == [:succeeded, :prepare_presale] }).to eq 2
  end

  it "returns unmatched failures unchanged" do
    unmatched = -> input { Failure("unmatched") }

    result = build_transaction(reserve: unmatched, presell: presell).call(order_id: 3)

    expect(result).to eq Failure("unmatched")
  end

  it "matches an explicitly nil failure value" do
    transaction = Class.new do
      include Dry::Transaction

      step :reserve
      recover :presell, from: :reserve, failure: nil

      def reserve(input)
        Failure(nil)
      end

      def presell(failure_value, input)
        Success(input.merge(failure: failure_value, recovered: true))
      end
    end.new

    expect(transaction.call(order_id: 17)).to eq Success(order_id: 17, failure: nil, recovered: true)
  end

  it "preserves the original and recovery failure when recovery fails" do
    failing_presell = -> _failure_value, _input { Failure(RecoveryRejected.new("presale rejected")) }

    result = build_transaction(reserve: reserve, presell: failing_presell).call(order_id: 4)

    expect(result).to be_failure
    expect(result.failure).to be_a Dry::Transaction::RecoveryFailure
    expect(result.failure.cause).to be_a InventoryUnavailable
    expect(result.failure.value).to be_a RecoveryRejected
    expect(result.failure.recovery_failure).to be_a RecoveryRejected
    expect(result.failure.original_failure).to be_a InventoryUnavailable
    expect(result.failure.to_a).to eq [result.failure.cause, result.failure.value]
    expect(result.failure.to_a).to contain_exactly(
      an_instance_of(InventoryUnavailable),
      an_instance_of(RecoveryRejected)
    )
  end

  it "raises ordinary Ruby exceptions from recovery operations" do
    raising_presell = -> _failure_value, _input { raise RecoveryCrashed, "presale crashed" }

    expect {
      build_transaction(reserve: reserve, presell: raising_presell).call(order_id: 5)
    }.to raise_error(RecoveryCrashed, "presale crashed")
  end

  it "raises ordinary Ruby exceptions from failure matchers" do
    transaction = Class.new do
      include Dry::Transaction

      step :reserve
      recover :presell, from: :reserve, failure: RaisingMatcher
    end.new(
      reserve: -> input { Failure(:error) },
      presell: -> _failure_value, input { Success(input) }
    )

    expect { transaction.call(order_id: 18) }.to raise_error(RecoveryCrashed, "matcher crashed")
  end

  it "publishes failure, recovery and subsequent step events in order" do
    transaction.subscribe(listener)

    transaction.call(order_id: 6)

    expect(listener.events.map { |event| event.first(2) }).to eq [
      [:step, :reserve],
      [:failed, :reserve],
      [:step, :presell],
      [:succeeded, :presell],
      [:step, :charge],
      [:succeeded, :charge],
      [:step, :deliver],
      [:succeeded, :deliver]
    ]
    expect(listener.events.none? { |event| event == [:succeeded, :reserve] }).to be true
    expect(listener.events.count { |event| event[0..1] == [:succeeded, :charge] }).to eq 1
  end

  it "publishes a recovery failure event and stops the transaction" do
    failing_presell = -> _failure_value, _input { Failure(RecoveryRejected.new) }
    recovery_transaction = build_transaction(reserve: reserve, presell: failing_presell)
    recovery_transaction.subscribe(listener)

    recovery_transaction.call(order_id: 7)

    expect(listener.events.map { |event| event.first(2) }).to eq [
      [:step, :reserve],
      [:failed, :reserve],
      [:step, :presell],
      [:failed, :presell]
    ]
  end

  it "does not publish recovery events for unmatched failures" do
    transaction = build_transaction(
      reserve: -> input { Failure("unmatched") },
      presell: presell
    )
    transaction.subscribe(listener)

    transaction.call(order_id: 8)

    expect(listener.events.map { |event| event.first(2) }).to eq [
      [:step, :reserve],
      [:failed, :reserve]
    ]
  end

  it "uses the first matching recovery and returns its failure without trying another recovery" do
    chosen = []
    first = -> _failure_value, _input { chosen << :first; Failure(:first_rejected) }
    second = -> failure_value, input { chosen << :second; Success(input.merge(reason: failure_value)) }

    transaction = Class.new do
      include Dry::Transaction

      step :reserve
      recover :first_recovery, step: :reserve, with: :first, failure: StandardError
      recover :second_recovery, step: :reserve, with: :second, failure: StandardError
    end.new(
      reserve: -> input { Failure(InventoryUnavailable.new) },
      first_recovery: first,
      second_recovery: second
    )

    result = transaction.call(order_id: 9)

    expect(result).to be_failure
    expect(result.failure).to be_a Dry::Transaction::RecoveryFailure
    expect(result.failure.cause).to be_a InventoryUnavailable
    expect(result.failure.value).to eq :first_rejected
    expect(chosen).to eq [:first]
  end

  it "supports anonymous recoveries in declaration order and catch as a matching alias" do
    chosen = []
    first = -> _failure_value, _input { chosen << :first; Failure(:first_rejected) }
    second = -> failure_value, input { chosen << :second; Success(input.merge(reason: failure_value)) }

    transaction = Class.new do
      include Dry::Transaction

      step :reserve
      recover :reserve, with: :first, catch: Integer
      recover :reserve, with: :second, catch: Symbol
    end.new(
      reserve: -> input { Failure(:not_reserved) },
      first: first,
      second: second
    )

    expect(transaction.call(order_id: 13)).to eq Success(order_id: 13, reason: :not_reserved)
    expect(chosen).to eq [:second]
  end

  it "keeps recovery definitions for steps following a recovered step" do
    transaction = Class.new do
      include Dry::Transaction

      step :reserve
      recover :sell_anyway, from: :reserve, failure: Symbol
      step :charge
      recover :retry_charge, from: :charge, failure: Symbol
      step :deliver

      def reserve(input)
        Failure(:inventory_unavailable)
      end

      def sell_anyway(failure_value, input)
        Success(input.merge(reserved: true, first_failure: failure_value))
      end

      def charge(input)
        Failure(:payment_declined)
      end

      def retry_charge(failure_value, input)
        Success(input.merge(charged: true, second_failure: failure_value))
      end

      def deliver(input)
        Success(input.merge(delivered: true))
      end
    end.new

    expect(transaction.call(order_id: 16)).to eq Success(
      order_id: 16,
      reserved: true,
      first_failure: :inventory_unavailable,
      charged: true,
      second_failure: :payment_declined,
      delivered: true
    )
  end

  it "keeps recovery behavior when adding step arguments" do
    transaction = Class.new do
      include Dry::Transaction

      step :reserve
      recover :presell, from: :reserve, failure: Symbol
      step :finish

      def reserve(input, mode)
        mode == :presellable ? Failure(:inventory_unavailable) : Success(input)
      end

      def presell(failure_value, input)
        Success(input.merge(presale: true, reason: failure_value))
      end

      def finish(input)
        Success(input.merge(done: true))
      end
    end.new.with_step_args(reserve: [:presellable])

    expect(transaction.call(order_id: 14)).to eq Success(
      order_id: 14,
      presale: true,
      reason: :inventory_unavailable,
      done: true
    )
  end

  it "recovers failures created from ordinary exceptions by try adapters" do
    transaction = Class.new do
      include Dry::Transaction

      try :reserve, catch: InventoryUnavailable
      recover :presell, from: :reserve, failure: InventoryUnavailable
      step :finish

      def reserve(input)
        raise InventoryUnavailable, "held elsewhere"
      end

      def presell(failure_value, input)
        Success(input.merge(presale: true, error: failure_value.message))
      end

      def finish(input)
        Success(input.merge(done: true))
      end
    end.new
    transaction.subscribe(listener)

    expect(transaction.call(order_id: 15)).to eq Success(
      order_id: 15,
      presale: true,
      error: "held elsewhere",
      done: true
    )
    expect(listener.events.map { |event| event.first(2) }).to eq [
      [:step, :reserve],
      [:failed, :reserve],
      [:step, :presell],
      [:succeeded, :presell],
      [:step, :finish],
      [:succeeded, :finish]
    ]
  end

  it "does not rerun successful steps inside an around step after recovery" do
    calls = []
    transaction = Class.new do
      include Dry::Transaction

      around :wrap
      step :before_failure
      step :reserve
      recover :presell, from: :reserve, failure: InventoryUnavailable
      step :finish
    end.new(
      wrap: -> input, &block { calls << :wrap; block.call(Success(input)) },
      before_failure: -> input { calls << :before_failure; Success(input) },
      reserve: -> input { calls << :reserve; Failure(InventoryUnavailable.new) },
      presell: -> _failure_value, input { calls << :presell; Success(input.merge(presale: true)) },
      finish: -> input { calls << :finish; Success(input) }
    )

    expect(transaction.call(order_id: 17)).to eq Success(order_id: 17, presale: true)
    expect(calls).to eq [:wrap, :before_failure, :reserve, :presell, :finish]
  end

  it "validates recovery target steps" do
    expect {
      Class.new do
        include Dry::Transaction

        step :reserve
        recover :presell, step: :missing, with: -> failure_value, input { Success(input) }, failure: StandardError
      end.new(
        reserve: -> input { Success(input) },
        presell: -> failure_value, input { Success(input) }
      )
    }.to raise_error ArgumentError, "+:missing+ is not a valid step name"
  end
end
