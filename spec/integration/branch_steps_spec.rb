# frozen_string_literal: true

RSpec.describe "branch steps" do
  include Dry::Monads[:result]

  let(:initialized_operations) { [] }
  let(:called_operations) { [] }

  let(:lazy_operation_class) do
    Class.new do
      include Dry::Monads[:result]

      def initialize(name, initialized_operations, called_operations)
        initialized_operations << name
        @name = name
        @called_operations = called_operations
      end

      def call(input)
        @called_operations << @name
        Success(input.merge(operation: @name))
      end
    end
  end

  let(:failing_operation) do
    -> input {
      called_operations << :failing
      Failure("failed in #{input[:kind]}")
    }
  end

  let(:container) do
    initialized = initialized_operations
    called = called_operations
    operation_class = lazy_operation_class
    failing = failing_operation

    Class.new do
      extend Dry::Core::Container::Mixin

      register(:card) { operation_class.new(:card, initialized, called) }
      register(:cash) { operation_class.new(:cash, initialized, called) }
      register(:fallback_operation) { operation_class.new(:fallback, initialized, called) }
      register(:failing, &failing)
      register(:after) { |input| Dry::Monads.Success(input.merge(after: true)) }
    end
  end

  let(:transaction_class) do
    operations_container = container

    Class.new do
      include Dry::Transaction(container: operations_container)

      branch :payment do
        on :card, -> input { input[:kind] == :card } do
          step :card, with: :card
        end

        on :cash, -> input { input[:kind] == :cash } do
          step :cash, with: :cash
        end

        fallback :default do
          step :fallback_operation, with: :fallback_operation
        end
      end

      step :after, with: :after
    end
  end

  it "selects the first matching ordered branch" do
    result = transaction_class.new.call(kind: :card)

    expect(result).to eq Success(kind: :card, operation: :card, after: true)
    expect(initialized_operations).to eq [:card]
    expect(called_operations).to eq [:card]
  end

  it "uses the fallback branch after all conditions fail" do
    result = transaction_class.new.call(kind: :coupon)

    expect(result).to eq Success(kind: :coupon, operation: :fallback, after: true)
    expect(initialized_operations).to eq [:fallback]
  end

  it "does not resolve operations from branches after the selected branch" do
    transaction_class.new.call(kind: :cash)

    expect(initialized_operations).to eq [:cash]
  end

  it "checks each ordered condition once with the current input" do
    condition_inputs = []
    operations_container = container

    transaction = Class.new do
      include Dry::Transaction(container: operations_container)

      branch :payment do
        on :cash, -> input { condition_inputs << [:cash, input]; input[:kind] == :cash } do
          step :cash, with: :cash
        end

        on :card, -> input { condition_inputs << [:card, input]; input[:kind] == :card } do
          step :card, with: :card
        end
      end
    end.new

    transaction.call(kind: :cash)

    expect(condition_inputs).to eq [[:cash, kind: :cash]]
  end

  it "does not continue steps after a branch failure" do
    operations_container = container
    failing_transaction = Class.new do
      include Dry::Transaction(container: operations_container)

      branch :payment do
        on :card, -> input { input[:kind] == :card } do
          step :failing, with: :failing
        end
      end

        step :after, with: :after
    end

    result = failing_transaction.new.call(kind: :card)

    expect(result).to eq Failure("failed in card")
    expect(called_operations).to eq [:failing]
  end

  it "keeps both the branch and original failing step for result matching" do
    operations_container = container
    failing_transaction = Class.new do
      include Dry::Transaction(container: operations_container)

      branch :payment do
        on :card, -> input { input[:kind] == :card } do
          step :failing, with: :failing
        end
      end
    end

    original_match = nil
    branch_match = nil

    failing_transaction.new.call(kind: :card) do |matcher|
      matcher.success {}
      matcher.failure(:failing) { |value| original_match = value }
      matcher.failure { raise "unexpected catch-all" }
    end

    failing_transaction.new.call(kind: :card) do |matcher|
      matcher.success {}
      matcher.failure(:payment) { |value| branch_match = value }
    end

    expect(original_match).to eq "failed in card"
    expect(branch_match).to eq "failed in card"
  end

  it "publishes branch and selected child step events" do
    events = []
    subscriber = Class.new do
      def initialize(events)
        @events = events
      end

      def on_step(event)
        @events << [:start, event[:step_name], event[:branch_names]]
      end

      def on_step_succeeded(event)
        @events << [:success, event[:step_name], event[:branch_name], event[:branch_names]]
      end

      def on_step_failed(event)
        @events << [:failure, event[:step_name], event[:branch_name], event[:original_step_name]]
      end
    end.new(events)

    operations_container = container
    failing_transaction = Class.new do
      include Dry::Transaction(container: operations_container)

      branch :payment do
        on :card, -> input { input[:kind] == :card } do
          step :failing, with: :failing
        end
      end
    end.new

    failing_transaction.subscribe(subscriber)
    failing_transaction.call(kind: :card)

    expect(events).to eq [
      [:start, :payment, []],
      [:start, :failing, [:card]],
      [:failure, :failing, nil, nil],
      [:failure, :payment, :card, :failing]
    ]
  end

  it "passes nested step arguments only to the selected branch" do
    operations_container = Class.new do
      extend Dry::Core::Container::Mixin

      register(:card) do |input, suffix|
        Dry::Monads.Success(input.merge(tag: suffix))
      end
    end

    transaction = Class.new do
      include Dry::Transaction(container: operations_container)

      branch :payment do
        on :card, -> input { input[:kind] == :card } do
          step :card, with: :card
        end
      end
    end.new

    result = transaction
      .with_step_args(payment: {card: [:paid]})
      .call(kind: :card)

    expect(result).to eq Success(kind: :card, tag: :paid)
  end

  it "passes arguments and listeners through nested branches" do
    events = []
    subscriber = Class.new do
      def initialize(events)
        @events = events
      end

      def on_step_failed(event)
        @events << [event[:step_name], event[:branch_names]]
      end
    end.new(events)

    operations_container = Class.new do
      extend Dry::Core::Container::Mixin

      register(:annotate) do |input, suffix|
        Dry::Monads.Success(input.merge(tag: suffix))
      end

      register(:fail, ->(_input) { Dry::Monads.Failure(:nested_failure) })
    end

    transaction = Class.new do
      include Dry::Transaction(container: operations_container)

      branch :outer do
        fallback :first do
          branch :inner do
            fallback :second do
              step :annotate, with: :annotate
              step :fail, with: :fail
            end
          end
        end
      end
    end.new

    transaction
      .with_step_args(outer: {inner: {annotate: [:nested]}})
      .tap { |instance| instance.subscribe(outer: {inner: {fail: subscriber}}) }
      .call(kind: :other)

    expect(events).to eq [[:fail, [:first, :second]]]
  end

  it "works when wrapped by an around step" do
    order = []
    wrapper_operations = Module.new do
      include Dry::Monads[:result]

      define_method(:wrapper) do |input, &continue|
        order << :wrapper_start
        result = continue.call(Success(input))
        order << :wrapper_end
        result
      end

      define_method(:failing) do |_input|
        order << :failing
        Failure(:failed)
      end

      define_method(:after) do |input|
        order << :after
        Success(input)
      end
    end

    transaction = Class.new do
      include Dry::Transaction
      include wrapper_operations

      around :wrapper
      branch :payment do
        fallback :default do
          step :failing
        end
      end
      step :after
    end.new

    result = transaction.call(kind: :other)

    expect(result).to eq Failure(:failed)
    expect(order).to eq [:wrapper_start, :failing, :wrapper_end]
  end
end
