# frozen_string_literal: true

RSpec.describe "branch steps" do
  include Dry::Monads[:result]

  let(:events) { [] }

  let(:subscriber) do
    Class.new do
      attr_reader :events

      def initialize(events)
        @events = events
      end

      def on_step(event)
        @events << [:step, event[:step_name], event.to_h[:branch_name]]
      end

      def on_step_succeeded(event)
        @events << [:succeeded, event[:step_name], event.to_h[:branch_name]]
      end

      def on_step_failed(event)
        @events << [:failed, event[:step_name], event.to_h[:branch_name]]
      end
    end.new(events)
  end

  def transaction_class(container = nil)
    Class.new do
      include Dry::Transaction(container: container)

      step :prepare
      branch :pay do
        on(:card, if: :card?) do
          step :card_pay
          step :audit_card
        end

        on(:voucher, if: :voucher?) do
          step :voucher_pay
        end

        fallback do
          step :cash_pay
        end
      end
      step :finish

      def prepare(input)
        Success(input)
      end

      def card?(input)
        input[:type] == :card
      end

      def voucher?(input)
        input[:type] == :voucher
      end

      def card_pay(input, accepted = true)
        accepted ? Success(input.merge(method: :card)) : Failure(:card_declined)
      end

      def audit_card(input)
        Success(input)
      end

      def voucher_pay(input)
        input[:type] == :voucher ? Failure(:voucher_declined) : Success(input)
      end

      def cash_pay(input)
        Success(input.merge(method: :cash))
      end

      def finish(input)
        Success(input.merge(finished: true))
      end
    end
  end

  it "selects ordered branches and runs later outer steps" do
    result = transaction_class.new.call(type: :card)

    expect(result).to eq Success(type: :card, method: :card, finished: true)
  end

  it "uses the fallback branch when no condition matches" do
    result = transaction_class.new.call(type: :cash)

    expect(result).to eq Success(type: :cash, method: :cash, finished: true)
  end

  it "raises when no branch matches and no fallback is defined" do
    transaction = Class.new do
      include Dry::Transaction

      branch :pay do
        on(:card, if: -> input { input == :card }) do
          step :card_pay
        end
      end

      def card_pay(input)
        Success(input)
      end
    end.new

    expect { transaction.call(:cash) }
      .to raise_error(Dry::Transaction::NoBranchMatchedError, /pay/)
  end

  it "checks each condition once and stops at the first matching branch" do
    checked = []

    transaction = Class.new do
      include Dry::Transaction

      branch :pay do
        on(:first, if: -> input { checked << :first; input == :first }) do
          step :first_pay
        end
        on(:second, if: -> input { checked << :second; input == :second }) do
          step :second_pay
        end
      end

      def first_pay(input); Success(input); end
      def second_pay(input); Success(input); end
    end.new

    transaction.call(:second)

    expect(checked).to eq [:first, :second]
  end

  it "does not resolve unselected branch operations" do
    resolved = []
    container = Class.new do
      extend Dry::Core::Container::Mixin

      register(:card?) { |input| resolved << :card?; input[:type] == :card }
      register(:card_pay) do
        resolved << :card_pay
        -> input { Dry::Monads.Success(input) }
      end
      register(:cash_pay) do
        resolved << :cash_pay
        -> input { Dry::Monads.Success(input) }
      end
    end

    transaction = Class.new do
      include Dry::Transaction(container: container)

      branch :pay do
        on(:card, if: :card?, with: :card?) do
          step :card_pay, with: :card_pay
        end
        fallback do
          step :cash_pay, with: :cash_pay
        end
      end
    end

    transaction.new.call(type: :card)

    expect(resolved).to eq [:card?, :card_pay]
  end

  it "publishes branch and selected child events only" do
    transaction = transaction_class.new
    transaction.subscribe(subscriber)
    transaction.call(type: :card)

    expect(events).to eq [
      [:step, :prepare, nil],
      [:succeeded, :prepare, nil],
      [:step, :pay, nil],
      [:step, :card_pay, :card],
      [:succeeded, :card_pay, :card],
      [:step, :audit_card, :card],
      [:succeeded, :audit_card, :card],
      [:succeeded, :pay, :card],
      [:step, :finish, nil],
      [:succeeded, :finish, nil]
    ]
  end

  it "stops after a failed selected branch and retains matcher names" do
    branch_match = nil
    child_match = nil
    transaction_class.new.call(type: :voucher) do |matcher|
      matcher.success { raise "unexpected success" }
      matcher.failure(:pay) { |value| branch_match = value }
    end

    transaction_class.new.call(type: :voucher) do |matcher|
      matcher.success { raise "unexpected success" }
      matcher.failure(:voucher_pay) { |value| child_match = value }
    end

    expect(branch_match).to eq :voucher_declined
    expect(child_match).to eq :voucher_declined
  end

  it "applies with_step_args to a selected child step" do
    result = transaction_class
      .new
      .with_step_args(pay: {card: {card_pay: [false]}})
      .call(type: :card)

    expect(result).to eq Failure(:card_declined)
  end

  it "retains targeted subscriptions when applying with_step_args" do
    listener = Class.new do
      attr_reader :failed

      def initialize
        @failed = []
      end

      def on_step_failed(event)
        @failed << [event[:step_name], event.to_h[:branch_name]]
      end
    end.new

    transaction = transaction_class.new
    transaction.subscribe(card_pay: listener)

    transaction
      .with_step_args(pay: {card: {card_pay: [false]}})
      .call(type: :card)

    expect(listener.failed).to eq [[:card_pay, :card]]
  end

  it "works with an around step after the branch" do
    transaction = Class.new do
      include Dry::Transaction

      branch :pay do
        on(:card, if: -> input { input == :card }) do
          step :card_pay
        end
      end
      around :wrap

      def card_pay(input)
        Success(method: input)
      end

      def wrap(input, &continue)
        continue.(Success(input)).fmap { |value| value.merge(wrapped: true) }
      end
    end.new

    expect(transaction.call(:card)).to eq Success(method: :card, wrapped: true)
  end

  it "works with an around step inside the selected branch" do
    transaction = Class.new do
      include Dry::Transaction

      branch :pay do
        on(:card, if: -> input { input == :card }) do
          around :wrap_payment
          step :card_pay
        end
      end

      def wrap_payment(input, &continue)
        continue.(Success(input)).fmap { |value| value.merge(wrapped: true) }
      end

      def card_pay(input)
        Success(method: input)
      end
    end.new

    expect(transaction.call(:card)).to eq Success(method: :card, wrapped: true)
  end

  it "supports custom step adapters inside branches" do
    custom_adapters = Class.new(Dry::Transaction::StepAdapters) do
      register :enqueue, -> operation, _options, args {
        Dry::Monads.Success(operation.(*args))
      }
    end

    transaction = Class.new do
      include Dry::Transaction(step_adapters: custom_adapters)

      branch :pay do
        on(:card, if: -> input { input == :card }) do
          enqueue :card_pay
        end
      end

      def card_pay(input)
        {method: input}
      end
    end.new

    expect(transaction.call(:card)).to eq Success(method: :card)
  end
end
