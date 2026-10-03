# frozen_string_literal: true

require 'test_helper'

class TransitionCollectionWithStateInvariantsTest < StateMachinesTest
  def setup
    @superclass = Class.new do
      attr_accessor :tracking_number, :confirmation_code, :business_value

      def save
        true
      end
    end

    @klass = Class.new(@superclass) do
      attr_reader :saved, :state_on_save, :status_on_save

      def initialize
        super
        @write_tracking = false
        @write_confirmation = false
        @confirmation_invariant_error = false
      end

      def write_required_attributes
        @write_tracking = true
        @write_confirmation = true
      end

      def confirmation_invariant_error!
        @confirmation_invariant_error = true
      end

      def confirmation_invariant_error?
        @confirmation_invariant_error
      end

      def save
        @saved = true
        @state_on_save = state
        @status_on_save = status
        self.business_value = :kept
        self.tracking_number = 'T-1' if @write_tracking
        self.confirmation_code = 'C-1' if @write_confirmation

        self.class.state_machines.transitions(self, :save).perform { super }
      end
    end

    @state_machine = StateMachines::Machine.new(@klass, :state, initial: :pending, action: :save)
    after_transitions = []
    failure_callbacks = []
    checks = []
    @state_transition = nil
    state_invariant = lambda do |object, transition|
      checks << :state
      @state_transition = transition
      !object.tracking_number.nil?
    end
    @state_machine.state :shipped do
      invariant state_invariant
    end
    @state_machine.event :ship do
      transition pending: :shipped
    end
    @state_machine.after_transition { |_object, transition| after_transitions << transition }
    @state_machine.after_failure { |_object, transition| failure_callbacks << transition }

    @status_machine = StateMachines::Machine.new(@klass, :status, initial: :ready, action: :save)
    @status_transition = nil
    status_invariant = lambda do |object, transition|
      checks << :status
      @status_transition = transition
      raise ArgumentError, 'confirmation invariant failed' if object.confirmation_invariant_error?

      !object.confirmation_code.nil?
    end
    @status_machine.state :confirmed do
      invariant status_invariant
    end
    @status_machine.event :confirm do
      transition ready: :confirmed
    end
    @status_machine.after_transition { |_object, transition| after_transitions << transition }
    @status_machine.after_failure { |_object, transition| failure_callbacks << transition }

    @object = @klass.new
    @checks = checks
    @after_transitions = after_transitions
    @failure_callbacks = failure_callbacks
  end

  def test_should_return_false_when_a_target_state_invariant_fails
    refute @object.fire_events(:ship, :confirm)
  end

  def test_should_check_every_target_state_before_returning_false
    @object.fire_events(:ship, :confirm)

    assert_equal %i[state status], @checks
  end

  def test_should_roll_back_only_state_machine_attributes_when_invariant_fails
    @object.fire_events(:ship, :confirm)

    assert_equal 'pending', @object.state
    assert_equal 'ready', @object.status
    assert_equal :kept, @object.business_value
  end

  def test_should_run_failure_callbacks_instead_of_success_callbacks_when_invariant_fails
    @object.fire_events(:ship, :confirm)

    assert_empty @after_transitions
    assert_equal [@status_transition, @state_transition], @failure_callbacks
  end

  def test_should_pass_transition_to_state_invariant
    @object.fire_events(:ship, :confirm)

    assert_equal :ship, @state_transition.event
    assert_equal :confirm, @status_transition.event
  end

  def test_should_distinguish_invariant_exceptions_from_false_results
    @object.confirmation_invariant_error!

    error = assert_raises(ArgumentError) { @object.fire_events(:ship, :confirm) }
    assert_equal 'confirmation invariant failed', error.message
  end

  def test_should_check_every_target_state_before_raising_an_invariant_exception
    @object.confirmation_invariant_error!

    assert_raises(ArgumentError) { @object.fire_events(:ship, :confirm) }
    assert_equal %i[state status], @checks
  end

  def test_should_roll_back_state_attributes_when_invariant_raises
    @object.confirmation_invariant_error!

    assert_raises(ArgumentError) { @object.fire_events(:ship, :confirm) }
    assert_equal 'pending', @object.state
    assert_equal 'ready', @object.status
    assert_equal :kept, @object.business_value
  end

  def test_should_not_run_success_or_failure_callbacks_when_invariant_raises
    @object.confirmation_invariant_error!

    assert_raises(ArgumentError) { @object.fire_events(:ship, :confirm) }
    assert_empty @after_transitions
    assert_empty @failure_callbacks
  end

  def test_should_succeed_when_action_populates_required_attributes
    @object.write_required_attributes

    assert @object.fire_events(:ship, :confirm)
    assert_equal 'shipped', @object.state
    assert_equal 'confirmed', @object.status
  end

  def test_should_run_success_callbacks_only_after_invariants_pass
    @object.write_required_attributes

    @object.fire_events(:ship, :confirm)

    assert_equal [@status_transition, @state_transition], @after_transitions
    assert_empty @failure_callbacks
  end

  def test_should_check_invariants_through_shared_action_hook
    @object.state_event = :ship
    @object.status_event = :confirm

    refute @object.save
    assert_equal 'pending', @object.state
    assert_equal 'ready', @object.status
    assert_empty @after_transitions
  end

  def test_should_succeed_through_shared_action_hook_after_action_writes_attributes
    @object.write_required_attributes
    @object.state_event = :ship
    @object.status_event = :confirm

    assert @object.save
    assert_equal 'shipped', @object.state
    assert_equal 'confirmed', @object.status
    assert_equal [@status_transition, @state_transition], @after_transitions
  end
end
