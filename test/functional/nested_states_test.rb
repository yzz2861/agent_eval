# frozen_string_literal: true

require 'test_helper'

class NestedStatesTest < StateMachinesTest
  class WorkOrder
    attr_accessor :log

    def initialize
      @log = []
      super
    end

    state_machine initial: :processing do
      state :idle
      state :paused

      state :processing, history: true do |processing|
        processing.enter(:enter_processing)
        processing.exit(:exit_processing)

        state :dispatching, initial: true do |state|
          state.enter(:enter_dispatching)
          state.exit(:exit_dispatching)
        end

        state :executing do |state|
          state.enter(:enter_executing)
          state.exit(:exit_executing)
        end

        event :finish do
          transition processing: :idle
        end
      end

      event :start do
        transition idle: :processing
      end

      event :assign do
        transition processing: :executing
      end

      event :pause do
        transition executing: :paused
      end

      event :resume do
        transition paused: :processing
      end
    end

    def enter_processing(transition)
      log << "enter:processing:#{transition.event}"
    end

    def exit_processing(transition)
      log << "exit:processing:#{transition.event}"
    end

    def enter_dispatching(transition)
      log << "enter:dispatching:#{transition.event}"
    end

    def exit_dispatching(transition)
      log << "exit:dispatching:#{transition.event}"
    end

    def enter_executing(transition)
      log << "enter:executing:#{transition.event}"
    end

    def exit_executing(transition)
      log << "exit:executing:#{transition.event}"
    end
  end

  def setup
    @order = WorkOrder.new
  end

  def test_initializes_composite_state_to_default_leaf
    assert_equal 'dispatching', @order.state
  end

  def test_parent_predicate_matches_descendant_leaf
    assert @order.processing?
    assert @order.dispatching?
    refute @order.executing?
  end

  def test_persists_only_leaf_state
    @order.assign
    @order.pause
    @order.resume

    assert_equal 'executing', @order.state
  end

  def test_shallow_history_restores_previous_child
    @order.assign
    @order.pause
    @order.resume

    assert @order.executing?
  end

  def test_first_entry_uses_default_child_and_callbacks_run_outer_to_inner
    @order.state = 'idle'
    @order.log.clear
    @order.start

    assert_equal %w[enter:processing:start enter:dispatching:start], @order.log
  end

  def test_nested_transition_exits_inner_to_outer_and_enters_outer_to_inner
    @order.assign
    @order.log.clear
    @order.pause
    @order.resume

    expected = %w[
      exit:executing:pause
      exit:processing:pause
      enter:processing:resume
      enter:executing:resume
    ]
    assert_equal expected, @order.log
  end

  def test_transition_between_sibling_leaves_does_not_reenter_common_parent
    @order.log.clear
    @order.assign

    expected = %w[
      exit:dispatching:assign
      enter:executing:assign
    ]
    assert_equal expected, @order.log
  end

  def test_child_event_refinement_overrides_parent_event
    klass = Class.new do
      attr_accessor :log

      def initialize
        @log = []
        super
      end

      state_machine initial: :dispatching do
        state :processing, history: true do |processing|
          state :dispatching, initial: true
          state :executing

          event :assign do
            transition executing: same
          end
        end

        event :assign do
          transition processing: :executing
        end
      end
    end

    object = klass.new
    object.assign
    object.assign

    assert_equal 'executing', object.state
  end

  def test_subclass_event_definition_does_not_change_parent_machine
    subclass = Class.new(WorkOrder)
    subclass.state_machine do
      before_transition on: :cancel do
      end

      event :cancel do
        transition processing: :idle
      end

      state :canceled
    end

    refute WorkOrder.state_machine.events[:cancel]
    assert subclass.state_machine.events[:cancel]
    refute WorkOrder.state_machine.states[:canceled]
    assert subclass.state_machine.states[:canceled]
    assert_equal 0, WorkOrder.state_machine.callbacks[:before].length
    assert_equal 1, subclass.state_machine.callbacks[:before].length
  end

  def test_failed_action_rolls_back_shallow_history
    klass = Class.new do
      attr_accessor :failing

      def initialize
        @failing = false
        super
      end

      state_machine initial: :dispatching, action: :save do
        state :processing, history: true do
          state :dispatching, initial: true
          state :executing

          event :pause do
            transition executing: :dispatching
          end
        end
      end

      def save
        !failing
      end
    end

    object = klass.new
    object.pause
    object.failing = true

    refute object.pause
    assert_equal 'dispatching', object.state
  end
end
