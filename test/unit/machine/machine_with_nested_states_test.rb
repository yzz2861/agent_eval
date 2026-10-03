# frozen_string_literal: true

require 'test_helper'

class MachineWithNestedStatesTest < StateMachinesTest
  def setup
    @klass = Class.new do
      attr_accessor :log

      def initialize
        @log = []
        super
      end
    end

    @klass.class_eval do
      state_machine initial: :processing do
        before_transition do |object, transition|
          object.log << [:before, transition.event]
        end

        after_transition do |object, transition|
          object.log << [:after, transition.event]
        end

        state :processing, initial_child: :dispatching, history: :shallow do |processing|
          processing.enter { |object, transition| object.log << [:enter, :processing, transition.event] }
          processing.exit { |object, transition| object.log << [:exit, :processing, transition.event] }

          processing.event :pause do
            transition dispatching: :paused
            transition executing: :paused
          end

          processing.event :choose do
            transition executing: :executing
          end

          processing.state :dispatching do |dispatching|
            dispatching.enter { |object, transition| object.log << [:enter, :dispatching, transition.event] }
            dispatching.exit { |object, transition| object.log << [:exit, :dispatching, transition.event] }

            dispatching.event :choose do
              transition dispatching: :executing
            end
          end

          processing.state :executing do |executing|
            executing.enter { |object, transition| object.log << [:enter, :executing, transition.event] }
            executing.exit { |object, transition| object.log << [:exit, :executing, transition.event] }
          end
        end

        state :paused do |paused|
          paused.enter { |object, transition| object.log << [:enter, :paused, transition.event] }
          paused.exit { |object, transition| object.log << [:exit, :paused, transition.event] }
        end

        event :resume do
          transition paused: :processing, history: true
        end
      end
    end

    @machine = @klass.state_machine
    @object = @klass.new
  end

  def test_stores_only_the_initial_leaf_state
    assert_equal 'dispatching', @object.state
    assert_equal :dispatching, @object.state_name
  end

  def test_parent_predicate_matches_descendants
    assert @object.processing?
    assert @object.dispatching?
    refute @object.executing?
  end

  def test_child_event_refinement_takes_precedence_over_parent
    assert @object.choose
    assert_equal 'executing', @object.state

    @object.state = 'paused'
    refute @object.choose
  end

  def test_cross_layer_callbacks_have_lca_order
    @object.choose

    assert_equal [
      [:before, :choose],
      [:exit, :dispatching, :choose],
      [:enter, :executing, :choose],
      [:after, :choose]
    ], @object.log
  end

  def test_transition_callbacks_match_parent_states_and_descendants
    events = []
    @machine.after_transition to: :processing do |_object, transition|
      events << transition.event
    end

    @object.choose
    @object.pause
    @object.resume

    assert_equal %i[choose resume], events
  end

  def test_pause_and_resume_uses_shallow_history
    @object.choose
    @object.log.clear

    assert @object.pause
    assert_equal 'paused', @object.state
    assert @object.resume

    assert_equal 'executing', @object.state
    assert_equal :executing, @object.state_name
    assert @object.executing?
    assert @object.processing?
    assert_equal [
      [:before, :pause],
      [:exit, :executing, :pause],
      [:exit, :processing, :pause],
      [:enter, :paused, :pause],
      [:after, :pause],
      [:before, :resume],
      [:exit, :paused, :resume],
      [:enter, :processing, :resume],
      [:enter, :executing, :resume],
      [:after, :resume]
    ], @object.log
  end

  def test_resume_without_history_uses_initial_child
    assert @object.pause
    @object.instance_variable_set(:@state_machine_shallow_history, nil)

    assert @object.resume
    assert_equal 'dispatching', @object.state
  end

  def test_subclass_refinement_does_not_mutate_parent_machine
    subclass = Class.new(@klass)
    subclass.state_machine(:state) do
      event :choose do
        transition dispatching: :dispatching
      end
    end

    parent_object = @klass.new
    assert parent_object.choose
    assert_equal 'executing', parent_object.state

    child_object = subclass.new
    assert child_object.choose
    assert_equal 'dispatching', child_object.state
  end

  def test_subclass_state_definition_does_not_mutate_parent_machine
    subclass = Class.new(@klass)
    subclass.state_machine(:state) do
      state :dispatching, value: 'custom-dispatching'
    end

    parent_object = @klass.new
    child_object = subclass.new

    assert_equal 'dispatching', parent_object.state
    assert_equal 'custom-dispatching', child_object.state
  end
end
