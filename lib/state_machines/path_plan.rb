# frozen_string_literal: true

module StateMachines
  # A PathPlan is the immutable result of planning a weighted route through a
  # state machine (see StateMachines::PathPlanner).  It describes the sequence
  # of events that should transition an object from its current state to a
  # target state, the total business cost of that sequence, and the guard
  # conditions that could not be verified statically and therefore still need
  # to hold when the events are actually fired.
  #
  # A plan is advisory only: it never performs transitions and never runs
  # actions.  Firing the planned events (e.g. via +fire_event+) still
  # re-evaluates every guard against the live object at fire time.
  class PathPlan
    # The object the plan was generated for
    attr_reader :object

    # The state machine the plan was generated from
    attr_reader :machine

    # The state the plan starts from
    attr_reader :from_name

    # The target state the plan ends on
    attr_reader :to_name

    # The ordered sequence of event names to fire.  Empty when the target is
    # unreachable or when the object is already on the target state.
    attr_reader :events

    # The summed weight of every event in the plan.  Nil when the target
    # state is unreachable.
    attr_reader :total_cost

    # The guard conditions along the planned route that were not verified
    # during planning and must still hold when the events are fired.  Each
    # entry is a hash of the form:
    #
    #   { event: :ignite, from: :parked, to: :idling, type: :if, condition: :seatbelt_on? }
    #
    # where +type+ is one of +:if+, +:unless+, or a state guard type
    # (+:if_state+, +:unless_state+, +:if_all_states+, +:unless_all_states+,
    # +:if_any_state+, +:unless_any_state+), and +condition+ is the original
    # condition (Symbol / Proc / String) or, for state guards, the frozen
    # hash of machine name => required state(s).
    attr_reader :unverified_guards

    def initialize(object:, machine:, from_name:, to_name:, events: [], total_cost: nil, unverified_guards: [])
      @object = object
      @machine = machine
      @from_name = from_name
      @to_name = to_name
      @events = events.freeze
      @total_cost = total_cost
      @unverified_guards = unverified_guards.freeze
    end

    # Whether a route from the source state to the target state was found.
    # When this is false, +events+ is empty and +total_cost+ is nil.
    def reachable?
      !total_cost.nil?
    end

    def ==(other)
      other.is_a?(PathPlan) &&
        from_name == other.from_name &&
        to_name == other.to_name &&
        events == other.events &&
        total_cost == other.total_cost &&
        unverified_guards == other.unverified_guards
    end
    alias eql? ==

    def inspect
      if reachable?
        "#<#{self.class} #{from_name.inspect} -> #{to_name.inspect} events=#{events.inspect} total_cost=#{total_cost.inspect} unverified_guards=#{unverified_guards.length}>"
      else
        "#<#{self.class} #{from_name.inspect} -> #{to_name.inspect} unreachable>"
      end
    end
  end
end
