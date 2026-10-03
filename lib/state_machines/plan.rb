# frozen_string_literal: true

module StateMachines
  # A plan represents the cheapest sequence of events that can bring an object
  # from its current state to a target state, as computed by
  # StateMachines::Planner.  Plans are pure value objects: building one never
  # fires events, runs actions, or executes callbacks on the object.
  #
  # Each step may carry guard conditions that were *not* evaluated while
  # planning.  Those guards are treated as unknown and are expected to be
  # verified when the events are actually fired (firing an event always
  # re-checks its guards against the live object).
  class Plan
    # A single step in a plan: firing +event+ moves the object from
    # +from_name+ to +to_name+ at the given business cost (+weight+).
    # +guards+ lists the guard conditions that still need to be verified at
    # runtime, keyed by :if, :unless, and :state_guards.
    Step = Data.define(:event, :from_name, :to_name, :weight, :guards)

    # The object the plan was built for
    attr_reader :object

    # The state machine this plan walks
    attr_reader :machine

    # The state the plan starts from
    attr_reader :from_name

    # The target state the plan ends on
    attr_reader :to_name

    # The ordered list of steps (StateMachines::Plan::Step) in this plan
    attr_reader :steps

    def initialize(object, machine, from_name:, to_name:, steps: []) # :nodoc:
      @object = object
      @machine = machine
      @from_name = from_name
      @to_name = to_name
      @steps = steps.freeze
    end

    # The sequence of events to fire, in order.
    #
    # For example,
    #
    #   plan.events # => [:ignite, :shift_up]
    def events
      steps.map(&:event)
    end

    # The total business cost of this plan: the sum of the weights of every
    # step.
    def total_cost
      steps.sum(&:weight)
    end

    # Whether this plan contains no steps.  This is the case when the object
    # is already in the target state.
    def empty?
      steps.empty?
    end
    alias blank? empty?

    # The guard conditions that were not evaluated while planning and still
    # need to be verified when the events are actually fired.  Returns one
    # entry per step that has unverified guards, for example:
    #
    #   plan.pending_guards
    #   # => [{event: :ignite, if: [:seatbelt_on?]}, {event: :shift_up, state_guards: {if_state: {alarm: :off}}}]
    def pending_guards
      steps.filter_map do |step|
        { event: step.event }.merge(step.guards) unless step.guards.empty?
      end
    end

    # Whether every guard along this plan was evaluated while planning.  When
    # false, firing the planned events may still fail unless the pending
    # guards hold for the object at runtime.
    def verified?
      pending_guards.empty?
    end

    def inspect
      "#<#{self.class} #{from_name.inspect} => #{to_name.inspect} events=#{events.inspect} total_cost=#{total_cost}>"
    end
  end
end
