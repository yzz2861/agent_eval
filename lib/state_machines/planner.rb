# frozen_string_literal: true

require_relative 'options_validator'
require_relative 'plan'

module StateMachines
  # Plans the cheapest sequence of events that brings an object from its
  # current state to a target state, using per-event weights as the business
  # cost.  This is meant for operational UIs that need to show *what* would
  # need to happen to reach a goal state before anything is executed.
  #
  # Planning is strictly read-only:
  # * No event is ever fired and no action / callback is ever run.
  # * Guard conditions (:if / :unless / state guards) are *not* treated as
  #   static truths.  By default every guard is left unevaluated and reported
  #   back on the plan as a pending condition.  Callers may explicitly
  #   whitelist guards that are safe to evaluate for this planning run via
  #   the :evaluate_guards option; only those are executed against the object.
  # * Firing the planned events afterwards still re-checks every guard, so a
  #   plan is a hint, never a guarantee.
  #
  # Deterministic rules:
  # * The plan minimizes total cost (sum of event weights).
  # * Ties are broken by fewer events first, then by the lexicographically
  #   smaller sequence of event names, so equal-cost alternatives always
  #   resolve to the same plan.
  # * Zero-weight cycles cannot cause infinite searches: each state is
  #   settled at most once and a path is only ever replaced by a strictly
  #   better one.
  # * If the target state cannot be reached, +plan+ returns nil.
  # * If the object is already in the target state, +plan+ returns an empty
  #   plan with a total cost of 0.
  #
  # == Examples
  #
  #   planner = StateMachines::Planner.new(vehicle, Vehicle.state_machine, to: :first_gear)
  #   plan = planner.plan
  #   plan.events         # => [:ignite, :shift_up]
  #   plan.total_cost     # => 3
  #   plan.pending_guards # => [{event: :ignite, if: [:seatbelt_on?]}]
  class Planner
    include EvalHelpers

    # The object the plan is being built for
    attr_reader :object

    # The state machine being planned on
    attr_reader :machine

    # The state the plan starts from
    attr_reader :from_name

    # The target state of the plan
    attr_reader :to_name

    # Creates a new planner for the given object and machine.
    #
    # Configuration options:
    # * <tt>:from</tt> - The initial state to start from.  Default is the
    #   object's current state.
    # * <tt>:to</tt> - The target state to plan towards.  Required.
    # * <tt>:weights</tt> - A hash of event name => non-negative numeric cost,
    #   overriding the weights defined on the events for this planning run.
    # * <tt>:evaluate_guards</tt> - A list of guard conditions (symbols,
    #   strings, or procs, compared by equality with the conditions defined on
    #   the transitions) that are allowed to be evaluated against the object
    #   during this planning run.  All other guards are treated as unknown and
    #   reported as pending conditions on the resulting plan.
    def initialize(object, machine, options = {})
      options = { from: machine.states.match!(object).name }.merge(options)
      StateMachines::OptionsValidator.assert_valid_keys!(options, :from, :to, :weights, :evaluate_guards)
      raise ArgumentError, 'Must specify a :to target state to plan towards' unless options[:to]

      @object = object
      @machine = machine
      @from_name = machine.states.fetch(options[:from]).name
      @to_name = machine.states.fetch(options[:to]).name
      @weights = validate_weights(options[:weights] || {})
      @evaluate_guards = Array(options[:evaluate_guards])
    end

    # Computes the cheapest plan towards the target state.  Returns a
    # StateMachines::Plan, or nil if the target state cannot be reached.
    def plan
      return build_plan([]) if from_name == to_name

      # state name => [cost, steps], the best known way to reach that state
      best = { from_name => [0, []] }
      settled = {}

      loop do
        entry = best.reject { |state, _| settled[state] }.min_by { |_, (cost, steps)| plan_key(cost, steps) }
        break unless entry

        state, (cost, steps) = entry
        break if state == to_name

        settled[state] = true
        steps_from(state).each do |step|
          next if settled[step.to_name]

          candidate = [cost + step.weight, steps + [step]]
          current = best[step.to_name]
          best[step.to_name] = candidate if current.nil? || better?(candidate, current)
        end
      end

      best[to_name] ? build_plan(best[to_name].last) : nil
    end

    private

    # Builds the deterministic ordering key for a partial plan.  Plans are
    # ordered by total cost, then number of events, then the sequence of
    # event names so that equivalent optima always resolve the same way.
    def plan_key(cost, steps)
      [cost, steps.length, steps.map { |step| step.event.to_s }.join("\0")]
    end

    # Whether the candidate way of reaching a state is strictly better than
    # the current best known way
    def better?(candidate, current)
      (plan_key(*candidate) <=> plan_key(*current)).negative?
    end

    # Lists the steps that could be taken from the given state, mirroring how
    # Event#transition_for resolves branches at runtime: for each event (in
    # definition order) the first branch matching the from state wins, and
    # guards that are not whitelisted for evaluation are left unverified.
    def steps_from(state)
      machine.events.each_with_object([]) do |event, steps|
        event.branches.each do |branch|
          next unless (match = branch.match(object, { from: state, guard: false }))
          next unless allowed_guards_pass?(branch)

          to = resolve_to(match, state)
          next unless to

          steps << Plan::Step.new(event: event.name, from_name: state, to_name: to, weight: weight_for(event), guards: pending_guards_for(branch))
          break
        end
      end
    end

    # Resolves the state a branch transitions to, using the same rules as
    # Event#transition_for
    def resolve_to(match, from)
      if match[:to].is_a?(LoopbackMatcher)
        from
      else
        match[:to].filter([from] | machine.states.map(&:name)).first
      end
    end

    # Evaluates the guards whitelisted via :evaluate_guards against the
    # object.  Returns false if any of them rejects the branch.
    def allowed_guards_pass?(branch)
      Array(branch.if_condition).all? { |condition| !evaluable_guard?(condition) || evaluate_method(object, condition) } &&
        Array(branch.unless_condition).none? { |condition| evaluable_guard?(condition) && evaluate_method(object, condition) }
    end

    # The guards of the branch that remain unverified by this planning run
    def pending_guards_for(branch)
      {
        if: Array(branch.if_condition).reject { |condition| evaluable_guard?(condition) },
        unless: Array(branch.unless_condition).reject { |condition| evaluable_guard?(condition) },
        state_guards: branch.state_guards
      }.reject { |_, conditions| conditions.nil? || conditions.empty? }
    end

    # Whether the given guard condition may be evaluated during this run
    def evaluable_guard?(condition)
      @evaluate_guards.any? { |allowed| allowed == condition }
    end

    # The planning cost of the given event
    def weight_for(event)
      @weights.fetch(event.name) { event.weight }
    end

    def validate_weights(weights)
      weights.each do |event_name, weight|
        raise ArgumentError, "weight for event #{event_name.inspect} must be a non-negative number, got #{weight.inspect}" unless weight.is_a?(Numeric) && weight >= 0
      end
      weights.transform_keys(&:to_sym).freeze
    end

    def build_plan(steps)
      Plan.new(object, machine, from_name: from_name, to_name: to_name, steps: steps)
    end
  end
end
