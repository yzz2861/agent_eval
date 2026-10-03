# frozen_string_literal: true

require_relative 'options_validator'
require_relative 'path_plan'

module StateMachines
  # Plans the cheapest sequence of events that transitions an object from its
  # current state to a target state, using per-event weights as the business
  # cost of firing each event.
  #
  # Planning is strictly read-only with respect to the state machine:
  #
  # * It never performs transitions, so no actions, callbacks, or state
  #   writes are triggered.
  # * It never treats arbitrary Ruby guards as static truth.  A guard is only
  #   evaluated against the object when the caller explicitly whitelists it
  #   via the +:evaluate_guards+ option for this planning run.  Every other
  #   guard is treated as an unknown condition: the transition is considered
  #   passable (optimistic) and the guard is reported in the resulting plan's
  #   +unverified_guards+ so the caller knows what still needs to hold when
  #   the events are actually fired.
  #
  # Deterministic rules:
  #
  # * Weights must be non-negative numbers; events without an explicit weight
  #   cost +DEFAULT_WEIGHT+ (1).
  # * Zero-weight cycles cannot loop the planner: every edge strictly
  #   increases the (cost, length, events) label of a path, so cycles are
  #   never part of an optimal route.
  # * When several routes are equally cheap, the one with fewer events wins;
  #   remaining ties are broken by the lexicographically smallest sequence of
  #   event names.  The result is therefore always deterministic.
  # * An unreachable target yields a plan where +reachable?+ is false,
  #   +events+ is empty, and +total_cost+ is nil.
  #
  # The returned PathPlan is advisory.  Firing the planned events through
  # +fire_event+ (or the generated event helpers) still re-evaluates all
  # guards against the live object at fire time.
  #
  # == Examples
  #
  #   planner = StateMachines::PathPlanner.new(vehicle, Vehicle.state_machine,
  #     to: :third_gear,
  #     weights: { shift_up: 2 },
  #     evaluate_guards: [:seatbelt_on?]
  #   )
  #   plan = planner.plan
  #   plan.events             # => [:ignite, :shift_up, :shift_up]
  #   plan.total_cost         # => 5
  #   plan.unverified_guards  # => [{ event: :ignite, ..., type: :unless, condition: :stalling? }]
  class PathPlanner
    include EvalHelpers

    # The cost assigned to events that have no explicit weight
    DEFAULT_WEIGHT = 1

    # The object the route is planned for
    attr_reader :object

    # The state machine being planned through
    attr_reader :machine

    # The state the route starts from
    attr_reader :from_name

    # The target state the route ends on
    attr_reader :to_name

    # Creates a new planner for the given object.
    #
    # Configuration options:
    # * <tt>:to</tt> - The target state to plan towards (required)
    # * <tt>:from</tt> - The state to plan from.  Defaults to the object's
    #   current state.
    # * <tt>:weights</tt> - A hash of event name => non-negative numeric cost.
    #   Events without an entry cost +DEFAULT_WEIGHT+.  Unknown event names
    #   and negative or non-numeric weights raise an ArgumentError.
    # * <tt>:evaluate_guards</tt> - The if/unless guard conditions (Symbol,
    #   Proc, or String, exactly as defined on the transition) that may be
    #   evaluated against the object during this planning run.  Guards that
    #   require event arguments (arity > 1) are never evaluated, even when
    #   whitelisted, since no event arguments exist at plan time.  All other
    #   guards -- including every state guard (+:if_state+ and friends) --
    #   are kept as unknown conditions.
    def initialize(object, machine, options = {})
      options = { from: machine.states.match!(object).name }.merge(options)
      StateMachines::OptionsValidator.assert_valid_keys!(options, :from, :to, :weights, :evaluate_guards)
      raise ArgumentError, 'A :to state is required for path planning' unless options[:to]

      @object = object
      @machine = machine
      @from_name = machine.states.fetch(options[:from]).name
      @to_name = machine.states.fetch(options[:to]).name
      @weights = build_weights(options[:weights] || {})
      @evaluate_guards = Array(options[:evaluate_guards])
    end

    # Computes the cheapest route to the target state and returns it as a
    # StateMachines::PathPlan.
    def plan
      label = compute_labels[to_name]
      build_plan(label)
    end

    private

    # Validates and normalizes the configured event weights
    def build_weights(weights)
      raise ArgumentError, ":weights must be a Hash of event name => non-negative numeric cost, got #{weights.inspect}" unless weights.is_a?(Hash)

      known_events = machine.events.map(&:name)
      weights.each_with_object(Hash.new(DEFAULT_WEIGHT)) do |(event, weight), normalized|
        event = event.to_sym
        raise ArgumentError, ":weights references unknown event #{event.inspect}" unless known_events.include?(event)
        raise ArgumentError, ":weights for event #{event.inspect} must be a non-negative numeric cost, got #{weight.inspect}" unless weight.is_a?(Numeric) && weight >= 0

        normalized[event] = weight
      end
    end

    # Builds the static graph of possible transitions.  Each edge is a hash of
    # +event+, +from+, +to+, +weight+, and +unverified+ (the guard conditions
    # that were not evaluated during planning).  Branches whose whitelisted
    # guards evaluate to a blocking result are excluded entirely.
    def edges
      @edges ||= begin
        state_names = machine.states.map(&:name)
        merged = {}
        machine.events.each do |event|
          event.branches.each do |branch|
            unverified = classify_guards(branch)
            next unless unverified

            branch.state_requirements.each do |requirement|
              state_names.select { |name| requirement[:from].matches?(name, from: name) }.each do |from|
                to_states = requirement[:to].is_a?(LoopbackMatcher) ? [from] : requirement[:to].filter(state_names)
                to_states.each do |to|
                  key = [event.name, from, to]
                  edge_unverified = unverified.map { |guard| guard.merge(event: event.name, from: from, to: to) }
                  if (existing = merged[key])
                    # Multiple branches can produce the same edge; at runtime
                    # the first matching branch wins, so optimistically keep
                    # the variant requiring the fewest verifications.
                    existing[:unverified] = edge_unverified if edge_unverified.length < existing[:unverified].length
                  else
                    merged[key] = { event: event.name, from: from, to: to, weight: @weights[event.name], unverified: edge_unverified }
                  end
                end
              end
            end
          end
        end
        merged.values
      end
    end

    # Splits a branch's guards into evaluated and unknown conditions.  Returns
    # nil when a whitelisted guard statically blocks the branch; otherwise
    # returns the list of guard descriptors that remain unverified.
    def classify_guards(branch)
      unverified = []

      Array(branch.if_condition).each do |condition|
        case evaluate_guard(condition)
        when :unknown then unverified << { type: :if, condition: condition }
        when false then return
        end
      end

      Array(branch.unless_condition).each do |condition|
        case evaluate_guard(condition)
        when :unknown then unverified << { type: :unless, condition: condition }
        when true then return
        end
      end

      # State guards depend on the runtime state of other machines and are
      # never evaluated during planning
      branch.state_guards.each do |guard_type, conditions|
        unverified << { type: guard_type, condition: conditions }
      end

      unverified
    end

    # Evaluates a whitelisted guard against the object.  Returns true/false
    # for evaluated guards, or :unknown when the guard must not (or cannot)
    # be evaluated during planning.
    def evaluate_guard(condition)
      return :unknown unless @evaluate_guards.include?(condition)
      return :unknown unless plan_time_evaluatable?(condition)

      !!evaluate_method_with_event_args(object, condition, [])
    end

    # Guards that require event arguments cannot be evaluated at plan time,
    # since no event arguments exist yet
    def plan_time_evaluatable?(condition)
      !(condition.is_a?(Proc) || condition.is_a?(Method)) || condition.arity <= 1
    end

    # Runs a label-setting search (Dijkstra) over the static graph.  Labels
    # are [cost, event count, event names, edges] tuples; the first three
    # elements strictly increase along every edge -- including zero-weight
    # edges -- so the search always terminates and zero-weight cycles are
    # never part of a result.
    def compute_labels
      labels = { from_name => [0, 0, [], []] }
      settled = {}

      loop do
        current, = labels.reject { |state, _| settled[state] }.min_by { |state, (cost, length, events, _)| [cost, length, events.map(&:to_s), state.to_s] }
        break unless current

        settled[current] = true
        break if current == to_name

        cost, length, events, path_edges = labels[current]
        edges.each do |edge|
          next unless edge[:from] == current && !settled[edge[:to]]

          candidate = [cost + edge[:weight], length + 1, events + [edge[:event]]]
          existing = labels[edge[:to]]
          next if existing && compare_labels(candidate, existing) >= 0

          labels[edge[:to]] = candidate + [path_edges + [edge]]
        end
      end

      labels
    end

    # Compares two search labels by total cost, then event count, then the
    # lexicographic ordering of event names
    def compare_labels(left, right)
      (left[0] <=> right[0]).nonzero? ||
        (left[1] <=> right[1]).nonzero? ||
        (left[2].map(&:to_s) <=> right[2].map(&:to_s)) ||
        0
    end

    # Builds the immutable plan result from the search label for the target
    def build_plan(label)
      if label
        events = label[2]
        path_edges = label[3]
        unverified = path_edges.flat_map { |edge| edge[:unverified] }.uniq
        PathPlan.new(object: object, machine: machine, from_name: from_name, to_name: to_name,
                     events: events, total_cost: label[0], unverified_guards: unverified)
      else
        PathPlan.new(object: object, machine: machine, from_name: from_name, to_name: to_name)
      end
    end
  end
end
