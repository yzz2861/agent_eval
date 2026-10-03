# frozen_string_literal: true

require_relative 'options_validator'

module StateMachines
  # An event defines an action that transitions an attribute from one state to
  # another.  The state that an attribute is transitioned to depends on the
  # branches configured for the event.
  class Event
    include MatcherHelpers

    # The state machine for which this event is defined
    attr_accessor :machine

    # The name of the event
    attr_reader :name

    # The fully-qualified name of the event, scoped by the machine's namespace
    attr_reader :qualified_name

    # The human-readable name for the event
    attr_writer :human_name

    # The list of branches that determine what state this event transitions
    # objects to when fired
    attr_reader :branches

    # A list of all of the states known to this event using the configured
    # branches/transitions as the source
    attr_reader :known_states

    # Creates a new event within the context of the given machine
    #
    # Configuration options:
    # * <tt>:human_name</tt> - The human-readable version of this event's name
    def initialize(machine, name, options = nil, human_name: nil, **extra_options) # :nodoc:
      # Handle both old hash style and new kwargs style for backward compatibility
      case options
      in Hash
        # Old style: initialize(machine, name, {human_name: 'Custom Name'})
        StateMachines::OptionsValidator.assert_valid_keys!(options, :human_name)
        human_name = options[:human_name]
      in nil
        # New style: initialize(machine, name, human_name: 'Custom Name')
        StateMachines::OptionsValidator.assert_valid_keys!(extra_options, :human_name) unless extra_options.empty?
      else
        # Handle unexpected options
        raise ArgumentError, "Unexpected positional argument in Event initialize: #{options.inspect}"
      end

      @machine = machine
      @name = name
      @qualified_name = machine.namespace ? :"#{name}_#{machine.namespace}" : name
      @human_name = human_name || @name.to_s.tr('_', ' ')
      reset

      # Output a warning if another event has a conflicting qualified name
      if (conflict = machine.owner_class.state_machines.detect { |_other_name, other_machine| other_machine != @machine && other_machine.events[qualified_name, :qualified_name] })
        _name, other_machine = conflict
        warn "Event #{qualified_name.inspect} for #{machine.name.inspect} is already defined in #{other_machine.name.inspect}"
      else
        add_actions
      end
    end

    # Creates a copy of this event in addition to the list of associated
    # branches to prevent conflicts across events within a class hierarchy.
    def initialize_copy(orig) # :nodoc:
      super
      @branches = @branches.dup
      @known_states = @known_states.dup
    end

    # Transforms the event name into a more human-readable format, such as
    # "turn on" instead of "turn_on"
    def human_name(klass = @machine.owner_class)
      @human_name.is_a?(Proc) ? @human_name.call(self, klass) : @human_name
    end

    # Evaluates the given block within the context of this event.  This simply
    # provides a DSL-like syntax for defining transitions.
    def context(&)
      instance_eval(&)
    end

    # Creates a new transition that determines what to change the current state
    # to when this event fires.
    #
    # Since this transition is being defined within an event context, you do
    # *not* need to specify the <tt>:on</tt> option for the transition.  For
    # example:
    #
    #  state_machine do
    #    event :ignite do
    #      transition :parked => :idling, :idling => same, :if => :seatbelt_on? # Transitions to :idling if seatbelt is on
    #      transition all => :parked, :unless => :seatbelt_on?                  # Transitions to :parked if seatbelt is off
    #    end
    #  end
    #
    # See StateMachines::Machine#transition for a description of the possible
    # configurations for defining transitions.
    def transition(options)
      options = options.dup
      raise ArgumentError, 'Must specify as least one transition requirement' if options.empty?
      # Only a certain subset of explicit options are allowed for transition
      # requirements
      valid_keys = %i[from to except_from except_to if unless if_state unless_state if_all_states unless_all_states if_any_state unless_any_state region parent_state on except_on]
      implicit_pairs = options.select { |key, _value| !valid_keys.include?(key) }
      if implicit_pairs.empty?
        legacy_keys = %i[from to except_from except_to if unless if_state unless_state if_all_states unless_all_states if_any_state unless_any_state]
        StateMachines::OptionsValidator.assert_valid_keys!(options, *legacy_keys)
      end
      unless implicit_pairs.empty?
        implicit_pairs.each_key { |key| options.delete(key) }
      end

      branch_options = options.merge(on: name)
      unless implicit_pairs.empty?
        branch_options[:implicit_state_requirements] = implicit_pairs.map { |from, to| { from: from, to: to } }
      end

      branches << branch = Branch.new(branch_options)
      @known_states |= branch.state_requirements.flat_map do |requirement|
        %i[from to].flat_map do |option|
          matcher = requirement[option]
          matcher == AllMatcher.instance || matcher == LoopbackMatcher.instance ? [] : matcher.values
        end
      end
      branch
    end

    # Determines whether any transitions can be performed for this event based
    # on the current state of the given object.
    #
    # If the event can't be fired, then this will return false, otherwise true.
    #
    # *Note* that this will not take the object context into account.  Although
    # a transition may be possible based on the state machine definition,
    # object-specific behaviors (like validations) may prevent it from firing.
    def can_fire?(object, requirements = {})
      !transition_for(object, requirements).nil?
    end

    # Finds and builds the next transition that can be performed on the given
    # object.  If no transitions can be made, then this will return nil.
    #
    # Valid requirement options:
    # * <tt>:from</tt> - One or more states being transitioned from.  If none
    #   are specified, then this will be the object's current state.
    # * <tt>:to</tt> - One or more states being transitioned to.  If none are
    #   specified, then this will match any to state.
    # * <tt>:guard</tt> - Whether to guard transitions with the if/unless
    #   conditionals defined for each one.  Default is true.
    #
    # Event arguments are passed to guard conditions if they accept multiple parameters.
    def transition_for(object, requirements = {}, *event_args)
      return transitions_for(object, requirements, *event_args).first if machine.orthogonal_configured?

      StateMachines::OptionsValidator.assert_valid_keys!(requirements, :from, :to, :guard)
      requirements[:from] = machine.states.match!(object).name unless (custom_from_state = requirements.include?(:from))

      branches.each do |branch|
        next unless (match = branch.match(object, requirements, event_args))

        # Branch allows for the transition to occur
        from = requirements[:from]
        to = if match[:to].is_a?(LoopbackMatcher)
               from
             else
               values = requirements.include?(:to) ? [requirements[:to]].flatten : [from] | machine.states.map { |state| state.name }

               match[:to].filter(values).first
             end

        return Transition.new(object, machine, name, from, to, !custom_from_state)
      end

      # No transition matched
      nil
    end

    # Builds every region transition selected for one event. Transitions are
    # selected before callbacks run, so guards observe the same configuration.
    def transitions_for(object, requirements = {}, *event_args)
      machine.transitions_for_event(self, object, requirements, *event_args)
    end

    def transition_in_frame(object, frame, requirements = {}, event_args = [])
      requirements = requirements.dup
      requirements[:from] = frame[:state].name
      transition_for_branch(object, frame, requirements, event_args)
    end

    def transition_for_branch(object, frame, requirements = {}, event_args = [])
      custom_from_state = requirements.include?(:from)

      branches.each do |branch|
        next unless branch_applicable_in_frame?(branch, frame)
        next unless (match = branch.match(object, requirements, event_args))

        from = requirements[:from]
        to = if match[:to].is_a?(LoopbackMatcher)
               from
             else
               values = requirements.include?(:to) ? [requirements[:to]].flatten : [from] | machine.states.map { |state| state.name }
               selected_to = match[:to].filter(values).first
               next unless selected_to

               selected_to
             end

        read_state = machine.orthogonal_configured? ? false : !custom_from_state
        transition = Transition.new(object, machine, name, from, to, read_state)
        transition.region_path = transition.from_state.parent_region&.path || []
        return transition
      end

      nil
    end

    def branch_applicable_in_frame?(branch, frame)
      return true if frame.nil?

      region = frame&.dig(:region)
      source_matches = branch.state_requirements.any? do |requirement|
        requirement[:from].matches?(frame[:state]&.name)
      end

      if frame[:ancestor]
        return source_matches if branch.region_path.empty?
        return false unless region

        return source_matches if region.path[0...branch.region_path.length] == branch.region_path

        branch.region_path == region.path &&
          (branch.parent_state_name.nil? || branch.parent_state_name == region.parent_state&.name) &&
          source_matches
      end

      return false unless region
      return false unless source_matches
      return true if region.path.include?(frame[:state]&.name)

      branch.region_path == region.path &&
        (branch.parent_state_name.nil? || branch.parent_state_name == region.parent_state&.name)
    end

    # Attempts to perform the next available transition on the given object.
    # If no transitions can be made, then this will return false, otherwise
    # true.
    #
    # Any additional arguments are passed to the StateMachines::Transition#perform
    # instance method.
    def fire(object, *event_args, preselected_transitions: nil, from_helper: false, helper_run_action: nil, **event_options)
      machine.reset(object)
      event_args << event_options unless event_options.empty?

      run_action = helper_run_action.nil? ? true : helper_run_action
      if from_helper
        if event_args.length == 1 && (event_args.first.equal?(true) || event_args.first.equal?(false)) && preselected_transitions.nil?
          run_action = event_args.pop
        elsif event_args.length > 1 && (event_args.last.equal?(true) || event_args.last.equal?(false)) && !event_args[-2].equal?(true) && !event_args[-2].equal?(false)
          run_action = event_args.pop
        end
      elsif event_args.length == 1 && (event_args.first.equal?(true) || event_args.first.equal?(false))
        run_action = event_args.pop
      elsif boolean_run_action?(event_args)
        run_action = event_args.pop
      end
      transitions = preselected_transitions || (machine.orthogonal_configured? ? transitions_for(object, {}, *event_args) : Array(transition_for(object, {}, *event_args)))
      transitions.each { |transition| transition.args = event_args }

      if transitions.any?
        result = TransitionCollection.new(transitions,
                                          use_transactions: machine.use_transactions,
                                          actions: run_action).perform
        machine.run_completion_transitions(object, event_args, run_action) if result && machine.orthogonal_configured?
        result
      else
        on_failure(object, *event_args)
        false
      end
    end

    # Marks the object as invalid and runs any failure callbacks associated with
    # this event.  This should get called anytime this event fails to transition.
    def on_failure(object, *args)
      state = machine.orthogonal_configured? ? machine.active_states(object).first : machine.states.match!(object)
      state ||= machine.initial_state(object)
      machine.invalidate(object, :state, :invalid_transition, [[:event, human_name(object.class)], [:state, state.human_name(object.class)]])

      transition = Transition.new(object, machine, name, state.name, state.name)
      transition.args = args if args.any?
      transition.run_callbacks(before: false)
    end

    # Resets back to the initial state of the event, with no branches / known
    # states associated.  This allows you to redefine an event in situations
    # where you either are re-using an existing state machine implementation
    # or are subclassing machines.
    def reset
      @branches = []
      @known_states = []
    end

    def draw(graph, options = {}, io = $stdout)
      machine.renderer.draw_event(self, graph, options, io)
    end

    # Generates a nicely formatted description of this event's contents.
    #
    # For example,
    #
    #   event = StateMachines::Event.new(machine, :park)
    #   event.transition all - :idling => :parked, :idling => same
    #   event   # => #<StateMachines::Event name=:park transitions=[all - :idling => :parked, :idling => same]>
    def inspect
      transitions = branches.flat_map do |branch|
        branch.state_requirements.map do |state_requirement|
          "#{state_requirement[:from].description} => #{state_requirement[:to].description}"
        end
      end.join(', ')

      "#<#{self.class} name=#{name.inspect} transitions=[#{transitions}]>"
    end

    protected

    def boolean_run_action?(event_args)
      return false if event_args.empty?

      if event_args.length > 1
        (event_args.last.equal?(true) || event_args.last.equal?(false)) &&
          !event_args[-2].equal?(true) && !event_args[-2].equal?(false)
      end
    end

    # Add the various instance methods that can transition the object using
    # the current event
    def add_actions
      # Checks whether the event can be fired on the current object
      machine.define_helper(:instance, "can_#{qualified_name}?") do |machine, object, *args, **kwargs|
        machine.event(name).can_fire?(object, *args, **kwargs)
      end

      # Gets the next transition that would be performed if the event were
      # fired now
      machine.define_helper(:instance, "#{qualified_name}_transition") do |machine, object, *args, **kwargs|
        machine.event(name).transition_for(object, *args, **kwargs)
      end

      # Fires the event
      machine.define_helper(:instance, qualified_name) do |machine, object, *args, **kwargs|
        event = machine.event(name)
        run_action = true
        preselected = nil
        if args.length == 1 && (args.last.equal?(true) || args.last.equal?(false))
          preselected = machine.orthogonal_configured? ? event.transitions_for(object, {}, *args) : Array(event.transition_for(object, {}, *args))
          without_boolean = machine.orthogonal_configured? ? event.transitions_for(object, {}) : Array(event.transition_for(object, {}))
          if preselected.any? && preselected.map(&:to_name) != without_boolean.map(&:to_name)
          else
            preselected = nil
            run_action = false
            args.pop
          end
        elsif args.length > 1 && (args.last.equal?(true) || args.last.equal?(false)) && !args[-2].equal?(true) && !args[-2].equal?(false)
          run_action = args.pop
        end

        event.fire(object, *args, **kwargs, preselected_transitions: preselected, from_helper: true, helper_run_action: run_action)
      end

      # Fires the event, raising an exception if it fails
      machine.define_helper(:instance, "#{qualified_name}!") do |machine, object, *args, **kwargs|
        object.send(qualified_name, *args, **kwargs) || raise(StateMachines::InvalidTransition.new(object, machine, name))
      end
    end
  end
end
