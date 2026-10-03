# frozen_string_literal: true

module StateMachines
  module Orthogonal
    COMPLETION_EVENT = :complete

    def define_region(state_name, name = nil, initial: nil, &block)
      parent_state = states.fetch(state_name)
      parent_state.composite = true unless parent_state.composite?

      name ||= :default if parent_state.regions.length.zero?
      name ||= :"region_#{parent_state.regions.length + 1}"

      parent_region = parent_state.parent_region
      region = Region.new(name, self,
                          parent_state: parent_state,
                          parent_region: parent_region,
                          initial_state: initial && send(:add_states, [initial]).first,
                          order: parent_state.regions.length)
      @regions ||= []
      @regions << region
      parent_state.regions << region
      region.initial_state.parent_region ||= region if region.initial_state

      event(COMPLETION_EVENT) unless events[COMPLETION_EVENT]

      if block
        context = RegionDefinitionContext.new(self, region)
        context.instance_exec(&block)
        context.bind_defined_states!
      end

      region
    end

    def orthogonal_configured?
      defined?(@regions) && @regions.any?
    end

    def initialize_orthogonal_state(object)
      return unless orthogonal_configured?

      initial = initial_state(object)
      value = read(object, :state, true)
      return unless initial && (value.nil? || (value.respond_to?(:empty?) && value.empty?))

      write(object, :state, initial_region_value(initial), true)
    end

    def initial_region_value(state)
      return state.name unless state.composite? && state.regions.any? { |region| region.initial_state }

      value = { state.name => {} }

      state.regions.each do |region|
        next unless region.initial_state

        container = value[state.name]
        container[region.path.last] = initial_region_value(region.initial_state)
      end
      value
    end

    def active_state(object)
      active_leaf_states(object).first
    end

    def active_states(object)
      active_leaf_states(object)
    end

    def active_leaf_states(object)
      value = read(object, :state, true)
      collect_active_states(value)
    end

    def active_state_named?(object, name)
      state = states[name]
      return false unless state

      value = read(object, :state, true)
      return value == state.name unless state.composite?

      composite_value_active?(value, state.name)
    end

    def assign_states_to_region(names, region)
      names.each do |name|
        state = states[name]
        state.parent_region ||= region if state
      end
    end

    def assign_branch_sources_to_region(branch, region)
      branch.state_requirements.each do |requirement|
        names = requirement[:from].respond_to?(:values) ? requirement[:from].values : []
        assign_states_to_region(names, region)
      end
    end

    def transitions_for_event(event, object, requirements = {}, *event_args)
      value = read(object, :state, true)
      requirements = requirements.dup
      requirements.delete(:from)
      transitions = transitions_for_value(event, object, value, [], nil, requirements, event_args).flatten
      select_priority_transitions(transitions)
    end

    def run_completion_transitions(object, event_args, run_action = true)
      value = read(object, :state, true)
      transitions = completion_transitions(value, [], object)
      return true if transitions.empty?

      collection = TransitionCollection.new(transitions,
                                            use_transactions: false,
                                            actions: false,
                                            after: true)
      result = collection.perform
      run_completion_transitions(object, event_args, run_action) if result
      result
    end

    def persist_region_state(transition)
      value = read(transition.object, :state, true) || {}
      path = transition.region_path
      transition.previous_region_value = fetch_region_value(value, path)

      if path.empty?
        write(transition.object, :state, transition.to_state.composite? ? initial_region_value(transition.to_state) : transition.to_state.value)
      else
        target_value = transition.to_state.composite? ? initial_region_value(transition.to_state) : transition.to_state.name
        container = navigate_region_value(value, path[0...-1])
        container[path.last] = target_value
        write(transition.object, :state, value, true)
      end
    end

    def rollback_region_state(transition)
      path = transition.region_path
      if path.empty?
        write(transition.object, :state, transition.from)
        return
      end

      value = read(transition.object, :state, true) || {}
      container = navigate_region_value(value, path[0...-1])
      container[path.last] = transition.previous_region_value
      write(transition.object, :state, value, true)
    end

    private

    def transitions_for_value(event, object, value, path, parent_region, requirements, event_args)
      if value.is_a?(::Hash)
        state_name, child = value.first
        state = states[state_name]
        return [] unless state&.composite?

        transitions = []
        child.each do |region_name, region_value|
          region = state.regions.detect { |candidate| candidate.name == region_name }
          next unless region

          region_transitions = transitions_for_value(event, object, region_value, path + [state_name, region_name], region, requirements, event_args)
          transitions.concat(region_transitions)
        end
        transitions
      else
        state = states[value]
        return [] unless state

        frame = { state: state, path: path, region: parent_region, value: value }
        candidates = []
        local_transition = event.transition_in_frame(object, frame, requirements, event_args)
        candidates << local_transition if local_transition
        candidates.concat(ancestor_transitions(event, object, frame, requirements, event_args))
        candidates
      end
    end

    def ancestor_transitions(event, object, frame, requirements, event_args)
      region = frame[:region]
      return [] unless region

      candidates = []

      while region
        parent_frame = {
          state: region.parent_state,
          path: frame[:path][0...-2],
          region: region.parent_region,
          value: region.parent_state.name,
          ancestor: true
        }
        transition = event.transition_in_frame(object, parent_frame, requirements, event_args)
        candidates << transition if transition

        region = region.parent_region
        frame = parent_frame
      end

      candidates
    end

    def completion_transitions(value, path, object = nil)
      return [] unless value.is_a?(::Hash)

      state_name, child = value.first
      state = states[state_name]
      return [] unless state&.composite?

      ready = state.regions.all? do |region|
        region_value = child[region.name]
        region_state = region_value.is_a?(::Hash) ? states[region_value.keys.first] : states[region_value]
        next false unless region_state

        if region_state.composite?
          completion_transitions(region_value, path + [state_name, region.name], object).any?
        else
          region_state.final == true
        end
      end
      return [] unless ready

      event = events[COMPLETION_EVENT]
      return [] unless event

      frame = { state: state, path: path, region: state.parent_region, value: state_name, ancestor: true }
      transition = event.transition_in_frame(object, frame, {}, [])
      transition ? [transition] : []
    end

    def collect_active_states(value)
      if value.is_a?(::Hash)
        _state_name, child = value.first
        child.values.flat_map { |region_value| collect_active_states(region_value) }
      else
        states[value] ? [states[value]] : []
      end
    end

    def composite_value_active?(value, name)
      return false unless value.is_a?(::Hash)

      state_name, child = value.first
      return false unless state_name == name

      child.values.all? { |region_value| value_active?(region_value) }
    end

    def leaf_value_active?(value, name)
      if value.is_a?(::Hash)
        _state_name, child = value.first
        child.values.any? { |region_value| leaf_value_active?(region_value, name) }
      else
        value == name
      end
    end

    def value_active?(value)
      value.is_a?(::Hash) ? composite_value_active?(value, value.keys.first) : states.key?(value)
    end

    def select_priority_transitions(transitions)
      return transitions if transitions.empty?

      minimum_depth = transitions.map { |transition| transition.region_path.length }.min
      transitions
        .select { |transition| transition.region_path.length == minimum_depth }
        .uniq { |transition| [transition.event, transition.from_name, transition.to_name, transition.region_path] }
    end

    def fetch_region_value(value, path)
      path.reduce(value) do |current, key|
        return nil unless current.is_a?(::Hash)

        current[key]
      end
    end

    def navigate_region_value(value, path)
      path.reduce(value) do |current, key|
        current.is_a?(::Hash) ? current[key] : current
      end
    end

  end
end
