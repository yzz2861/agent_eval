# frozen_string_literal: true

module StateMachines
  # An orthogonal region inside a composite state. Every active region keeps
  # its own active substate while remaining part of the enclosing machine.
  class Region
    attr_accessor :parent_state, :parent_region
    attr_reader :name, :initial_state, :order

    def initialize(name, machine, parent_state:, parent_region: nil, initial_state: nil, order: 0)
      @name = name
      @machine = machine
      @parent_state = parent_state
      @parent_region = parent_region
      @initial_state = initial_state
      @order = order
    end

    def initial_state=(state)
      @initial_state = state
    end

    def path
      parent_path + [name]
    end

    def nested?
      !parent_state.nil?
    end

    def rewire(machine, states_by_name)
      @machine = machine
      @parent_state = states_by_name[parent_state.name] if parent_state
      @parent_region = machine.regions.detect { |region| region.name == parent_region&.name && region.parent_state == parent_state } if parent_region
      @initial_state = states_by_name[@initial_state] if @initial_state.is_a?(State)
      @parent_state.regions << self if @parent_state && !@parent_state.regions.include?(self)
      @parent_state.regions.sort_by!(&:order)
    end

    private

    def parent_path
      return [] unless nested?

      parent_region ? parent_region.path + [parent_state.name] : [parent_state.name]
    end
  end

  # DSL used while defining a region. It tags every branch created inside the
  # region so event resolution can constrain it to that region's active state.
  class RegionEventContext < BasicObject
    def initialize(machine, event_name, region:, parent_state: nil)
      @machine = machine
      @event_name = event_name
      @region = region
      @parent_state = parent_state
    end

    def transition(options)
      options = options.dup
      options[:region] = @region.path
      options[:parent_state] = @parent_state&.name
      @machine.event(@event_name) do
        branch = transition(options)
        @machine.assign_branch_sources_to_region(branch, @region)
        branch
      end
    end

    def method_missing(name, *args, **options, &block)
      if options.empty?
        @machine.public_send(name, *args, &block)
      else
        @machine.public_send(name, *args, **options, &block)
      end
    end

    def respond_to_missing?(name, include_private = false)
      @machine.respond_to?(name, include_private)
    end
  end

  class RegionDefinitionContext < BasicObject
    def initialize(machine, region)
      @machine = machine
      @region = region
      @state_names = machine.states.map(&:name)
    end

    def event(*names, &block)
      names.each do |name|
        ::Kernel.raise ::ArgumentError, 'Events require a block' unless block

        RegionEventContext
          .new(@machine, name, region: @region, parent_state: @region.parent_state)
          .instance_exec(&block)
      end
    end

    def initial(name)
      @region.initial_state = @machine.states.fetch(name)
    end

    def state(*names, **options, &block)
      states = @machine.state(*names, **options, &block)
      @machine.assign_states_to_region(names, @region)
      states
    end

    def method_missing(name, *args, **options, &block)
      if options.empty?
        @machine.public_send(name, *args, &block)
      else
        @machine.public_send(name, *args, **options, &block)
      end
    end

    def respond_to_missing?(name, include_private = false)
      @machine.respond_to?(name, include_private)
    end

    def bind_defined_states!
      new_names = @machine.states.map(&:name) - @state_names
      @machine.assign_states_to_region(new_names, @region)
    end
  end
end
