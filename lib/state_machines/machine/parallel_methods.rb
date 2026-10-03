# frozen_string_literal: true

module StateMachines
  class Machine
    # Adds support for parallel (composite) states with orthogonal regions.
    #
    # A parallel state groups two or more regions, each of which tracks its
    # own active substate while the object is inside the parallel state.
    # This allows independent axes of progress -- such as payment and
    # fulfillment for an order -- to live in a single state machine backed
    # by a single attribute, instead of being split into multiple machines
    # that know nothing about each other.
    #
    # == Defining parallel states
    #
    #   class Order
    #     state_machine initial: :cart do
    #       parallel_state :processing do
    #         region :payment do
    #           state :awaiting_payment, initial: true
    #           state :paid
    #         end
    #
    #         region :fulfillment do
    #           state :awaiting_stock, initial: true
    #           state :shipped
    #         end
    #
    #         on_complete :complete_processing
    #       end
    #
    #       event :checkout do
    #         transition cart: :processing
    #       end
    #
    #       event :pay do
    #         transition awaiting_payment: :paid
    #       end
    #
    #       event :ship do
    #         transition awaiting_stock: :shipped
    #       end
    #
    #       event :complete_processing do
    #         transition processing: :completed
    #       end
    #     end
    #   end
    #
    # == Event dispatch semantics
    #
    # When an event is fired while the object is inside a parallel state, the
    # event is offered to every region.  The full set of transitions -- at
    # most one per region -- is determined *before* any callback is executed:
    #
    # * Regions are evaluated in the order in which they were defined.
    # * A region consumes the event if one of the event's branches matches
    #   the region's currently active substate.
    # * Child-before-parent priority: the parent parallel state only handles
    #   the event itself (e.g. <tt>transition processing: :cancelled</tt>)
    #   when *no* region consumed it.
    # * If a region's transition targets a state outside the region, the
    #   whole parallel state is exited; every other active region is exited
    #   as well.
    #
    # Callbacks for the resulting transition set run in region definition
    # order.  When the parallel state is exited, each active region is
    # properly exited first (in region order) via a loopback transition on
    # its active substate, so callbacks hooked to those substates still run.
    #
    # == Completion
    #
    # Once *all* regions of a parallel state have reached a final state (a
    # state with no outgoing transitions), the completion event configured
    # via +on_complete+ is fired automatically.
    #
    # == Attribute storage
    #
    # The single machine attribute continues to hold one string value.  While
    # an object is inside a parallel state, the value encodes the active
    # substate of each region, e.g.:
    #
    #   order.state  # => "processing(payment:awaiting_payment,fulfillment:awaiting_stock)"
    #
    # Reading helpers remain compatible: +state_name+ returns the parallel
    # state's name (<tt>:processing</tt>), predicates such as +processing?+
    # keep working, and predicates for region substates (e.g. +paid?+)
    # reflect the region's active substate.
    module ParallelMethods
      # Defines a parallel (composite) state with orthogonal regions.  See
      # StateMachines::Machine::ParallelMethods for full documentation.
      #
      # Configuration options:
      # * <tt>:value</tt> - The value prefix stored in the attribute while the
      #   object is in this state.  Default is the name (stringified).
      # * <tt>:human_name</tt> - The human-readable version of this state's name
      def parallel_state(name, options = {}, &block)
        raise ArgumentError, 'Must specify a block defining the orthogonal regions' unless block

        StateMachines::OptionsValidator.assert_valid_keys!(options, :value, :human_name)

        state = add_states([name]).first
        if options.include?(:value)
          state.value = options[:value]
          states.update(state)
        end
        state.human_name = options[:human_name] if options.include?(:human_name)

        ParallelStateContext.new(self, state).instance_eval(&block)

        raise ArgumentError, "Parallel state #{name.inspect} must define at least one region" if state.regions.empty?

        configure_parallel_state_matcher(state)
        define_parallel_helpers

        state
      end

      # Whether this machine defines any parallel states
      def parallel?
        states.any? { |state| state.parallel? }
      end

      # The list of parallel (composite) states defined in this machine
      def parallel_states
        states.select { |state| state.parallel? }
      end

      # The list of all orthogonal regions across all parallel states
      def regions
        parallel_states.flat_map(&:regions)
      end

      # Gets the orthogonal region with the given name.  Raises an IndexError
      # if no such region exists.
      def parallel_region(name)
        regions.detect { |region| region.name == name.to_sym } ||
          raise(IndexError, "#{name.inspect} is an invalid region")
      end

      # Gets the parallel state the given object is currently in, or nil if
      # the object is not in a parallel state.
      def parallel_state_for(object)
        return unless parallel?

        value = read(object, :state)
        parallel_states.detect { |state| state.matches?(value) }
      end

      # Gets the currently active substate of the given region for the object.
      # The region can be referenced by name or passed as a Region instance.
      def region_state(object, region)
        region = parallel_region(region) unless region.is_a?(Region)
        decoded = decode_parallel_value(read(object, :state))
        leaf_value = decoded.fetch(region.name) { region.initial_state.value }
        region.states.detect { |state| state.matches?(leaf_value) } || region.initial_state
      end

      # Gets the list of currently active leaf states for the object.  When
      # the object is inside a parallel state, this is the active substate of
      # each region (in region definition order); otherwise it is simply the
      # object's current state.
      def current_states(object)
        if (parallel_state = parallel_state_for(object))
          parallel_state.regions.map { |region| region_state(object, region) }
        else
          [states.match!(object)]
        end
      end

      # Determines the full set of transitions that would be performed if the
      # given event were fired on the object while inside a parallel state.
      # The set is computed entirely before any transition is performed.
      def parallel_transitions_for(event, object, event_args = [])
        event = events.fetch(event) unless event.is_a?(Event)
        parallel_state = parallel_state_for(object)
        return [] unless parallel_state

        snapshot = read(object, :state)
        transitions = []

        parallel_state.regions.each do |region|
          leaf = region_state(object, region)
          next unless (transition = event.transition_for(object, { from: leaf.name }, *event_args))

          if region.include?(transition.to_name)
            transition.region = region
            transition.configuration_snapshot = snapshot
            transitions << transition
          else
            # The transition leaves the region: the entire parallel state is
            # exited, properly exiting every other active region as well
            return parallel_exit_transitions(event, object, parallel_state, transition, snapshot, except: region)
          end
        end

        if transitions.empty?
          # Child-before-parent priority: the parent parallel state only
          # handles the event when none of its regions consumed it
          if (transition = event.transition_for(object, { from: parallel_state.name }, *event_args))
            return parallel_exit_transitions(event, object, parallel_state, transition, snapshot)
          end
        end

        transitions
      end

      # Fires the given event on the object while it is inside a parallel
      # state.  The transition set is determined first; only then are any
      # callbacks executed.
      def fire_parallel_event(event, object, event_args)
        event_args = event_args.dup
        run_action = case event_args.last
                     in true | false
                       event_args.pop
                     in { run_action: }
                       event_args.last.delete(:run_action)
                     else
                       true
                     end

        transitions = parallel_transitions_for(event, object, event_args)

        if transitions.empty?
          event.on_failure(object, *event_args)
          return false
        end

        transitions.each { |transition| transition.args = event_args }

        result = ParallelTransitionCollection.new(
          transitions,
          use_transactions: use_transactions,
          actions: run_action
        ).perform

        check_parallel_completion(object, event_args, run_action) if result

        result
      end

      # Encodes the value stored in the machine's attribute for the given
      # parallel state and a mapping of region names to substate values.
      def encode_parallel_value(state, region_values)
        parts = state.regions.map { |region| "#{region.name}:#{region_values[region.name]}" }
        "#{state.value}(#{parts.join(',')})"
      end

      # Encodes the attribute value used when first entering the given
      # parallel state: every region starts at its initial substate.
      def encode_initial_parallel_value(state)
        encode_parallel_value(state, state.regions.to_h { |region| [region.name, region.initial_state.value] })
      end

      # Decodes a parallel attribute value into a mapping of region names to
      # their active substate values.  Returns an empty hash for values that
      # do not encode a region configuration.
      def decode_parallel_value(value)
        decoded = {}
        string = value.to_s
        return decoded unless (match = string.match(/\((.+)\)\z/))

        match[1].split(',').each do |pair|
          key, val = pair.split(':', 2)
          decoded[key.to_sym] = val
        end
        decoded
      end

      # Persists the attribute value for the given transition, taking
      # orthogonal regions into account:
      # * Region transitions update only their region's active substate
      # * Transitions into a parallel state initialize every region
      # * All other transitions behave exactly as before
      def persist_transition(transition)
        if (region = transition.region)
          persist_region_transition(transition, region)
        else
          to_state = states.fetch(transition.to_name)
          value = to_state.parallel? ? encode_initial_parallel_value(to_state) : transition.to
          write(transition.object, :state, value)
        end
      end

      protected

      # Persists a region-local transition by rewriting only that region's
      # active substate within the encoded attribute value
      def persist_region_transition(transition, region)
        parallel_state = region.state
        decoded = decode_parallel_value(read(transition.object, :state))
        region_values = {}
        parallel_state.regions.each do |r|
          region_values[r.name] = decoded.fetch(r.name) { r.initial_state.value }
        end
        region_values[region.name] = transition.to
        write(transition.object, :state, encode_parallel_value(parallel_state, region_values))
      end

      # Builds the transition set used when the parallel state is exited:
      # each active region (except the one that originated the exit, if any)
      # is exited first via a loopback transition on its active substate,
      # followed by the actual exit transition.  Regions are exited in
      # definition order.
      def parallel_exit_transitions(event, object, parallel_state, exit_transition, snapshot, except: nil)
        transitions = parallel_state.regions.filter_map do |region|
          next if region == except

          leaf = region_state(object, region)
          exit = Transition.new(object, self, event.name, leaf.name, leaf.name, false)
          exit.region = region
          exit.configuration_snapshot = snapshot
          exit
        end
        exit_transition.configuration_snapshot = snapshot
        transitions << exit_transition
        transitions
      end

      # Fires the parallel state's completion event once every region has
      # reached a final state
      def check_parallel_completion(object, event_args, run_action)
        parallel_state = parallel_state_for(object)
        return unless parallel_state&.completion_event
        return unless parallel_state.regions.all? { |region| region_state(object, region).final? }

        completion_event = events[parallel_state.completion_event]
        completion_event&.fire(object, *event_args, run_action) if completion_event&.can_fire?(object)
      end

      # Allows the encoded configuration value to resolve back to the
      # parallel state (and region substates to resolve within their region)
      def configure_parallel_state_matcher(state)
        state_value = state.value
        state.matcher = lambda do |value|
          string = value.to_s
          string == state_value.to_s || string.start_with?("#{state_value}(")
        end

        state.regions.each do |region|
          region.states.each do |leaf|
            leaf_value = leaf.value
            initial_value = region.initial_state.value
            region_name = region.name
            parent_value = state_value.to_s
            machine = self
            leaf.matcher = lambda do |value|
              next true if value == leaf_value

              decoded = machine.decode_parallel_value(value)
              if decoded.key?(region_name)
                decoded[region_name] == leaf_value.to_s
              else
                # Bare parent value (no encoded configuration): every region
                # is at its initial substate
                value.to_s == parent_value && initial_value == leaf_value
              end
            end
          end
        end
      end

      # Defines instance helpers for querying orthogonal regions
      def define_parallel_helpers
        return if @parallel_helpers_defined

        @parallel_helpers_defined = true

        define_helper(:instance, :current_states) do |machine, object|
          machine.current_states(object)
        end

        define_helper(:instance, :region_state) do |machine, object, region_name|
          machine.region_state(object, region_name)
        end
      end
    end
  end
end
