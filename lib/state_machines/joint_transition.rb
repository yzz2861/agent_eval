# frozen_string_literal: true

require_relative 'transition_collection'

module StateMachines
  # Performs a coordinated ("joint") transition across multiple independent
  # objects, each with its own state machine and event.  This is intended for
  # *in-memory* objects only (e.g. handing off a task where both the old and
  # the new owner's state must change together).
  #
  # Each participant is described as an "object, machine, event" triple and
  # can be given either as a hash or as a 3-element array:
  #
  #   StateMachines::JointTransition.perform([
  #     { object: order,   machine: :state,  event: :reassign },
  #     { object: courier, machine: :status, event: :start_delivery }
  #   ])
  #
  #   StateMachines::JointTransition.perform([
  #     [order, Order.state_machines[:state], :reassign],
  #     [courier, :status, :start_delivery]
  #   ])
  #
  # The machine may be referenced by its name / attribute or given as a
  # StateMachines::Machine instance.
  #
  # Semantics:
  # * The whole group is validated first: a transition is built for every
  #   participant before anything is performed.  If any event cannot
  #   transition, nothing is executed, failure callbacks run for the failed
  #   participants, and the call returns false.
  # * All transitions are then performed together (before callbacks, state
  #   persistence, actions, after callbacks).  If any action fails or an
  #   exception is raised, every participant's state attribute is restored
  #   to its original value.
  #
  # == Rollback scope
  #
  # Rollback only restores the *in-memory state attributes* of the
  # participants.  It is NOT a database transaction: any database writes (or
  # other side effects) performed by user callbacks or actions are outside
  # the rollback guarantee and will not be undone.
  #
  # == Concurrency
  #
  # Participants are locked in a canonical order (by object identity), so two
  # concurrent joint transitions that list the same objects in opposite
  # orders cannot deadlock.  Listing the same object more than once in a
  # single call is rejected with an ArgumentError before anything runs.
  #
  # The single-object StateMachines::InstanceMethods#fire_events API is
  # unaffected by this interface.
  class JointTransition
    # A transition collection whose transitions may belong to *different*
    # objects.  Actions are invoked on each transition's own object and no
    # transaction is opened (rollback is in-memory only).
    class Collection < TransitionCollection
      def initialize(transitions)
        super(transitions, use_transactions: false, actions: true)
      end

      protected

      # Uniqueness is scoped per object and attribute: distinct objects may
      # share attribute names.
      def assert_unique_attributes!
        pairs = map { |transition| [transition.object.object_id, transition.attribute] }.uniq
        raise ArgumentError, 'Cannot perform multiple transitions in parallel for the same object and state machine attribute' if pairs.length != length
      end

      private

      # Joint transitions never use the event-attribute / action-hook path;
      # they always run callbacks and actions directly.
      def use_event_attributes?
        false
      end

      # Runs each transition's action on its own object (rather than on the
      # first transition's object).
      def run_actions
        catch_exceptions do
          @success = all? do |transition|
            (action = transition.action).nil? || !!transition.object.send(action)
          end
        end
      end
    end

    # Runs a joint transition for the given participants.  Returns true if
    # every participant transitioned, false if validation or execution
    # failed (in which case all state attributes are left unchanged).
    def self.perform(participants)
      new(participants).perform
    end

    def initialize(participants)
      @participants = Array(participants).map { |participant| normalize(participant) }
      raise ArgumentError, 'Must specify at least one participant for a joint transition' if @participants.empty?
    end

    def perform
      reject_duplicate_objects!
      resolved = @participants.map { |participant| resolve(participant) }

      # Lock participants in a canonical order so that concurrent joint
      # transitions over the same objects cannot deadlock, regardless of the
      # order in which each group listed them.
      ordered = resolved.sort_by { |entry| entry[:object].object_id }
      with_locks(ordered.map { |entry| self.class.lock_for(entry[:object]) }) do
        if (transitions = build_transitions(ordered))
          perform_transitions(transitions)
        else
          false
        end
      end
    end

    class << self
      # Gets (or creates) the mutex guarding the given object.  Locks are
      # stored weakly so they don't prevent garbage collection of the
      # objects they guard.
      def lock_for(object)
        lock_registry_guard.synchronize { lock_registry[object] ||= Mutex.new }
      end

      private

      def lock_registry
        @lock_registry ||= ObjectSpace::WeakMap.new
      end

      def lock_registry_guard
        @lock_registry_guard ||= Mutex.new
      end
    end

    private

    # Normalizes a participant given as a hash or a 3-element array into a
    # hash of :object, :machine and :event.
    def normalize(participant)
      object, machine, event =
        case participant
        when Hash
          unknown = participant.keys - %i[object machine event]
          raise ArgumentError, "Unknown participant keys: #{unknown.map(&:inspect) * ', '}" unless unknown.empty?

          missing = %i[object machine event] - participant.keys
          raise ArgumentError, "Missing participant keys: #{missing.map(&:inspect) * ', '}" unless missing.empty?

          participant.values_at(:object, :machine, :event)
        when Array
          raise ArgumentError, 'Array participants must be [object, machine, event]' unless participant.length == 3

          participant
        else
          raise ArgumentError, "Invalid participant: #{participant.inspect} (expected a Hash or [object, machine, event])"
        end

      { object: object, machine: machine, event: event }
    end

    # Rejects groups that list the same object more than once.  This runs
    # before any validation or execution takes place.
    def reject_duplicate_objects!
      seen = {}
      @participants.each do |participant|
        object_id = participant[:object].object_id
        raise ArgumentError, 'Cannot perform a joint transition with the same object listed more than once' if seen[object_id]

        seen[object_id] = true
      end
    end

    # Resolves the machine and event references for a participant.
    def resolve(participant)
      object = participant[:object]
      machine = resolve_machine(object, participant[:machine])

      event = machine.events[participant[:event], :qualified_name]
      raise(InvalidEvent.new(object, participant[:event])) unless event

      participant.merge(machine: machine, event: event)
    end

    def resolve_machine(object, machine)
      return machine if machine.is_a?(StateMachines::Machine)

      machines = object.class.state_machines
      machines[machine] || machines.values.find { |candidate| candidate.name == machine.to_sym } ||
        raise(ArgumentError, "#{machine.inspect} is not a state machine defined on #{object.class}")
    end

    # Builds a transition for every participant.  If any event cannot
    # transition, failure callbacks are run for the failed participants and
    # nil is returned; nothing is performed in that case.
    def build_transitions(resolved)
      transitions = []
      failures = []

      resolved.each do |entry|
        if (transition = entry[:event].transition_for(entry[:object]))
          transitions << transition
        else
          failures << entry
        end
      end

      return transitions if failures.empty?

      failures.each { |entry| entry[:event].on_failure(entry[:object]) }
      nil
    end

    # Performs the validated transitions as a group.  If anything fails or
    # raises, every participant's state attribute is restored to its
    # original value.  Note that only in-memory state attributes are
    # restored; side effects of user callbacks / actions (such as database
    # writes) are not rolled back.
    def perform_transitions(transitions)
      Collection.new(transitions).perform
    rescue StandardError
      transitions.each(&:rollback)
      raise
    end

    # Acquires the given locks in order (already canonically sorted by the
    # caller), runs the block, and releases them.
    def with_locks(locks, &block)
      if locks.empty?
        yield
      else
        locks.first.synchronize { with_locks(locks[1..], &block) }
      end
    end
  end
end
