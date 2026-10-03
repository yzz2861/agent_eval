# frozen_string_literal: true

require_relative 'options_validator'

module StateMachines
  # Performs a joint transition across multiple objects as a single,
  # all-or-nothing operation.  Each participant names an object, a state
  # machine, and an event to fire on that object:
  #
  #   StateMachines::JointTransition.new([
  #     { object: assignee, machine: :state, event: :release },
  #     { object: task,     machine: :state, event: :hand_off },
  #     { object: reviewer, machine: :state, event: :assign }
  #   ]).perform
  #
  # Participants can also be given as 3-element arrays of
  #   [object, machine, event]
  #
  # == Semantics
  #
  # 1. The entire group is validated first: every participant's event must
  #    be able to transition from its object's current state.  If any
  #    participant cannot transition, nothing is executed and +perform+
  #    returns false.
  # 2. Only then are transitions executed: before callbacks, state
  #    persistence, actions, and after callbacks run for every participant.
  # 3. If execution fails -- a before callback halts, an action returns a
  #    falsey value, or an exception is raised -- the state attribute of
  #    *every* participant is restored to its original value.
  #
  # == Rollback scope
  #
  # The rollback guarantee covers *only* the in-memory state attributes of
  # the participating objects.  Any side effects produced by user callbacks
  # or actions -- most notably database writes -- are *not* rolled back.
  # If you need database-level atomicity, wrap the call in your own
  # transaction.
  #
  # == In-memory objects only
  #
  # This interface is intended for plain in-memory objects.  It never opens
  # a transaction and ignores each machine's +use_transactions+ setting;
  # integration-specific persistence hooks are not invoked.
  #
  # == Concurrency
  #
  # Each participating object is guarded by its own lock.  Locks are always
  # acquired in a canonical order (sorted by object id), so two concurrent
  # joint transitions listing the same objects -- even in opposite orders --
  # cannot deadlock.  Listing the same object more than once in a single
  # group is rejected with an ArgumentError before anything is executed.
  #
  # The single-object StateMachines::InstanceMethods#fire_events API is
  # unaffected by this class.
  class JointTransition
    # The normalized participants for this joint transition
    attr_reader :participants

    @locks = ObjectSpace::WeakMap.new
    @locks_mutex = Mutex.new

    class << self
      # Gets (or creates) the mutex guarding the given object.  The registry
      # holds objects weakly so locks do not prevent garbage collection.
      def lock_for(object)
        @locks_mutex.synchronize { @locks[object] ||= Mutex.new }
      end
    end

    # Creates a new joint transition from a list of participants.  Each
    # participant must be either:
    # * a Hash with +:object+, +:machine+, and +:event+ keys (+:machine+
    #   defaults to +:state+), or
    # * a 3-element array of [object, machine, event]
    #
    # Machines may be referenced by name or as StateMachines::Machine
    # instances.  Unknown machines raise ArgumentError and unknown events
    # raise StateMachines::InvalidEvent.  Listing the same object more than
    # once raises ArgumentError before anything is executed.
    def initialize(participants)
      participants = participants.to_a
      raise ArgumentError, 'Must specify at least one participant' if participants.empty?

      @participants = participants.map { |participant| normalize(participant) }

      objects = @participants.map { |participant| participant[:object] }
      if objects.map(&:object_id).uniq.length != objects.length
        raise ArgumentError, 'Cannot perform a joint transition with the same object listed more than once'
      end

      @participants.each { |participant| resolve!(participant) }
    end

    # Validates the whole group and, if every participant can transition,
    # runs the transitions.  Returns true if the joint transition succeeded,
    # false otherwise.  On failure, every participant's state attribute is
    # restored to its original value.  Exceptions raised by callbacks or
    # actions are re-raised after the rollback.
    def perform
      with_ordered_locks do
        transitions = build_transitions
        transitions ? execute(transitions) : false
      end
    end

    private

    # Normalizes a participant into a hash of :object, :machine, and :event
    def normalize(participant)
      case participant
      when Hash
        StateMachines::OptionsValidator.assert_valid_keys!(participant, :object, :machine, :event)
        {
          object: participant.fetch(:object),
          machine: participant.fetch(:machine, :state),
          event: participant.fetch(:event)
        }
      when Array
        unless participant.length == 3
          raise ArgumentError, "Invalid participant: #{participant.inspect}. Expected [object, machine, event]"
        end

        object, machine, event = participant
        { object: object, machine: machine, event: event }
      else
        raise ArgumentError, "Invalid participant: #{participant.inspect}. Expected a Hash or a 3-element Array"
      end
    end

    # Resolves the machine and event references for a participant, raising
    # on unknown names
    def resolve!(participant)
      participant[:machine] = resolve_machine(participant[:object], participant[:machine])

      event_name = participant[:event]
      event = participant[:machine].events[event_name, :qualified_name]
      raise(InvalidEvent.new(participant[:object], event_name)) unless event

      participant[:event] = event
    end

    # Finds the machine referenced by the given name (or passes through an
    # actual StateMachines::Machine instance)
    def resolve_machine(object, machine)
      return machine if machine.is_a?(StateMachines::Machine)

      machines = object.class.state_machines if object.class.respond_to?(:state_machines)
      resolved = machines && machine.respond_to?(:to_sym) ? machines[machine.to_sym] : nil
      raise ArgumentError, "#{machine.inspect} is not a state machine defined on #{object.class}" unless resolved

      resolved
    end

    # Builds the transition for every participant.  Returns nil if any
    # participant's event cannot transition from its object's current state.
    def build_transitions
      transitions = @participants.map do |participant|
        participant[:event].transition_for(participant[:object])
      end
      transitions.all? ? transitions : nil
    end

    # Runs the given transitions, restoring every participant's state
    # attribute if any part of the group fails
    def execute(transitions)
      @results = {}
      @success = false

      begin
        catch(:halt) { run_callbacks(transitions) }
        rollback(transitions) unless @success
      rescue StandardError
        rollback(transitions)
        raise
      end

      @success
    end

    # Runs each transition's callbacks recursively.  Once all before
    # callbacks have run, every transition is persisted and each object's
    # action (if any) is invoked
    def run_callbacks(transitions, index = 0)
      if (transition = transitions[index])
        callback_result = transition.run_callbacks(after: true) do
          run_callbacks(transitions, index + 1)
          { result: @results[transition], success: @success }
        end

        throw :halt unless callback_result
      else
        transitions.each(&:persist)
        run_actions(transitions)
      end
    end

    # Invokes the action configured for each transition's machine.  Machines
    # without an action (the default for in-memory objects) are skipped
    def run_actions(transitions)
      transitions.each do |transition|
        action = transition.action
        @results[transition] = transition.object.send(action) if action
      end
      @success = @results.values.all?
    end

    # Restores the original state attribute of every participant
    def rollback(transitions)
      transitions.each(&:rollback)
    end

    # Acquires every participant's lock in a canonical order (sorted by
    # object id) so that concurrent joint transitions over the same objects
    # cannot deadlock, regardless of the order participants were listed in
    def with_ordered_locks
      locks = @participants.map { |participant| participant[:object] }
                           .sort_by(&:object_id)
                           .map { |object| self.class.lock_for(object) }
      acquired = []
      begin
        locks.each do |lock|
          lock.lock
          acquired << lock
        end
        yield
      ensure
        acquired.reverse_each(&:unlock)
      end
    end
  end

  # Performs a joint transition across multiple objects.  See
  # StateMachines::JointTransition for more information.
  #
  # == Example
  #
  #   StateMachines.joint_transition([
  #     { object: assignee, machine: :state, event: :release },
  #     { object: task,     machine: :state, event: :hand_off },
  #     { object: reviewer, machine: :state, event: :assign }
  #   ]) # => true
  def self.joint_transition(participants)
    JointTransition.new(participants).perform
  end
end
