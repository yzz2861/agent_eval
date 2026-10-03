# frozen_string_literal: true

module StateMachines
  module Audit
    # A TransitionRecord is a serializable, structured description of a single
    # state transition that was observed (e.g. by an audit log).  It captures
    # only data; it never executes actions, callbacks or guards.
    #
    # Every record carries:
    # * +machine_identity+ - Stable identity of the machine this transition
    #   belongs to (for example +"Vehicle#state"+).
    # * +definition_fingerprint+ - Fingerprint of the exact machine definition
    #   that authorized the transition.  Records produced against different
    #   revisions of the same machine may carry different fingerprints.
    # * +event+ / +from+ / +to+ - The declared event and the state immediately
    #   before and after the transition.
    # * +sequence+ - The position of this transition in the machine's local
    #   history (1-based, gapless by default).
    #
    # Guard evaluation results are intentionally *not* part of a record.  A
    # record states that a transition happened; whether its dynamic guards
    # would pass cannot be re-evaluated from the record alone.
    class TransitionRecord
      # Stable identity of the machine (name, attribute or any caller-defined
      # identifier).
      attr_reader :machine_identity

      # Fingerprint of the machine definition that authorized this transition.
      attr_reader :definition_fingerprint

      # The event that was fired (Symbol or String).
      attr_reader :event

      # The declared state immediately before the transition.
      attr_reader :from

      # The declared state immediately after the transition.
      attr_reader :to

      # The 1-based, per-machine sequence number of this transition.
      attr_reader :sequence

      # Optional timestamp or token used for ordering/display only.  It is not
      # used for chain validation.
      attr_reader :recorded_at

      # Optional free-form metadata captured at audit time.
      attr_reader :metadata

      # Keys accepted by the constructor.
      ATTRIBUTES = %i[machine_identity definition_fingerprint event from to sequence recorded_at metadata].freeze

      # Builds a record from keyword arguments, a Hash, or an existing
      # StateMachines::Transition.
      def self.coerce(record = nil, **overrides)
        return new(**overrides) if record.nil? && !overrides.empty?

        case record
        when TransitionRecord
          record
        when StateMachines::Transition
          from_transition(record, **overrides)
        when Hash
          new(**record.merge(overrides))
        else
          raise ArgumentError, "cannot coerce #{record.inspect} into a TransitionRecord"
        end
      end

      # Builds a record from a live StateMachines::Transition.  The machine
      # identity and fingerprint can be supplied explicitly; by default they
      # are derived from the transition's machine.
      def self.from_transition(transition, machine_identity: nil, definition_fingerprint: nil,
                               sequence: nil, recorded_at: nil, metadata: nil)
        machine = transition.machine
        new(
          machine_identity: machine_identity || machine_identity_for(machine),
          definition_fingerprint: definition_fingerprint || MachineDefinition.fingerprint_for(machine),
          event: transition.event,
          from: transition.from_name,
          to: transition.to_name,
          sequence: sequence,
          recorded_at: recorded_at,
          metadata: metadata
        )
      end

      # Derives a stable, human-readable identity string for a live machine.
      def self.machine_identity_for(machine)
        owner = machine.owner_class
        owner_name = owner.respond_to?(:name) && owner.name ? owner.name : owner.class.name
        "#{owner_name}##{machine.attribute}"
      end

      def initialize(machine_identity:, definition_fingerprint:, event:, from:, to:, sequence: nil,
                     recorded_at: nil, metadata: nil)
        @machine_identity = machine_identity
        @definition_fingerprint = definition_fingerprint
        @event = event.nil? ? nil : event.to_sym
        @from = from.nil? ? nil : from.to_sym
        @to = to.nil? ? nil : to.to_sym
        @sequence = sequence
        @recorded_at = recorded_at
        @metadata = metadata
      end

      # Whether this record declares a sequence number.
      def sequenced?
        !sequence.nil?
      end

      # Whether this record describes a loopback (from and to are equal).
      def loopback?
        from == to
      end

      # A serializable representation of the record.
      def to_h
        {
          machine_identity: machine_identity,
          definition_fingerprint: definition_fingerprint,
          event: event,
          from: from,
          to: to,
          sequence: sequence,
          recorded_at: recorded_at,
          metadata: metadata
        }
      end

      def ==(other)
        other.is_a?(TransitionRecord) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end

      def inspect
        "#<#{self.class} identity=#{machine_identity.inspect} fp=#{definition_fingerprint.inspect} " \
          "seq=#{sequence.inspect} event=#{event.inspect} #{from.inspect}->#{to.inspect}>"
      end
    end
  end
end
