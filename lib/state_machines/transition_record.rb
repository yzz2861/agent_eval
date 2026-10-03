# frozen_string_literal: true

require 'digest'

module StateMachines
  # A structured, serializable record of a single state transition, suitable
  # for audit logs that need to be replayed and verified later.
  #
  # Each record captures:
  # * +machine+ - the identity of the machine that produced the transition
  #   (owner class, machine name, and attribute)
  # * +definition+ - a fingerprint of the machine definition the transition
  #   was recorded against, so records are never validated silently against
  #   a different definition
  # * +event+ - the event that fired the transition
  # * +from+ / +to+ - the states before and after the transition
  # * +sequence+ - a monotonically increasing number ordering the records
  #
  # Records are plain data: they can be serialized with #to_h and rebuilt
  # with .from_h, and a chain of records can be validated with
  # StateMachines::TransitionChainValidator.
  #
  # == Examples
  #
  #   transition = StateMachines::Transition.new(vehicle, machine, :ignite, :parked, :idling)
  #   record = StateMachines::TransitionRecord.capture(machine, transition, 1)
  #   record.to_h
  #   # => {:machine=>"Vehicle#state(state)", :definition=>"9f2c...", :event=>:ignite, :from=>:parked, :to=>:idling, :sequence=>1}
  class TransitionRecord
    # The fields that make up a record, in canonical order
    FIELDS = %i[machine definition event from to sequence].freeze

    # The identity of the machine that produced the transition
    attr_reader :machine

    # The fingerprint of the machine definition this record was captured against
    attr_reader :definition

    # The event that fired the transition
    attr_reader :event

    # The state before the transition
    attr_reader :from

    # The state after the transition
    attr_reader :to

    # The position of this record within the audited chain
    attr_reader :sequence

    def initialize(machine:, definition:, event:, from:, to:, sequence:)
      @machine = machine
      @definition = definition
      @event = event
      @from = from
      @to = to
      @sequence = sequence
    end

    # Builds a record for the given transition, stamped with the identity and
    # definition fingerprint of the given machine.  States are recorded by
    # name (not stored value) so records line up with machine definitions.
    def self.capture(machine, transition, sequence)
      new(
        machine: machine_identity(machine),
        definition: definition_fingerprint(machine),
        event: transition.event,
        from: transition.from_name,
        to: transition.to_name,
        sequence: sequence
      )
    end

    # The identity of a machine, combining its owner class, machine name, and
    # the attribute it tracks.  Two machines share an identity only if all
    # three match.
    def self.machine_identity(machine)
      owner = machine.owner_class.name || machine.owner_class.to_s
      "#{owner}##{machine.name}(#{machine.attribute})"
    end

    # A stable fingerprint of the machine's definition: its identity, states,
    # events, and each event's branches (from/to requirements and the kinds
    # of guards configured).  Guard *implementations* (proc bodies) are not
    # fingerprinted -- only their presence and kind.
    def self.definition_fingerprint(machine)
      parts = [machine_identity(machine)]
      parts << "states:#{machine.states.map { |state| state.name.to_s }.sort.join(',')}"
      machine.events.map(&:name).sort.each do |event_name|
        machine.events[event_name].branches.each do |branch|
          parts << "event:#{event_name}|#{fingerprint_branch(branch)}"
        end
      end
      Digest::SHA256.hexdigest(parts.join("\n"))[0, 16]
    end

    # Rebuilds a record from a plain hash (such as parsed JSON).  Keys are
    # symbolized and string event/from/to values are converted to symbols so
    # they line up with machine definitions.  Raises ArgumentError if keys
    # are missing or unknown.
    def self.from_h(hash)
      attributes = hash.each_with_object({}) { |(key, value), memo| memo[key.to_sym] = value }

      unknown = attributes.keys - FIELDS
      raise ArgumentError, "Unknown keys: #{unknown.map(&:inspect).join(', ')}" unless unknown.empty?

      missing = FIELDS - attributes.keys
      raise ArgumentError, "Missing keys: #{missing.map(&:inspect).join(', ')}" unless missing.empty?

      %i[event from to].each do |field|
        attributes[field] = attributes[field].to_sym if attributes[field].is_a?(String)
      end

      new(**attributes)
    end

    # A plain-hash representation of this record, suitable for serialization
    def to_h
      {
        machine: machine,
        definition: definition,
        event: event,
        from: from,
        to: to,
        sequence: sequence
      }
    end

    def ==(other)
      other.is_a?(TransitionRecord) && other.to_h == to_h
    end
    alias eql? ==

    def hash
      to_h.hash
    end

    def inspect
      "#<#{self.class.name} #{to_h.map { |key, value| "#{key}=#{value.inspect}" }.join(' ')}>"
    end

    # Fingerprint fragment for a single branch: its from/to requirements and
    # the kinds of guards it carries
    def self.fingerprint_branch(branch)
      requirements = branch.state_requirements.map do |requirement|
        %i[from to].map { |option| "#{option}=#{fingerprint_matcher(requirement[option])}" }.join(',')
      end
      guards = []
      guards << 'if' if branch.if_condition
      guards << 'unless' if branch.unless_condition
      guards.concat(branch.state_guards.keys.map(&:to_s))
      "req[#{requirements.join(';')}]guards[#{guards.sort.join(',')}]"
    end
    private_class_method :fingerprint_branch

    # Fingerprint fragment for a matcher: its class and configured values
    def self.fingerprint_matcher(matcher)
      "#{matcher.class.name}(#{matcher.values.map(&:inspect).join(',')})"
    end
    private_class_method :fingerprint_matcher
  end
end
