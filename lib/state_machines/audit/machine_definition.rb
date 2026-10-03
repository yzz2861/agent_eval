# frozen_string_literal: true

require 'digest'
require 'json'

module StateMachines
  module Audit
    # An Edge is the static, declared shape of one transition branch: a given
    # event may move along any of the concrete state +pairs+ it contains.
    #
    # +guarded?+ is true when the branch carries +:if+/:unless+ conditions or
    # guards on other machines.  Such an edge is *statically* present in the
    # definition, but whether it actually authorizes a concrete historical
    # transition depends on runtime/external information that a pure replay
    # cannot re-evaluate.
    Edge = Struct.new(:event, :pairs, :guarded, :guard_types, keyword_init: true) do
      def guarded?
        !!guarded
      end

      # Pure structural match: does the declared event/from/to fall on this
      # edge?  Guard satisfaction is deliberately not considered.
      def allows?(event, from, to)
        self.event == event && pairs.include?([from, to])
      end

      def from_states
        pairs.map(&:first).uniq
      end

      def to_states
        pairs.map(&:last).uniq
      end

      def to_h
        { event: event, pairs: pairs, guarded: guarded?, guard_types: guard_types }
      end
    end

    # An immutable snapshot of the parts of a state machine definition that a
    # replay audit needs: its identity, initial state, known states and the
    # declared transition edges.
    #
    # Snapshots are plain data (arrays, symbols, booleans) so they can be
    # serialized alongside audit logs and compared via a fingerprint without
    # loading the original Ruby class.
    class MachineDefinition
      # Stable identity of the machine this snapshot describes.
      attr_reader :identity

      # The initial state name, if one was statically declared.
      attr_reader :initial_state

      # All state names known to the machine.
      attr_reader :states

      # The declared Edge objects.
      attr_reader :edges

      # Caller-provided fingerprint; otherwise derived from content.
      attr_reader :fingerprint

      def self.coerce(definition)
        return definition if definition.is_a?(MachineDefinition)

        from_machine(definition)
      end

      # Builds a snapshot from a live StateMachines::Machine by projecting its
      # events/branches into static Edge objects.  Matcher-based requirements
      # (whitelist / blacklist / all / loopback) are expanded against the
      # machine's known states.
      def self.from_machine(machine, identity: nil, fingerprint: nil)
        state_names = machine.states.map(&:name).freeze

        edges = machine.events.flat_map do |event|
          event.branches.flat_map do |branch|
            branch.state_requirements.map do |requirement|
              Edge.new(
                event: event.name,
                pairs: expand_pairs(requirement[:from], requirement[:to], state_names),
                guarded: dynamic_guard?(branch),
                guard_types: guard_types_for(branch)
              )
            end
          end
        end

        initial = state_names.find { |name| machine.states[name].initial? }

        new(
          identity: identity || TransitionRecord.machine_identity_for(machine),
          initial_state: initial,
          states: state_names,
          edges: edges,
          fingerprint: fingerprint
        )
      end

      # Shortcut for callers that only need a fingerprint of a live machine.
      def self.fingerprint_for(machine)
        from_machine(machine).fingerprint
      end

      def self.expand_matcher(matcher, state_names)
        values = case matcher
                 when LoopbackMatcher, AllMatcher
                   state_names
                 when BlacklistMatcher
                   state_names - matcher.values
                 when WhitelistMatcher
                   matcher.values
                 when Matcher
                   matcher.values
                 else
                   Array(matcher)
                 end
        values.map(&:to_sym).sort.uniq
      end

      # Expands a from/to matcher requirement into concrete [from, to] pairs.
      # A loopback +to+ (+same+) is correlated with its +from+ rather than
      # producing a cartesian product.
      def self.expand_pairs(from_matcher, to_matcher, state_names)
        from_states = expand_matcher(from_matcher, state_names)

        if to_matcher.is_a?(LoopbackMatcher)
          from_states.map { |state| [state, state] }
        else
          to_states = expand_matcher(to_matcher, state_names)
          from_states.product(to_states)
        end.sort.uniq
      end

      # A branch is considered dynamically guarded whenever its authorization
      # depends on information external to the declared event/from/to triple.
      def self.dynamic_guard?(branch)
        !branch.if_condition.nil? ||
          !branch.unless_condition.nil? ||
          !branch.state_guards.empty?
      end

      # Classifies the dynamic conditions attached to a branch so the audit
      # report can state precisely what was not re-evaluated.
      def self.guard_types_for(branch)
        types = []
        types << :if_unless unless branch.if_condition.nil? && branch.unless_condition.nil?
        types << :state_guard unless branch.state_guards.empty?
        types
      end

      def initialize(identity:, states:, edges:, initial_state: nil, fingerprint: nil)
        @identity = identity
        @initial_state = initial_state&.to_sym
        @states = states.map(&:to_sym).sort.uniq
        @edges = edges.map do |edge|
          next edge if edge.is_a?(Edge)

          attributes = edge.is_a?(Hash) ? edge : { pairs: edge }
          Edge.new(event: attributes[:event], pairs: attributes[:pairs],
                   guarded: attributes.fetch(:guarded, false),
                   guard_types: attributes.fetch(:guard_types, []))
        end
        @fingerprint = fingerprint || compute_fingerprint
      end

      # Returns the matching edges for the given event/from/to triple.
      def matching_edges(event, from, to)
        event = event&.to_sym
        edges.select { |edge| edge.allows?(event, from&.to_sym, to&.to_sym) }
      end

      # Pure structural authorization check.
      #
      # Returns:
      # * +:allowed+ - an unguarded declared edge authorizes the triple.
      # * +:allowed_guarded+ - only guarded declared edges match; the structure
      #   is valid but the guard cannot be re-evaluated.
      # * +:unknown_event+ - the event is not defined.
      # * +:unknown_state+ - from/to is not a known state.
      # * +:illegal+ - event/states exist but no declared edge connects them.
      def authorize(event, from, to)
        return :unknown_event unless event_defined?(event)
        return :unknown_state unless known_state?(from) && known_state?(to)

        matches = matching_edges(event, from, to)
        return :illegal if matches.empty?
        return :allowed if matches.any? { |edge| !edge.guarded? }

        :allowed_guarded
      end

      def event_defined?(event)
        edges.any? { |edge| edge.event == event&.to_sym }
      end

      def known_state?(state)
        states.include?(state&.to_sym)
      end

      def to_h
        {
          identity: identity,
          initial_state: initial_state,
          states: states,
          edges: edges.map(&:to_h)
        }
      end

      private

      def compute_fingerprint
        payload = to_h
        payload[:edges].each { |edge| edge[:pairs] = edge[:pairs].sort }
        Digest::SHA256.hexdigest(JSON.generate(payload))[0, 16]
      end
    end
  end
end
