# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  module DataSources
    # Represents a data time zone defined by a list of transitions that change
    # the locally observed time.
    class TransitionsDataTimezoneInfo < DataTimezoneInfo
      # @return [Array<TimezoneTransition>] the transitions that define this
      #   time zone in order of ascending timestamp.
      attr_reader :transitions

      # Initializes a new {TransitionsDataTimezoneInfo}.
      #
      # The passed in `identifier` instance will be frozen. A reference to the
      # passed in `Array` will be retained.
      #
      # The `transitions` `Array` must be sorted in order of ascending
      # timestamp. Each transition must have a
      # {TimezoneTransition#timestamp_value timestamp_value} that is greater
      # than the {TimezoneTransition#timestamp_value timestamp_value} of the
      # prior transition.
      #
      # @param identifier [String] the identifier of the time zone.
      # @param transitions [Array<TimezoneTransitions>] an `Array` of
      #   transitions that each indicate when a change occurs in the locally
      #   observed time.
      # @raise [ArgumentError] if `identifier` is `nil`.
      # @raise [ArgumentError] if `transitions` is `nil`.
      # @raise [ArgumentError] if `transitions` is an empty `Array`.
      def initialize(identifier, transitions)
        super(identifier)
        raise ArgumentError, 'transitions must be specified' unless transitions
        raise ArgumentError, 'transitions must not be an empty Array' if transitions.empty?
        @transitions = transitions.freeze
      end

      # (see DataTimezoneInfo#period_for)
      def period_for(timestamp)
        raise ArgumentError, 'timestamp must be specified' unless timestamp
        raise ArgumentError, 'timestamp must have a specified utc_offset' unless timestamp.utc_offset

        timestamp_value = timestamp.value

        index = find_minimum_transition {|t| t.timestamp_value >= timestamp_value }

        if index
          transition = @transitions[index]

          if transition.timestamp_value == timestamp_value
            # timestamp occurs within the second of the found transition, so is
            # the transition that starts the period.
            start_transition = transition
            end_transition = @transitions[index + 1]
          else
            # timestamp occurs before the second of the found transition, so is
            # the transition that ends the period.
            start_transition = index == 0 ? nil : @transitions[index - 1]
            end_transition = transition
          end
        else
          start_transition = @transitions.last
          end_transition = nil
        end

        TransitionsTimezonePeriod.new(start_transition, end_transition)
      end

      # Returns the {TimezonePeriod TimezonePeriods} observed for a sequence
      # of timestamps in non-decreasing chronological order.
      #
      # Unlike {#period_for}, which performs an independent binary search for
      # each timestamp, `period_for_all` advances a single cursor forwards
      # through {#transitions} as the timestamps are processed. Each
      # transition is examined at most once and no binary searches are
      # performed. Duplicate (identical) timestamps reuse the previously
      # found period without examining any transition.
      #
      # Timestamps must have a specified {Timestamp#utc_offset utc_offset};
      # ordering is determined from the UTC {Timestamp#value value} and
      # {Timestamp#sub_second sub_second}.
      #
      # Processing is lazy when an `Enumerator` is returned (no block given):
      # timestamps are consumed and validated as results are pulled.
      #
      # @param timestamps [Enumerable] an `Enumerable` of {Timestamp}
      #   instances in non-decreasing chronological order.
      # @yield [period] if a block is provided, each {TimezonePeriod} is
      #   yielded to the block, in the same order as the timestamps, before
      #   processing the next timestamp.
      # @yieldparam period [TimezonePeriod] the {TimezonePeriod} observed at
      #   the corresponding timestamp.
      # @return [Enumerator<TimezonePeriod>] if no block is provided, an
      #   `Enumerator` of the {TimezonePeriod TimezonePeriods} observed at
      #   each timestamp.
      # @return [nil] if a block is provided.
      # @raise [ArgumentError] if `timestamps` is `nil`.
      # @raise [ArgumentError] if a timestamp is `nil` or does not have a
      #   specified {Timestamp#utc_offset utc_offset}.
      # @raise [OutOfOrderTimestampError] if a timestamp is earlier than the
      #   preceding timestamp.
      def period_for_all(timestamps)
        raise ArgumentError, 'timestamps must be specified' unless timestamps
        return enum_for(:period_for_all, timestamps) unless block_given?

        # Index of the transition that ends the period most recently emitted
        # (0 for the unbounded period before the first transition). The linear
        # search for each new timestamp resumes at this transition and only
        # moves forwards, so each transition is examined at most once.
        end_index = 0
        # The period most recently emitted and the bounds within which
        # subsequent timestamps reuse it without examining the transitions.
        # end_second is nil for the unbounded final period.
        current_start_transition = nil
        current_end_transition = nil
        end_second = nil
        period_located = false
        previous_value = nil
        previous_sub_second = 0

        timestamps.each_with_index do |timestamp, index|
          raise ArgumentError, 'timestamp must be specified' unless timestamp
          raise ArgumentError, 'timestamp must have a specified utc_offset' unless timestamp.utc_offset

          timestamp_value = timestamp.value
          sub_second = timestamp.sub_second

          if index > 0
            comparison = timestamp_value <=> previous_value
            comparison = sub_second <=> previous_sub_second if comparison == 0
            raise OutOfOrderTimestampError.new(index) if comparison < 0
          end

          within_current_period =
            period_located &&
            (current_end_transition.nil? ||
            timestamp_value < end_second)

          unless within_current_period
            # Linearly advance from the transition ending the current period
            # to the first transition at or after this timestamp. This uses
            # the same transition condition as the binary search in
            # period_for. The cursor only moves forwards and each transition
            # is examined at most once across the whole sequence.
            while end_index < @transitions.length
              transition = @transitions[end_index]
              break unless transition_precedes_timestamp?(transition, timestamp_value, sub_second)
              end_index += 1
            end

            if end_index < @transitions.length
              transition_timestamp_value = transition.timestamp_value

              if transition_timestamp_value == timestamp_value
                # The timestamp falls on the transition second (including a
                # sub-second of that second), so that transition starts the
                # period.
                current_start_transition = transition
                current_end_transition = @transitions[end_index + 1]
                # Advance the cursor past this start transition to the one
                # that ends the new period, so timestamps later in that
                # period (including a duplicate of this exact timestamp) do
                # not examine the start transition again.
                end_index += 1
              else
                # The timestamp is before the transition second, so that
                # transition ends the period.
                current_start_transition = end_index == 0 ? nil : @transitions[end_index - 1]
                current_end_transition = transition
              end

              end_second = current_end_transition ? current_end_transition.timestamp_value : nil
            else
              # No transition at or after the timestamp: final period.
              current_start_transition = @transitions.last
              current_end_transition = nil
              end_second = nil
            end
            period_located = true
          end

          previous_value = timestamp_value
          previous_sub_second = sub_second

          yield TransitionsTimezonePeriod.new(current_start_transition, current_end_transition)
        end

        nil
      end

      # (see DataTimezoneInfo#periods_for_local)
      def periods_for_local(local_timestamp)
        raise ArgumentError, 'local_timestamp must be specified' unless local_timestamp
        raise ArgumentError, 'local_timestamp must have an unspecified utc_offset' if local_timestamp.utc_offset

        local_timestamp_value = local_timestamp.value
        latest_possible_utc_value = local_timestamp_value + 86400
        earliest_possible_utc_value = local_timestamp_value - 86400

        # Find the index of the first transition that occurs after a latest
        # possible UTC representation of the local timestamp and then search
        # backwards until an earliest possible UTC representation.

        index = find_minimum_transition {|t| t.timestamp_value >= latest_possible_utc_value }

        # No transitions after latest_possible_utc_value, set to max index + 1
        # to search backwards including the period after the last transition
        index = @transitions.length unless index

        result = []

        index.downto(0) do |i|
          start_transition = i > 0 ? @transitions[i - 1] : nil
          end_transition = @transitions[i]
          offset = start_transition ? start_transition.offset : end_transition.previous_offset
          utc_timestamp_value = local_timestamp_value - offset.observed_utc_offset

          # It is not necessary to compare the sub-seconds because a timestamp
          # is in the period if is >= the start transition (sub-seconds would
          # make == become >) and if it is < the end transition (which
          # sub-seconds cannot affect).
          if (!start_transition || utc_timestamp_value >= start_transition.timestamp_value) && (!end_transition || utc_timestamp_value < end_transition.timestamp_value)
            result << TransitionsTimezonePeriod.new(start_transition, end_transition)
          elsif end_transition && end_transition.timestamp_value < earliest_possible_utc_value
            break
          end
        end

        result.reverse!
      end

      # (see DataTimezoneInfo#transitions_up_to)
      def transitions_up_to(to_timestamp, from_timestamp = nil)
        raise ArgumentError, 'to_timestamp must be specified' unless to_timestamp
        raise ArgumentError, 'to_timestamp must have a specified utc_offset' unless to_timestamp.utc_offset

        if from_timestamp
          raise ArgumentError, 'from_timestamp must have a specified utc_offset' unless from_timestamp.utc_offset
          raise ArgumentError, 'to_timestamp must be greater than from_timestamp' if to_timestamp <= from_timestamp
        end

        if from_timestamp
          from_index = find_minimum_transition {|t| transition_on_or_after_timestamp?(t, from_timestamp) }
          return [] unless from_index
        else
          from_index = 0
        end

        to_index = find_minimum_transition {|t| transition_on_or_after_timestamp?(t, to_timestamp) }

        if to_index
          return [] if to_index < 1
          to_index -= 1
        else
          to_index = -1
        end

        @transitions[from_index..to_index]
      end

      private

      # Determines if a transition is strictly earlier than a timestamp while
      # advancing the sequential cursor used by {#period_for_all}. This is the
      # negated stop condition of the binary search in {#period_for}.
      #
      # @param transition [TimezoneTransition] the transition to compare.
      # @param timestamp_value [Integer] the whole-second value of the
      #   timestamp.
      # @param sub_second [Numeric] the sub-second of the timestamp.
      # @return [Boolean] `true` if the cursor should advance past
      #   `transition`, otherwise `false`.
      def transition_precedes_timestamp?(transition, timestamp_value, sub_second)
        transition_timestamp_value = transition.timestamp_value
        transition_timestamp_value < timestamp_value ||
          (transition_timestamp_value == timestamp_value && sub_second != 0)
      end

      # Array#bsearch_index was added in Ruby 2.3.0. Use bsearch_index to find
      # transitions if it is available, otherwise use a Ruby implementation.
      if [].respond_to?(:bsearch_index)
        # Performs a binary search on {transitions} to find the index of the
        # earliest transition satisfying a condition.
        #
        # @yield [transition] the caller will be yielded to to test the search
        #   condition.
        # @yieldparam transition [TimezoneTransition] a {TimezoneTransition}
        #   instance from {transitions}.
        # @yieldreturn [Boolean] `true` for the earliest transition that
        #   satisfies the condition and return `true` for all subsequent
        #   transitions. In all other cases, the result of the block must be
        #   `false`.
        # @return [Integer] the index of the earliest transition safisfying
        #   the condition or `nil` if there are no such transitions.
        #
        # :nocov_no_array_bsearch_index:
        def find_minimum_transition(&block)
          @transitions.bsearch_index(&block)
        end
        # :nocov_no_array_bsearch_index:
      else
        # Performs a binary search on {transitions} to find the index of the
        # earliest transition satisfying a condition.
        #
        # @yield [transition] the caller will be yielded to to test the search
        #   condition.
        # @yieldparam transition [TimezoneTransition] a {TimezoneTransition}
        #   instance from {transitions}.
        # @yieldreturn [Boolean] `true` for the earliest transition that
        #   satisfies the condition and return `true` for all subsequent
        #   transitions. In all other cases, the result of the block must be
        #   `false`.
        # @return [Integer] the index of the earliest transition safisfying
        #   the condition or `nil` if there are no such transitions.
        #
        # :nocov_array_bsearch_index:
        def find_minimum_transition
          # A Ruby implementation of the find-minimum mode of Array#bsearch_index.
          low = 0
          high = @transitions.length
          satisfied = false

          while low < high do
            mid = (low + high).div(2)
            if yield @transitions[mid]
              satisfied = true
              high = mid
            else
              low = mid + 1
            end
          end

          satisfied ? low : nil
        end
        # :nocov_array_bsearch_index:
      end

      # Determines if a transition occurs at or after a given {Timestamp},
      # taking the {Timestamp#sub_second sub_second} into consideration.
      #
      # @param transition [TimezoneTransition] the transition to compare.
      # @param timestamp [Timestamp] the timestamp to compare.
      # @return [Boolean] `true` if `transition` occurs at or after `timestamp`,
      #   otherwise `false`.
      def transition_on_or_after_timestamp?(transition, timestamp)
        transition_timestamp_value = transition.timestamp_value
        timestamp_value = timestamp.value
        transition_timestamp_value > timestamp_value || transition_timestamp_value == timestamp_value && timestamp.sub_second == 0
      end
    end
  end
end
