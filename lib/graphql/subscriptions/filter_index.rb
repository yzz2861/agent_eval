# frozen_string_literal: true
module GraphQL
  class Subscriptions
    # An in-memory index of subscription filters for a single event topic.
    #
    # Subscriptions are registered with a {Filter} (or nothing, to receive
    # every event). Indexable parts of each filter (attribute equality, set
    # membership, numeric ranges, and AND/OR combinations of them) are used
    # to narrow the candidate set for a triggered event; the filter's full
    # predicate is always evaluated before a subscription is considered
    # matching, so the index never changes which subscriptions match -- it
    # only avoids work for subscriptions that can't match.
    #
    # Filters with complex or unknown conditions (for example
    # {Filter::Custom}) are kept in a conservative fallback set and are
    # candidates for every event.
    class FilterIndex
      def initialize
        # { attribute => { value => [subscription_id, ...] } }
        @eq_index = {}
        # { attribute => [[Filter::IndexPlan::RangeLeaf, subscription_id], ...] }
        @range_index = {}
        # Subscriptions with no indexable constraints (or no filter at all):
        @fallback_ids = []
        # { subscription_id => Filter::IndexPlan, nil }
        @plans = {}
        # { subscription_id => Filter-like, nil }
        @filters = {}
      end

      def size
        @filters.size
      end

      def empty?
        @filters.empty?
      end

      # Register `subscription_id`, optionally narrowed by `filter`.
      # @param filter [#matches?, nil] a {Filter} or any object responding to `matches?`
      # @return [void]
      def add(subscription_id, filter)
        remove(subscription_id) if @filters.key?(subscription_id)
        @filters[subscription_id] = filter
        plan = filter && filter.respond_to?(:index_plan) ? filter.index_plan : nil
        leaves = plan ? indexable_leaves(plan) : nil
        if leaves.nil?
          # Not indexable (or an unknown condition): conservative fallback.
          plan = nil
          @fallback_ids << subscription_id
        else
          leaves.each do |leaf|
            case leaf
            when Filter::IndexPlan::EqLeaf
              by_value = (@eq_index[leaf.attribute] ||= {})
              (by_value[leaf.value] ||= []) << subscription_id
            when Filter::IndexPlan::RangeLeaf
              (@range_index[leaf.attribute] ||= []) << [leaf, subscription_id]
            end
          end
        end
        @plans[subscription_id] = plan
        nil
      end

      # Remove `subscription_id` and all of its index entries.
      # @return [Boolean] whether the subscription was registered here
      def remove(subscription_id)
        return false if !@filters.key?(subscription_id)
        @filters.delete(subscription_id)
        plan = @plans.delete(subscription_id)
        if plan.nil?
          @fallback_ids.delete(subscription_id)
        else
          # `plan` is only stored when it was fully indexable, but guard
          # anyway so a hand-rolled plan can't break cleanup:
          (indexable_leaves(plan) || []).each do |leaf|
            case leaf
            when Filter::IndexPlan::EqLeaf
              by_value = @eq_index[leaf.attribute]
              ids = by_value[leaf.value]
              ids.delete(subscription_id)
              if ids.empty?
                by_value.delete(leaf.value)
                @eq_index.delete(leaf.attribute) if by_value.empty?
              end
            when Filter::IndexPlan::RangeLeaf
              entries = @range_index[leaf.attribute]
              entries.delete_if { |(_leaf, id)| id == subscription_id }
              @range_index.delete(leaf.attribute) if entries.empty?
            end
          end
        end
        true
      end

      # All registered subscription ids whose filter matches
      # `event_attributes`. The index narrows the candidate set first, then
      # each candidate's full predicate is evaluated, so the result is exactly
      # the set of subscriptions whose filter matches -- no more, no less.
      #
      # @param event_attributes [Hash] attributes passed along with the event
      # @return [Array] matching subscription ids
      def matching_subscription_ids(event_attributes)
        leaf_hits = {}
        @eq_index.each do |attribute, by_value|
          value = event_attributes[attribute]
          if (ids = by_value[value]) && !ids.empty?
            leaf_hits[[:eq, attribute, value]] = ids
          end
        end
        @range_index.each do |attribute, entries|
          value = event_attributes[attribute]
          next if value.nil?
          entries.each do |(leaf, subscription_id)|
            if leaf.include_value?(value)
              (leaf_hits[leaf.key] ||= []) << subscription_id
            end
          end
        end

        matching = []
        examined = {}
        @fallback_ids.each do |subscription_id|
          examined[subscription_id] = true
          filter = @filters[subscription_id]
          if filter.nil? || filter.matches?(event_attributes)
            matching << subscription_id
          end
        end
        leaf_hits.each_value do |ids|
          ids.each do |subscription_id|
            next if examined[subscription_id]
            examined[subscription_id] = true
            plan = @plans[subscription_id]
            if plan.nil?
              # Present in a hit set but not index-planned; shouldn't happen,
              # but be conservative rather than risk skipping a match.
              filter = @filters[subscription_id]
              matching << subscription_id if filter.nil? || filter.matches?(event_attributes)
              next
            end
            next if !plan.satisfied_by?(subscription_id, leaf_hits)
            filter = @filters[subscription_id]
            next if filter && !filter.matches?(event_attributes)
            matching << subscription_id
          end
        end
        matching
      end

      private

      # @return [Array<Filter::IndexPlan>, nil] deduplicated known leaf
      #   constraints, or nil if the plan contains anything we can't index
      def indexable_leaves(plan)
        leaves = []
        seen = {}
        plan.each_leaf do |leaf|
          case leaf
          when Filter::IndexPlan::EqLeaf, Filter::IndexPlan::RangeLeaf
            if !seen[leaf.key]
              seen[leaf.key] = true
              leaves << leaf
            end
          else
            # Unknown constraint type: don't risk a partial index.
            return nil
          end
        end
        leaves
      end
    end
  end
end
