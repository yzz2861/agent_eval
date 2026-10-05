# frozen_string_literal: true
module GraphQL
  class Subscriptions
    # A {Filter} is a predicate over "event attributes" -- a plain Hash of
    # values passed along when an event is triggered. Subscriptions registered
    # with a filter are only executed for events whose attributes satisfy the
    # filter's full predicate.
    #
    # Filters can also be _indexed_: each filter exposes an {#index_plan}, a
    # necessary (but maybe not sufficient) condition for a match, built from
    # attribute equality, set membership, and numeric range constraints.
    # Backends (like {GraphQL::Subscriptions::FilterIndex}) use those plans to
    # narrow the candidate set for an event, then run the full {#matches?}
    # predicate on the remaining candidates. Filters whose conditions are too
    # complex or unknown return nil from {#index_plan} and are conservatively
    # treated as candidates for every event, so indexing never skips a
    # subscription that should have matched.
    #
    # @example Building a filter
    #   filter = GraphQL::Subscriptions::Filter.and(
    #     GraphQL::Subscriptions::Filter.eq(:tenant_id, 1),
    #     GraphQL::Subscriptions::Filter.or(
    #       GraphQL::Subscriptions::Filter.in(:region, ["us", "ca"]),
    #       GraphQL::Subscriptions::Filter.range(:score, 90..100),
    #     )
    #   )
    #
    #   filter.matches?({ tenant_id: 1, region: "us" }) # => true
    class Filter
      class << self
        # @return [Filter::Eq] matches when event_attributes[attribute] == value
        def eq(attribute, value)
          Eq.new(attribute, value)
        end

        # @return [Filter::Inclusion] matches when values includes event_attributes[attribute]
        def in(attribute, values)
          Inclusion.new(attribute, values)
        end

        # @param range [Range] a (possibly beginless or endless) numeric range
        # @return [Filter::RangeCondition] matches when event_attributes[attribute] falls within range
        def range(attribute, range)
          RangeCondition.new(attribute, range)
        end

        # @return [Filter::All] matches when all given filters match
        def and(*filters)
          All.new(filters.flatten)
        end

        # @return [Filter::Any] matches when any given filter matches
        def or(*filters)
          Any.new(filters.flatten)
        end

        # A filter with arbitrary logic. It can't be indexed, so backends
        # conservatively consider it a candidate for every event and rely on
        # the block alone.
        # @yieldparam event_attributes [Hash]
        # @yieldreturn [Boolean]
        def custom(&block)
          Custom.new(block)
        end
      end

      # The full predicate for this filter.
      # @param event_attributes [Hash] attributes passed along with the triggered event
      # @return [Boolean]
      def matches?(event_attributes)
        raise GraphQL::RequiredImplementationMissingError
      end

      # A necessary condition for {#matches?}, expressed with indexable
      # constraints, or nil when no useful condition can be derived.
      #
      # Invariant: if matches?(event_attributes) is true, then the plan is
      # nil (unknown) or satisfied by event_attributes. Backends rely on
      # this to avoid missing subscriptions.
      #
      # @return [IndexPlan, nil]
      def index_plan
        nil
      end

      # @return [Filter::All] this filter ANDed with other
      def &(other)
        All.new([self, other])
      end

      # @return [Filter::Any] this filter ORed with other
      def |(other)
        Any.new([self, other])
      end

      # An indexable view of a {Filter}: a tree of constraints which is
      # satisfied whenever the filter's full predicate is satisfied.
      class IndexPlan
        # Yield each leaf constraint so a subscription can be registered
        # under (and later removed from) the corresponding index entries.
        def each_leaf
          raise GraphQL::RequiredImplementationMissingError
        end

        # @param subscription_id [Object]
        # @param leaf_hits [Hash{Array => Array}] leaf key => subscription ids
        #   whose indexed constraint matched the current event
        # @return [Boolean] whether subscription_id may match the current event
        def satisfied_by?(subscription_id, leaf_hits)
          raise GraphQL::RequiredImplementationMissingError
        end

        # event_attributes[attribute] == value
        class EqLeaf < IndexPlan
          attr_reader :attribute, :value, :key

          def initialize(attribute, value)
            @attribute = attribute
            @value = value
            @key = [:eq, attribute, value].freeze
          end

          def each_leaf
            yield self
          end

          def satisfied_by?(subscription_id, leaf_hits)
            if (ids = leaf_hits[@key])
              ids.include?(subscription_id)
            else
              false
            end
          end
        end

        # minimum <= event_attributes[attribute] <= maximum (honoring exclude_end)
        class RangeLeaf < IndexPlan
          attr_reader :attribute, :minimum, :maximum, :exclude_end, :key

          def initialize(attribute, minimum, maximum, exclude_end)
            @attribute = attribute
            @minimum = minimum
            @maximum = maximum
            @exclude_end = exclude_end
            @key = [:range, attribute, minimum, maximum, exclude_end].freeze
          end

          # Shared by the index and the full predicate so they always agree.
          # @return [Boolean] whether value falls within this range
          def include_value?(value)
            return false if value.nil?
            return false if !@minimum.nil? && value < @minimum
            return false if !@maximum.nil? && (@exclude_end ? value >= @maximum : value > @maximum)
            true
          rescue ArgumentError, TypeError
            false
          end

          def each_leaf
            yield self
          end

          def satisfied_by?(subscription_id, leaf_hits)
            if (ids = leaf_hits[@key])
              ids.include?(subscription_id)
            else
              false
            end
          end
        end

        # Satisfied when all child plans are satisfied.
        class All < IndexPlan
          def initialize(plans)
            @plans = plans
          end

          def each_leaf(&block)
            @plans.each { |plan| plan.each_leaf(&block) }
          end

          def satisfied_by?(subscription_id, leaf_hits)
            @plans.all? { |plan| plan.satisfied_by?(subscription_id, leaf_hits) }
          end
        end

        # Satisfied when any child plan is satisfied.
        class Any < IndexPlan
          def initialize(plans)
            @plans = plans
          end

          def each_leaf(&block)
            @plans.each { |plan| plan.each_leaf(&block) }
          end

          def satisfied_by?(subscription_id, leaf_hits)
            @plans.any? { |plan| plan.satisfied_by?(subscription_id, leaf_hits) }
          end
        end
      end

      class Eq < Filter
        def initialize(attribute, value)
          @attribute = attribute
          @value = value
          @leaf = IndexPlan::EqLeaf.new(attribute, value)
        end

        def matches?(event_attributes)
          event_attributes[@attribute] == @value
        end

        def index_plan
          @leaf
        end
      end

      class Inclusion < Filter
        def initialize(attribute, values)
          @attribute = attribute
          @values = values.to_a.uniq
          @plan = IndexPlan::Any.new(@values.map { |value| IndexPlan::EqLeaf.new(attribute, value) })
        end

        def matches?(event_attributes)
          @values.include?(event_attributes[@attribute])
        end

        def index_plan
          @plan
        end
      end

      class RangeCondition < Filter
        def initialize(attribute, range)
          @attribute = attribute
          @leaf = IndexPlan::RangeLeaf.new(attribute, range.begin, range.end, range.exclude_end?)
        end

        def matches?(event_attributes)
          @leaf.include_value?(event_attributes[@attribute])
        end

        def index_plan
          @leaf
        end
      end

      class All < Filter
        def initialize(filters)
          @filters = filters
          plans = filters.map { |filter| filter.respond_to?(:index_plan) ? filter.index_plan : nil }.compact
          @plan = if plans.empty?
            nil
          elsif plans.size == 1
            plans.first
          else
            IndexPlan::All.new(plans)
          end
        end

        def matches?(event_attributes)
          @filters.all? { |filter| filter.matches?(event_attributes) }
        end

        def index_plan
          @plan
        end
      end

      class Any < Filter
        def initialize(filters)
          @filters = filters
          plans = filters.map { |filter| filter.respond_to?(:index_plan) ? filter.index_plan : nil }
          # If any branch can't be indexed, the whole OR is a candidate for
          # every event; narrowing here could miss matches from that branch.
          @plan = plans.any?(&:nil?) ? nil : IndexPlan::Any.new(plans)
        end

        def matches?(event_attributes)
          @filters.any? { |filter| filter.matches?(event_attributes) }
        end

        def index_plan
          @plan
        end
      end

      class Custom < Filter
        def initialize(callable)
          @callable = callable
        end

        def matches?(event_attributes)
          @callable.call(event_attributes)
        end

        # index_plan stays nil: the logic is opaque, so this filter is a
        # conservative candidate for every event.
      end
    end
  end
end
