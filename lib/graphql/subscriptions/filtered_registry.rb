# frozen_string_literal: true
module GraphQL
  class Subscriptions
    # An in-memory registry of subscriptions keyed by event name, backed by
    # per-attribute indexes that narrow the set of candidates before the full
    # filter predicate is evaluated.
    #
    # Indexability vs correctness:
    # - The *indexable* portion of a filter produces a superset of the true
    #   matches (an over-approximation), so the index only ever removes
    #   subscriptions that can be proven irrelevant.
    # - Every surviving candidate is checked with the *full* predicate
    #   ({Filter::Node#match?}), so optimization never changes the result.
    # - Filters (or branches) the index can't reason about are placed in a
    #   conservative fallback set which is always included as candidates.
    #
    # Registering ({#register}), replacing ({#update}) and cancelling
    # ({#unregister}) keep the indexes in sync synchronously.
    class FilteredRegistry
      # One registered subscription.
      Entry = Struct.new(:id, :event, :filter, :data, keyword_init: true)

      def initialize
        @mutex = Mutex.new
        # event => Shard
        @shards = {}
        # subscription id => [Entry, ...]
        @entries = Hash.new { |hash, key| hash[key] = [] }
      end

      # Register a subscription and add it to the relevant indexes.
      # @param subscription_id [String]
      # @param event [String, Symbol] the subscription/event (e.g. root field) name
      # @param filter [Filter::Node, Hash, #call, nil] explicit filter condition
      # @param data [Object] arbitrary payload returned for matches
      # @return [Entry]
      def register(subscription_id, event, filter = nil, data: nil, &resolver)
        filter = Filter.build(filter)
        entry = Entry.new(id: subscription_id, event: event.to_s, filter: filter, data: data || resolver)
        synchronize do
          @entries[subscription_id] << entry
          shard_for(entry.event).add(entry)
        end
        entry
      end

      # Replace the filter for an existing registration, updating the indexes
      # atomically. Returns the updated entry, or +nil+ if it isn't registered.
      # @param subscription_id [String]
      # @param filter [Filter::Node, Hash, #call, nil]
      # @return [Entry, nil]
      def update(subscription_id, filter)
        filter = Filter.build(filter)
        synchronize do
          old_entries = @entries[subscription_id]
          return nil if old_entries.empty?
          @entries[subscription_id] = old_entries.map do |entry|
            shard_for(entry.event).remove(entry)
            updated = entry.dup
            updated.filter = filter
            shard_for(updated.event).add(updated)
            updated
          end
        end
      end

      # Cancel a subscription and remove all of its index entries.
      # @param subscription_id [String]
      # @return [void]
      def unregister(subscription_id)
        synchronize do
          entries = @entries.delete(subscription_id)
          return if entries.nil?
          events = {}
          entries.each do |entry|
            shard_for(entry.event).remove(entry)
            events[entry.event] = true
          end
          events.each_key { |event_name| prune_shard(event_name) }
        end
        nil
      end

      # Use the index to narrow the candidates for +event+ to those in the
      # relevant tenants/intervals, then evaluate the full predicate on each.
      # @param event [String, Symbol]
      # @param attributes [Hash] triggered event attributes
      # @yield [Entry] invoked once for every confirmed match; runs outside the lock
      # @return [Array<Entry>] the confirmed matches
      def matching(event, attributes)
        shard = synchronize { @shards[event.to_s] }
        return [] if shard.nil?
        candidates = shard.candidates(attributes)
        matches = candidates.select { |entry| entry.filter.match?(attributes) }
        if block_given?
          matches.each { |entry| yield entry }
        end
        matches
      end

      # @return [Integer] number of registered subscriptions (ids)
      def size
        synchronize { @entries.size }
      end

      # @return [Array<String>] registered subscription ids
      def subscription_ids
        synchronize { @entries.keys.dup }
      end

      # @return [Array<Entry>] all registrations for one subscription id
      def entries_for(subscription_id)
        synchronize { @entries[subscription_id].dup }
      end

      # @return [Array<Object>] candidate entries the index selected (before the
      #   full predicate runs). Useful to prove that irrelevant subscriptions
      #   were never evaluated.
      def candidates_for(event, attributes)
        shard = synchronize { @shards[event.to_s] }
        shard.nil? ? [] : shard.candidates(attributes)
      end

      private

      def synchronize(&block)
        @mutex.synchronize(&block)
      end

      def shard_for(event)
        @shards[event] ||= Shard.new
      end

      def prune_shard(event)
        shard = @shards[event]
        @shards.delete(event) if shard && shard.empty?
      end

      # Holds the subscriptions and inverted indexes for one event name.
      #
      # A filter contributes indexable terms from its conjunction (AND) of
      # equality, membership and numeric-range conditions. Terms live in
      # posting lists. On trigger, only posting lists the event hits are read;
      # a subscription whose distinct terms are all covered is a candidate.
      # Filters containing a disjunction (OR) or an unknown condition are put
      # in a conservative fallback set and always checked with the full
      # predicate, so a matching subscription is never missed.
      class Shard
        # A single set-membership posting shared by every value in the set, so
        # that a membership condition counts as exactly one required term.
        class MembershipTerm
          attr_reader :field, :values

          def initialize(field, values)
            @field = field
            @values = values
            @hash = [self.class, field, values].hash
          end

          def fired?(read_value)
            @values.include?(read_value)
          end

          def ==(other)
            other.is_a?(self.class) && other.field == @field && other.values == @values
          end
          alias_method :eql?, :==

          def hash
            @hash
          end
        end

        # Other terms are arrays (Hash keys, content identity):
        # - equality: [:eq, field, value]
        # - range:    [:cmp, field, op, bound]

        def initialize
          # subscription_id => Entry
          @entries = {}
          # subscription_id => Set of distinct indexable terms required
          @required_terms = {}
          # Subscriptions an index can't narrow safely; always candidates.
          @fallback = Set.new
          # term => Set<subscription_id>
          @postings = Hash.new { |hash, term| hash[term] = Set.new }
        end

        def empty?
          @entries.empty?
        end

        def add(entry)
          @entries[entry.id] = entry
          terms = required_terms_for(entry.filter.index_expr)
          if terms.nil?
            @fallback.add(entry.id)
            @required_terms.delete(entry.id)
          else
            @fallback.delete(entry.id)
            @required_terms[entry.id] = terms
            terms.each { |term| @postings[term].add(entry.id) }
          end
        end

        def remove(entry)
          @entries.delete(entry.id)
          @fallback.delete(entry.id)
          terms = @required_terms.delete(entry.id)
          return if terms.nil?
          terms.each do |term|
            ids = @postings[term]
            ids.delete(entry.id)
            @postings.delete(term) if ids.empty?
          end
        end

        # Build the candidate superset using only posting lists the event hits,
        # union the fallback set, and leave exact matching to the caller.
        def candidates(attributes)
          hits = Hash.new { |hash, key| hash[key] = Set.new }
          fired_terms(attributes).each do |term|
            hits[term].merge(@postings[term])
          end

          ids = @fallback.dup
          @required_terms.each do |subscription_id, terms|
            covered = terms.all? { |term| hits[term].include?(subscription_id) }
            ids.add(subscription_id) if covered
          end

          ids.map { |subscription_id| @entries[subscription_id] }.compact
        end

        private

        # @return [Set, nil] required terms, or nil for OR/unknown fallback.
        def required_terms_for(expr)
          return nil if expr == :unknown
          terms = collect_terms(expr)
          terms.nil? ? nil : terms.to_set
        end

        # @return [Array, nil]
        def collect_terms(expr)
          case expr[:t]
          when :eq
            [[:eq, expr[:f], expr[:v]]]
          when :in
            [MembershipTerm.new(expr[:f], expr[:vs])]
          when :cmp
            [[:cmp, expr[:f], expr[:op], expr[:b]]]
          when :and
            collected = expr[:c].map { |child| collect_terms(child) }
            return nil if collected.any?(&:nil?)
            collected.flatten(1)
          else
            nil
          end
        end

        # Distinct terms satisfied by the event. Walking posting-list keys
        # (rather than every subscription) is what narrows the work.
        def fired_terms(attributes)
          result = []
          numeric_fields = {}

          if attributes.is_a?(Hash)
            attributes.each do |key, value|
              if value.is_a?(Numeric)
                numeric_fields[key.to_s] = value
                numeric_fields[key] = value
              end
            end
          end

          @postings.each_key do |term|
            if term.is_a?(MembershipTerm)
              result << term if present?(attributes, term.field) && term.fired?(read(attributes, term.field))
            else
              case term[0]
              when :eq
                field = term[1]
                result << term if present?(attributes, field) && read(attributes, field) == term[2]
              when :cmp
                field = term[1]
                value = numeric_fields[field]
                result << term if !value.nil? && compare?(value, term[2], term[3])
              end
            end
          end

          result
        end

        def present?(attributes, field)
          if attributes.is_a?(Hash)
            attributes.key?(field) || attributes.key?(field.to_sym)
          else
            true
          end
        end

        def read(attributes, field)
          if attributes.is_a?(Hash) && !attributes.key?(field) && attributes.key?(field.to_sym)
            attributes[field.to_sym]
          else
            attributes[field]
          end
        end

        def compare?(value, op, bound)
          comparison = begin
            value <=> bound
          rescue ArgumentError
            nil
          end
          return false if comparison.nil?
          case op
          when :gt then comparison > 0
          when :gte then comparison >= 0
          when :lt then comparison < 0
          when :lte then comparison <= 0
          else
            false
          end
        end
      end
    end
  end
end
