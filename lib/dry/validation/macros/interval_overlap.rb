# frozen_string_literal: true

module Dry
  module Validation
    module Macros
      # Checks whether intervals overlap within groups
      #
      # @api private
      class IntervalOverlap
        Entry = ::Data.define(:index, :group, :start, :end, :start_inclusive, :end_inclusive)

        ENDPOINT_MODES = {
          closed: [true, true],
          open: [false, false],
          left_open: [false, true],
          right_open: [true, false]
        }.freeze

        def initialize(root:, records:, result:, **options)
          @root = root
          @records = records
          @result = result
          @group_key = fetch_option(options, :group_by)
          @start_key = fetch_option(options, :start_field)
          @end_key = fetch_option(options, :end_field)
          @start_inclusive, @end_inclusive = endpoint_options(options)
          @message = options.fetch(:message, :interval_overlap)
        end

        def call
          valid_entries
            .group_by(&:group)
            .each_value do |entries|
              conflict = find_conflict(entries)
              return conflict if conflict
            end

          nil
        end

        def message
          @message
        end

        private

        def fetch_option(options, name)
          options.fetch(name) do
            raise ::ArgumentError, ":#{name} is required"
          end
        end

        def endpoint_options(options)
          if options.key?(:endpoints)
            ENDPOINT_MODES.fetch(options[:endpoints]) do
              raise ::ArgumentError, "unknown endpoint mode #{options[:endpoints].inspect}"
            end
          else
            [
              inclusive_option(options, :start_inclusive, :start_open, true),
              inclusive_option(options, :end_inclusive, :end_open, false)
            ]
          end
        end

        def inclusive_option(options, inclusive_key, open_key, default)
          return !options.fetch(open_key) if options.key?(open_key)

          options.fetch(inclusive_key, default)
        end

        def valid_entries
          @records.filter_map.with_index do |record, index|
            next unless record.is_a?(::Hash)
            next unless valid_record?(record, index)

            group = record.fetch(@group_key)
            start = record.fetch(@start_key)
            endpoint = record.fetch(@end_key)

            next if empty_interval?(start, endpoint)

            Entry.new(index, group, start, endpoint, @start_inclusive, @end_inclusive)
          end
        end

        def valid_record?(record, index)
          [@group_key, @start_key, @end_key].all? do |field|
            path = [*@root, index, field]
            record.key?(field) && !@result.schema_error?(path)
          end
        end

        def empty_interval?(start, endpoint)
          endpoint < start || (endpoint == start && (!@start_inclusive || !@end_inclusive))
        end

        def find_conflict(entries)
          ordered = entries.sort_by { |entry| [entry.start, entry.index] }
          active = nil
          index = 0

          while index < ordered.length
            start = ordered[index].start
            batch_end = index
            closed_entries = []
            positive_entries = []
            farthest = nil
            conflict = nil

            while batch_end < ordered.length && ordered[batch_end].start == start
              entry = ordered[batch_end]
              batch_end += 1
              closed_entries << entry if entry.start_inclusive
              positive_entries << entry if entry.end > entry.start
              farthest = farther_entry(farthest, entry)

              if entry.start_inclusive && closed_entries.length == 2
                conflict = closed_entries.first(2)
                break
              elsif entry.end > entry.start && positive_entries.length == 2
                conflict = positive_entries.first(2)
                break
              end
            end

            return conflict if conflict

            if active
              (index...batch_end).each do |entry_index|
                entry = ordered[entry_index]
                return [active, entry] if overlaps_boundary?(active, entry)
              end
            end

            active = active.nil? ? farthest : farther_entry(active, farthest)

            index = batch_end
          end

          nil
        end

        def farther_entry(first, second)
          return second if first.nil?
          return first if second.nil?

          farther_end?(second, first) ? second : first
        end

        def overlaps_boundary?(previous, entry)
          previous.end > entry.start ||
            (previous.end == entry.start && previous.end_inclusive && entry.start_inclusive)
        end

        def farther_end?(entry, previous)
          entry.end > previous.end ||
            (entry.end == previous.end && entry.end_inclusive && !previous.end_inclusive)
        end
      end
    end
  end
end
