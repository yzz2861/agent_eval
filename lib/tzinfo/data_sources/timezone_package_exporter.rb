# encoding: UTF-8
# frozen_string_literal: true

require_relative 'timezone_package'

module TZInfo
  module DataSources
    # Exports a limited, self-contained time zone package covering a specific
    # query window.
    #
    # The exported package is plain JSON-compatible data. It contains:
    #
    # * each requested time zone and any alias (link) relationships needed to
    #   resolve it, including multi-level links;
    # * the offsets observed during the query window;
    # * every transition needed to determine the period at either end of the
    #   window and all periods in between, including the first transition after
    #   the window (which bounds the final period);
    # * the inclusive coverage window itself.
    #
    # Importing the package never extrapolates the final offset beyond that
    # transition. Queries outside the window fail explicitly.
    class TimezonePackageExporter
      # @return [DataSource] the source used to resolve time zones during
      #   export. Defaults to the currently selected {DataSource}.
      attr_reader :data_source

      # Initializes a new {TimezonePackageExporter}.
      #
      # @param data_source [DataSource] an optional source to export from.
      def initialize(data_source = nil)
        @data_source = data_source || DataSource.get
      end

      # Exports the requested time zones for a query window.
      #
      # The window endpoints are given as UTC times and are inclusive. Any
      # object accepted by {Timezone#period_for} may be passed (e.g. a `Time`
      # with a UTC offset, a `DateTime` or a {Timestamp}).
      #
      # @param identifiers [Array<String>] the time zone identifiers to export.
      #   Alias (linked) time zones may be requested; their link target and any
      #   intermediate links are included automatically.
      # @param from [Object] the inclusive UTC start of the query window.
      # @param to [Object] the inclusive UTC end of the query window.
      # @return [Hash] a JSON-compatible package data structure. Use
      #   {TimezonePackageFormat.dump} to serialize it.
      # @raise [InvalidTimezonePackageExport] if the identifiers or window are
      #   invalid.
      def export(identifiers, from, to)
        requested = validate_identifiers(identifiers)
        from_value = timestamp_value(from, 'from')
        to_value = timestamp_value(to, 'to')
        raise InvalidTimezonePackageExport, 'to must be greater than or equal to from' unless to_value >= from_value

        data_zones = {}
        linked_zones = {}

        requested.each do |identifier|
          export_zone(identifier, data_zones, linked_zones, from_value, to_value)
        end

        {
          'format' => TimezonePackageFormat::FORMAT_NAME,
          'version' => TimezonePackageFormat::FORMAT_VERSION,
          'window' => {
            'from' => from_value,
            'to' => to_value
          },
          'data_timezones' => data_zones.values.map {|zone| zone[:data] }.sort_by {|zone| zone['identifier'] },
          'linked_timezones' => linked_zones.values.map {|zone| zone[:data] }.sort_by {|zone| zone['identifier'] }
        }
      end

      # Exports the requested time zones and returns the result as a JSON
      # string.
      #
      # @param identifiers [Array<String>] the time zone identifiers to export.
      # @param from [Object] the inclusive UTC start of the query window.
      # @param to [Object] the inclusive UTC end of the query window.
      # @return [String] the package serialized as JSON.
      def export_to_json(identifiers, from, to)
        TimezonePackageFormat.dump(export(identifiers, from, to))
      end

      private

      # Validates the requested identifier list.
      #
      # @param identifiers [Object] the requested identifiers.
      # @return [Array<String>] a frozen, de-duplicated copy of the requested
      #   identifiers.
      def validate_identifiers(identifiers)
        raise InvalidTimezonePackageExport, 'identifiers must be specified' unless identifiers
        list = identifiers.to_a
        raise InvalidTimezonePackageExport, 'at least one identifier must be specified' if list.empty?

        list.each do |identifier|
          raise InvalidTimezonePackageExport, "invalid identifier: #{identifier.nil? ? 'nil' : identifier}" unless identifier.kind_of?(String) && !identifier.empty?
        end

        list.uniq.freeze
      end

      # Converts a window endpoint to an integer number of seconds since
      # 1970-01-01 UTC.
      #
      # @param time [Object] the endpoint.
      # @param name [String] the endpoint name used in error messages.
      # @return [Integer] the endpoint as a number of seconds since the epoch.
      def timestamp_value(time, name)
        raise InvalidTimezonePackageExport, "#{name} must be specified" unless time
        timestamp = Timestamp.for(time)
        raise InvalidTimezonePackageExport, "#{name} must have a specified utc_offset" unless timestamp.utc_offset
        value = timestamp.value
        raise InvalidTimezonePackageExport, "#{name} must be a whole number of seconds" unless timestamp.sub_second == 0
        value
      end

      # Exports a single zone, following link chains to their canonical data
      # zone. Already visited zones are reused.
      #
      # @param identifier [String] the zone to export.
      # @param data_zones [Hash] already exported data zones.
      # @param linked_zones [Hash] already exported linked zones.
      # @param from_value [Integer] the window start.
      # @param to_value [Integer] the window end.
      def export_zone(identifier, data_zones, linked_zones, from_value, to_value)
        return if data_zones.has_key?(identifier) || linked_zones.has_key?(identifier)

        info = @data_source.get_timezone_info(identifier)

        if info.kind_of?(LinkedTimezoneInfo)
          target = info.link_to_identifier
          linked_zones[identifier] = {
            data: {
              'identifier' => identifier,
              'link_to' => target
            }
          }
          export_zone(target, data_zones, linked_zones, from_value, to_value)
        elsif info.kind_of?(ConstantOffsetDataTimezoneInfo)
          data_zones[identifier] = {
            data: {
              'identifier' => identifier,
              'type' => 'constant',
              'offset' => offset_data(info.constant_offset)
            }
          }
        elsif info.kind_of?(TransitionsDataTimezoneInfo)
          data_zones[identifier] = {
            data: export_transitions_zone(identifier, info.transitions, from_value, to_value)
          }
        else
          raise InvalidTimezonePackageExport, "unsupported time zone information for #{identifier}: #{info.class}"
        end
      rescue InvalidTimezoneIdentifier
        raise InvalidTimezonePackageExport, "unknown time zone: #{identifier}"
      end

      # Builds the data for a transitions-based zone restricted to the window.
      #
      # @param identifier [String] the zone identifier.
      # @param transitions [Array<TimezoneTransition>] all source transitions.
      # @param from_value [Integer] the window start.
      # @param to_value [Integer] the window end.
      # @return [Hash] the JSON-compatible zone data.
      def export_transitions_zone(identifier, transitions, from_value, to_value)
        # The period at the window start depends on the preceding transition.
        # Include every transition up to and including the first transition
        # after the window end so the final covered period has a known end and
        # can never be extrapolated.
        first_needed = transitions.bsearch_index {|t| t.timestamp_value > from_value } || transitions.length
        start_index = first_needed > 0 ? first_needed - 1 : 0

        end_index = transitions.bsearch_index {|t| t.timestamp_value > to_value }
        raise InvalidTimezonePackageExport, "time zone #{identifier} has no transition after the window end; coverage cannot be bounded" unless end_index

        selected = transitions[start_index..end_index]

        offsets = {}
        offset_order = []
        transition_data = []

        register_offset = lambda do |offset|
          key = offset_key(offset)
          unless offsets.has_key?(key)
            offsets[key] = offset_order.length
            offset_order << offset_data(offset)
          end
          offsets[key]
        end

        selected.each do |transition|
          offset_index = register_offset.call(transition.offset)
          previous_index = register_offset.call(transition.previous_offset)
          transition_data << {
            'at' => transition.timestamp_value,
            'offset' => offset_index,
            'previous_offset' => previous_index
          }
        end

        {
          'identifier' => identifier,
          'type' => 'transitions',
          'offsets' => offset_order,
          'transitions' => transition_data
        }
      end

      # @param offset [TimezoneOffset] an offset.
      # @return [Array] the deduplication key for an offset.
      def offset_key(offset)
        [offset.base_utc_offset, offset.std_offset, offset.abbreviation]
      end

      # @param offset [TimezoneOffset] an offset.
      # @return [Hash] the JSON-compatible offset data.
      def offset_data(offset)
        {
          'base_utc_offset' => offset.base_utc_offset,
          'std_offset' => offset.std_offset,
          'abbreviation' => offset.abbreviation
        }
      end
    end
  end
end
