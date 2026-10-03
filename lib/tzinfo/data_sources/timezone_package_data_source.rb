# encoding: UTF-8
# frozen_string_literal: true

require_relative 'timezone_package'
require_relative 'timezone_package_exporter'
require_relative 'package_data_timezone_info'

module TZInfo
  module DataSources
    # Imports limited time zone packages produced by
    # {TimezonePackageExporter} and presents them as a read-only
    # {DataSource}.
    #
    # Packages contain ordinary JSON data only. No Ruby source is evaluated on
    # import.
    #
    # Import validates:
    #
    # * the package envelope, format and version;
    # * transition ordering and the presence of a bounding transition after
    #   the window end;
    # * referential integrity (every offset and link reference must resolve,
    #   links must not form cycles);
    # * offset numerics (integer seconds within a sane range and consistent
    #   base + std = observed values).
    class TimezonePackageDataSource < DataSource
      # @return [Hash] the raw, validated package data.
      attr_reader :package

      # @return [Integer] the inclusive UTC window start.
      attr_reader :window_from

      # @return [Integer] the inclusive UTC window end.
      attr_reader :window_to

      # Imports a package from a JSON string.
      #
      # @param json [String] JSON previously produced by
      #   {TimezonePackageExporter#export_to_json}.
      # @return [TimezonePackageDataSource] the imported data source.
      # @raise [InvalidTimezonePackage] if the package is invalid.
      def self.from_json(json)
        new(TimezonePackageFormat.load(json))
      end

      # Imports a package from a data structure.
      #
      # @param package [Hash] a package previously produced by
      #   {TimezonePackageExporter#export}.
      def initialize(package)
        super()
        raise InvalidTimezonePackage, 'package must be a Hash' unless package.kind_of?(Hash)
        @package = package
        @infos = {}
        validate!
      end

      # (see DataSource#to_s)
      def to_s
        "Limited Timezone Package DataSource (window #{@window_from}..#{@window_to} UTC, #{data_timezone_identifiers.length} data zones, #{linked_timezone_identifiers.length} linked zones)"
      end

      # (see DataSource#data_timezone_identifiers)
      def data_timezone_identifiers
        @data_timezone_identifiers
      end

      # (see DataSource#linked_timezone_identifiers)
      def linked_timezone_identifiers
        @linked_timezone_identifiers
      end

      # Country data is not carried by time zone packages.
      #
      # @raise [InvalidCountryCode] always.
      def load_country_info(code)
        raise InvalidCountryCode, "country data is not included in time zone packages: #{code.nil? ? 'nil' : code}"
      end

      # (see DataSource#country_codes)
      def country_codes
        EMPTY_COUNTRY_CODES
      end

      protected

      # (see DataSource#load_timezone_info)
      def load_timezone_info(identifier)
        @infos.fetch(identifier) do
          raise InvalidTimezoneIdentifier, "time zone not included in package: #{identifier}"
        end
      end

      private

      EMPTY_COUNTRY_CODES = [].freeze
      private_constant :EMPTY_COUNTRY_CODES

      # Validates the entire package and builds the cached timezone info
      # instances and identifier lists.
      def validate!
        validate_envelope!
        validate_window!

        data_entries = validate_zone_list('data_timezones')
        linked_entries = validate_zone_list('linked_timezones')

        validate_unique_identifiers(data_entries, linked_entries)

        data_infos = {}
        data_entries.each do |entry|
          identifier = entry['identifier']
          data_infos[identifier] = build_data_info(entry)
        end

        validate_links(linked_entries, data_infos)

        data_infos.each_value {|info| @infos[info.identifier] = info }
        linked_entries.each do |entry|
          identifier = entry['identifier']
          @infos[identifier] = LinkedTimezoneInfo.new(identifier, entry['link_to'])
        end

        @data_timezone_identifiers = data_infos.keys.sort!.freeze
        @linked_timezone_identifiers = linked_entries.map {|e| e['identifier'] }.sort!.freeze
      end

      # Validates the package envelope.
      def validate_envelope!
        unless @package['format'] == TimezonePackageFormat::FORMAT_NAME
          raise InvalidTimezonePackage, "unsupported format: #{@package['format'].inspect}"
        end

        unless @package['version'] == TimezonePackageFormat::FORMAT_VERSION
          raise InvalidTimezonePackage, "unsupported version: #{@package['version'].inspect}"
        end

        unless @package.has_key?('window') && @package.has_key?('data_timezones') && @package.has_key?('linked_timezones')
          raise InvalidTimezonePackage, 'package must contain window, data_timezones and linked_timezones'
        end
      end

      # Validates the coverage window.
      def validate_window!
        window = @package['window']
        raise InvalidTimezonePackage, 'window must be present' unless window.kind_of?(Hash)
        @window_from = integer_field(window, 'from')
        @window_to = integer_field(window, 'to')
        raise InvalidTimezonePackage, 'window.to must be greater than or equal to window.from' unless @window_to >= @window_from
      end

      # Validates one of the two zone lists.
      #
      # @param key [String] either `'data_timezones'` or
      #   `'linked_timezones'`.
      # @return [Array<Hash>] the validated list entries.
      def validate_zone_list(key)
        list = @package[key]
        raise InvalidTimezonePackage, "#{key} must be present and an Array" unless list.kind_of?(Array)
        raise InvalidTimezonePackage, "#{key} must not be empty" if list.empty? && key == 'data_timezones'
        list.each do |entry|
          raise InvalidTimezonePackage, "#{key} entries must be objects" unless entry.kind_of?(Hash)
          validate_identifier(entry['identifier']) { |message| "#{key}: #{message}" }
        end
        list
      end

      # Validates that no identifier is declared more than once.
      #
      # @param data_entries [Array<Hash>] the data zone entries.
      # @param linked_entries [Array<Hash>] the linked zone entries.
      def validate_unique_identifiers(data_entries, linked_entries)
        seen = {}
        (data_entries + linked_entries).each do |entry|
          identifier = entry['identifier']
          raise InvalidTimezonePackage, "duplicate time zone identifier: #{identifier}" if seen[identifier]
          seen[identifier] = true
        end
      end

      # Builds and validates a data zone info object.
      #
      # @param entry [Hash] a data zone entry.
      # @return [DataTimezoneInfo] the validated info.
      def build_data_info(entry)
        identifier = entry['identifier']
        type = entry['type']

        case type
        when 'constant'
          offset = build_offset(entry['offset'], "#{identifier}.offset")
          PackageConstantOffsetDataTimezoneInfo.new(identifier, offset, @window_from, @window_to)
        when 'transitions'
          build_transitions_info(identifier, entry)
        else
          raise InvalidTimezonePackage, "#{identifier}: unsupported type #{type.inspect}"
        end
      end

      # Builds and validates a transitions-based zone.
      #
      # @param identifier [String] the zone identifier.
      # @param entry [Hash] the zone entry.
      # @return [PackageTransitionsDataTimezoneInfo] the validated info.
      def build_transitions_info(identifier, entry)
        offset_entries = entry['offsets']
        unless offset_entries.kind_of?(Array) && !offset_entries.empty?
          raise InvalidTimezonePackage, "#{identifier}: offsets must be a non-empty Array"
        end

        offsets = offset_entries.each_with_index.map do |offset_entry, index|
          build_offset(offset_entry, "#{identifier}.offsets[#{index}]")
        end

        transition_entries = entry['transitions']
        unless transition_entries.kind_of?(Array) && !transition_entries.empty?
          raise InvalidTimezonePackage, "#{identifier}: transitions must be a non-empty Array"
        end

        previous_at = nil
        transitions = transition_entries.each_with_index.map do |transition_entry, index|
          at = integer_field(transition_entry, 'at') { "#{identifier}.transitions[#{index}].at" }
          offset_index = offset_reference(transition_entry, 'offset', offsets.length, identifier, index)
          previous_offset_index = offset_reference(transition_entry, 'previous_offset', offsets.length, identifier, index)

          if previous_at && at <= previous_at
            raise InvalidTimezonePackage, "#{identifier}: transitions must be strictly increasing (transitions[#{index}])"
          end
          previous_at = at

          TimezoneTransition.new(offsets[offset_index], offsets[previous_offset_index], at)
        end

        first_at = transitions.first.timestamp_value
        last_at = transitions.last.timestamp_value
        raise InvalidTimezonePackage, "#{identifier}: first transition (#{first_at}) must be at or before window.from (#{@window_from})" if first_at > @window_from
        raise InvalidTimezonePackage, "#{identifier}: last transition (#{last_at}) must be strictly after window.to (#{@window_to})" if last_at <= @window_to

        # The previous_offset of the first carried transition describes the
        # period before it, which is never used inside the window. Every
        # subsequent transition must continue from the offset reached by the
        # preceding transition.
        transitions.each_cons(2).with_index do |(earlier, later), index|
          unless later.previous_offset == earlier.offset
            raise InvalidTimezonePackage, "#{identifier}: previous_offset of transitions[#{index + 1}] does not match the offset of transitions[#{index}]"
          end
        end

        PackageTransitionsDataTimezoneInfo.new(identifier, transitions, @window_from, @window_to)
      end

      # Validates a single offset reference.
      #
      # @param entry [Hash] the transition entry.
      # @param key [String] the reference field name.
      # @param length [Integer] the number of available offsets.
      # @param identifier [String] the zone identifier.
      # @param index [Integer] the transition index.
      # @return [Integer] the validated offset index.
      def offset_reference(entry, key, length, identifier, index)
        value = entry[key]
        unless value.kind_of?(Integer) && value >= 0 && value < length
          raise InvalidTimezonePackage, "#{identifier}.transitions[#{index}].#{key} must reference an offsets index (got #{value.inspect})"
        end
        value
      end

      # Validates and builds a {TimezoneOffset}.
      #
      # @param entry [Object] the offset entry.
      # @param path [String] the JSON path used in error messages.
      # @return [TimezoneOffset] the validated offset.
      def build_offset(entry, path)
        raise InvalidTimezonePackage, "#{path} must be an object" unless entry.kind_of?(Hash)

        base = integer_field(entry, 'base_utc_offset') { "#{path}.base_utc_offset" }
        std = integer_field(entry, 'std_offset') { "#{path}.std_offset" }
        abbreviation = entry['abbreviation']
        unless abbreviation.kind_of?(String) && !abbreviation.empty?
          raise InvalidTimezonePackage, "#{path}.abbreviation must be a non-empty String"
        end

        unless base.abs <= TimezonePackageFormat::MAX_OFFSET_SECONDS && std.abs <= TimezonePackageFormat::MAX_OFFSET_SECONDS
          raise InvalidTimezonePackage, "#{path}: offsets must be within #{TimezonePackageFormat::MAX_OFFSET_SECONDS} seconds"
        end

        offset = TimezoneOffset.new(base, std, abbreviation)
        unless offset.observed_utc_offset.abs <= TimezonePackageFormat::MAX_OFFSET_SECONDS
          raise InvalidTimezonePackage, "#{path}: observed offset must be within #{TimezonePackageFormat::MAX_OFFSET_SECONDS} seconds"
        end

        offset
      end

      # Validates every link target and rejects cycles and unknown targets.
      #
      # @param linked_entries [Array<Hash>] the linked zone entries.
      # @param data_infos [Hash] the canonical data zone infos by identifier.
      def validate_links(linked_entries, data_infos)
        links = {}
        linked_entries.each do |entry|
          identifier = entry['identifier']
          target = entry['link_to']
          validate_identifier(target) {|message| "#{identifier}.link_to: #{message}" }
          raise InvalidTimezonePackage, "#{identifier}: a link must not target itself" if target == identifier
          links[identifier] = target
        end

        links.each_key do |identifier|
          visited = {}
          current = identifier

          while current
            raise InvalidTimezonePackage, "link chain starting at #{identifier} is cyclic (#{current} repeated)" if visited[current]
            visited[current] = true

            if data_infos.has_key?(current)
              break
            elsif links.has_key?(current)
              current = links[current]
            else
              raise InvalidTimezonePackage, "#{identifier}: link target #{current} is not included in the package"
            end
          end
        end
      end

      # Validates a time zone identifier string.
      #
      # @param value [Object] the candidate identifier.
      # @yield [message] optional block used to prefix error messages.
      # @raise [InvalidTimezonePackage] if the identifier is invalid.
      def validate_identifier(value)
        unless value.kind_of?(String) && !value.empty?
          message = "identifier must be a non-empty String (got #{value.inspect})"
          message = yield(message) if block_given?
          raise InvalidTimezonePackage, message
        end
      end

      # Reads an integer field with a descriptive error.
      #
      # @param object [Hash] the containing object.
      # @param key [String] the field name.
      # @yield optional block returning the field path for error messages.
      # @return [Integer] the validated integer.
      def integer_field(object, key)
        value = object[key]
        path = block_given? ? yield : key
        unless value.kind_of?(Integer)
          raise InvalidTimezonePackage, "#{path} must be an Integer (got #{value.inspect})"
        end
        value
      end
    end
  end
end
