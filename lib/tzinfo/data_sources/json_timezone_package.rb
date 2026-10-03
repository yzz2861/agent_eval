# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  module DataSources
    # Raised when a limited JSON time zone package is malformed or fails its
    # consistency checks.
    class InvalidTimezonePackage < StandardError
    end

    # Exports and imports small, versioned time zone packages containing only
    # plain JSON data. Imported transition rules have explicit finite coverage
    # and do not extrapolate an offset beyond the saved window.
    class JsonTimezonePackage
      # The JSON format identifier.
      FORMAT_TYPE = 'tzinfo-limited-timezone-package'.freeze

      # The version of the JSON format produced and accepted by this class.
      SCHEMA_VERSION = 1

      class << self
        # Exports the requested time zones and returns a plain JSON-compatible
        # Hash. No Ruby source code is included in the result.
        #
        # @param identifiers [Array<String>] the time zone identifiers to save.
        # @param start_time [Object] the inclusive UTC start of the query
        #   window.
        # @param end_time [Object] the inclusive UTC end of the query window.
        # @param include_aliases [Boolean] whether to include all aliases known
        #   by the current data source for each canonical zone.
        # @return [Hash] a JSON-compatible package.
        def export(identifiers, start_time, end_time, include_aliases = true)
          new_exporter(identifiers, start_time, end_time, include_aliases).export
        end

        # Exports a package and returns it as formatted JSON.
        #
        # @param identifiers [Array<String>] the time zone identifiers to save.
        # @param start_time [Object] the inclusive UTC start of the query
        #   window.
        # @param end_time [Object] the inclusive UTC end of the query window.
        # @param include_aliases [Boolean] whether to include all aliases known
        #   by the current data source.
        # @return [String] JSON data.
        def dump(identifiers, start_time, end_time, include_aliases = true)
          require 'json'
          JSON.pretty_generate(export(identifiers, start_time, end_time, include_aliases))
        end

        # Imports JSON data or an already parsed JSON-compatible Hash and
        # returns a finite {DataSource}.
        #
        # @param json [String, Hash] JSON text or parsed package data.
        # @return [JsonPackageDataSource] the imported data source.
        # @raise [InvalidTimezonePackage] if the package is invalid.
        def import(json)
          load(json)
        end
        def load(json)
          data = case json
            when String
              require 'json'
              begin
                JSON.parse(json)
              rescue JSON::ParserError => e
                raise InvalidTimezonePackage, "Invalid JSON: #{e.message}"
              end
            when Hash
              json
            else
              raise InvalidTimezonePackage, 'Package must be a JSON object or a String containing JSON'
          end

          new(data).to_data_source
        end

        private

        def new_exporter(identifiers, start_time, end_time, include_aliases)
          PackageExporter.new(identifiers, start_time, end_time, include_aliases)
        end
      end

      # Initializes a package from parsed JSON data.
      #
      # @param data [Hash] the parsed package.
      # @api private
      def initialize(data)
        @data = data
      end

      # Validates the package and builds a {JsonPackageDataSource}.
      #
      # @return [JsonPackageDataSource] the imported data source.
      # @api private
      def to_data_source
        validate
        @data = deep_freeze(@data)
        JsonPackageDataSource.new(@data)
      end

      private

      def validate
        PackageValidator.new(@data).validate
      end

      def deep_freeze(value)
        case value
          when Hash
            value.each {|key, item| deep_freeze(key); deep_freeze(item) }
          when Array
            value.each {|item| deep_freeze(item) }
        end
        value.freeze
      end
    end

    # @api private
    class PackageExporter
      def initialize(identifiers, start_time, end_time, include_aliases)
        identifiers = Array(identifiers).map(&:to_s)
        raise ArgumentError, 'at least one identifier must be specified' if identifiers.empty?

        @start_value = timestamp_value(start_time, 'start_time')
        @end_value = timestamp_value(end_time, 'end_time')
        raise ArgumentError, 'start_time must be less than or equal to end_time' if @start_value > @end_value

        @data_source = DataSource.get
        @include_aliases = include_aliases
        @canonical_infos = {}
        @links = {}

        identifiers.each {|identifier| collect_requested_zone(identifier) }
        collect_all_aliases if include_aliases
      end

      def export
        {
          'format' => JsonTimezonePackage::FORMAT_TYPE,
          'version' => JsonTimezonePackage::SCHEMA_VERSION,
          'window' => {
            'start_at' => @start_value,
            'end_at' => @end_value
          },
          'timezones' => canonical_zones + linked_zones
        }
      end

      private

      def timestamp_value(time, name)
        timestamp = Timestamp.for(time)
        raise ArgumentError, "#{name} must have a specified utc_offset" unless timestamp.utc_offset
        raise ArgumentError, "#{name} must be a whole number of seconds" unless timestamp.sub_second == 0
        timestamp.value
      end

      def collect_requested_zone(identifier)
        chain = resolve_chain(identifier)
        canonical_identifier = chain.last
        @canonical_infos[canonical_identifier] ||= info_for(canonical_identifier)

        chain.each_cons(2) {|from, to| @links[from] = to }
      end

      def collect_all_aliases
        @data_source.linked_timezone_identifiers.each do |identifier|
          begin
            chain = resolve_chain(identifier)
          rescue InvalidTimezoneIdentifier
            next
          end

          next unless @canonical_infos.has_key?(chain.last)
          chain.each_cons(2) {|from, to| @links[from] = to }
        end
      end

      def resolve_chain(identifier)
        chain = [identifier]
        seen = { identifier => true }

        while chain.length < 1000
          info = info_for(chain.last)
          return chain unless info.kind_of?(LinkedTimezoneInfo)

          target = info.link_to_identifier
          raise ArgumentError, "Time zone alias #{chain.last} forms a cycle" if seen[target]
          seen[target] = true
          chain << target
        end

        raise ArgumentError, "Time zone alias chain for #{identifier} is too long"
      end

      def info_for(identifier)
        @data_source.get_timezone_info(identifier)
      end

      def canonical_zones
        @canonical_infos.keys.sort.map do |identifier|
          info = @canonical_infos[identifier]
          if info.kind_of?(ConstantOffsetDataTimezoneInfo)
            constant_zone(identifier, info)
          elsif transitions_info?(info)
            verify_bounded_coverage(identifier, info)
            transitions_zone(identifier, info)
          else
            raise ArgumentError, "#{identifier} uses an unsupported time zone info type: #{info.class}"
          end
        end
      end

      def linked_zones
        @links.keys.sort.map do |identifier|
          {
            'identifier' => identifier,
            'type' => 'linked',
            'link_to' => @links[identifier]
          }
        end
      end

      def constant_zone(identifier, info)
        {
          'identifier' => identifier,
          'type' => 'constant_offset',
          'offset' => offset_data(info.constant_offset)
        }
      end

      def transitions_zone(identifier, info)
        selected = selected_transitions(info.transitions)
        if selected.first.timestamp_value > @end_value
          raise ArgumentError, "#{identifier} has no period covering the specified window end"
        end

        offsets = []
        offset_ids = {}

        add_offset = lambda do |offset|
          signature = offset_signature(offset)
          unless offset_ids.has_key?(signature)
            id = "o#{offsets.length}"
            offsets << { 'id' => id }.merge(offset_data(offset))
            offset_ids[signature] = id
          end
          offset_ids[signature]
        end

        first = selected.first
        initial = if @start_value < first.timestamp_value
          add_offset.call(first.previous_offset)
        end

        transitions = selected.map do |transition|
          {
            'at' => transition.timestamp_value,
            'offset' => add_offset.call(transition.offset),
            'previous_offset' => add_offset.call(transition.previous_offset)
          }
        end

        zone = {
          'identifier' => identifier,
          'type' => 'transitions',
          'transitions' => transitions,
          'offsets' => offsets
        }
        zone['initial_offset'] = initial if initial
        zone
      end

      def transitions_info?(info)
        info.kind_of?(TransitionsDataTimezoneInfo) || info.kind_of?(BoundedTransitionsDataTimezoneInfo)
      end

      def verify_bounded_coverage(identifier, info)
        return unless info.kind_of?(BoundedTransitionsDataTimezoneInfo)

        if @start_value < info.coverage_start_value || @end_value > info.coverage_end_value
          raise ArgumentError, "#{identifier} does not cover the entire specified window"
        end
      end

      def selected_transitions(transitions)
        first_after_start = transitions.bsearch_index {|transition| transition.timestamp_value > @start_value }
        start_index = first_after_start ? [first_after_start - 1, 0].max : transitions.length - 1

        first_after_end = transitions.bsearch_index {|transition| transition.timestamp_value > @end_value }
        end_index = first_after_end || transitions.length - 1

        transitions[start_index..end_index]
      end

      def offset_data(offset)
        {
          'base_utc_offset' => offset.base_utc_offset,
          'std_offset' => offset.std_offset,
          'observed_utc_offset' => offset.observed_utc_offset,
          'abbreviation' => offset.abbreviation
        }
      end

      def offset_signature(offset)
        [offset.base_utc_offset, offset.std_offset, offset.abbreviation]
      end
    end

    # @api private
    class PackageValidator
      def initialize(data)
        @data = data
      end

      def validate
        assert_kind('package', @data, Hash)
        assert_keys(@data, ['format', 'version', 'window', 'timezones'], 'package')
        assert_equal(JsonTimezonePackage::FORMAT_TYPE, @data['format'], 'format')
        assert_equal(JsonTimezonePackage::SCHEMA_VERSION, @data['version'], 'version')
        validate_window
        validate_timezones
        validate_links
      end

      private

      def validate_window
        window = @data['window']
        assert_kind('window', window, Hash)
        assert_keys(window, ['start_at', 'end_at'], 'window')
        assert_integer_value(window['start_at'], 'window.start_at')
        assert_integer_value(window['end_at'], 'window.end_at')
        raise InvalidTimezonePackage, 'window.start_at must be less than or equal to window.end_at' unless window['start_at'] <= window['end_at']
      end

      def validate_timezones
        zones = @data['timezones']
        assert_kind('timezones', zones, Array)
        raise InvalidTimezonePackage, 'timezones must not be empty' if zones.empty?

        @identifiers = {}
        @canonical_identifiers = {}
        zones.each {|zone| validate_timezone(zone) }
      end

      def validate_timezone(zone)
        assert_kind('timezone', zone, Hash)
        identifier = zone['identifier']
        assert_string_value(identifier, 'timezone.identifier')
        raise InvalidTimezonePackage, "Duplicate time zone identifier: #{identifier}" if @identifiers[identifier]
        @identifiers[identifier] = true

        case zone['type']
          when 'constant_offset'
            assert_keys(zone, ['identifier', 'type', 'offset'], identifier)
            validate_offset_value(zone['offset'], "#{identifier}.offset", nil)
            @canonical_identifiers[identifier] = true
          when 'transitions'
            assert_keys(zone, ['identifier', 'type', 'offsets', 'transitions', 'initial_offset'], identifier, true)
            validate_transitions_zone(zone)
            @canonical_identifiers[identifier] = true
          when 'linked'
            assert_keys(zone, ['identifier', 'type', 'link_to'], identifier)
            assert_string_value(zone['link_to'], "#{identifier}.link_to")
            raise InvalidTimezonePackage, "#{identifier} cannot link to itself" if identifier == zone['link_to']
          else
            if zone.has_key?('type')
              raise InvalidTimezonePackage, "#{identifier} has an invalid type: #{zone['type'].inspect}"
            else
              raise InvalidTimezonePackage, "#{identifier} is missing field: type"
            end
        end
      end

      def validate_transitions_zone(zone)
        identifier = zone['identifier']
        offsets = zone['offsets']
        assert_kind("#{identifier}.offsets", offsets, Array)
        raise InvalidTimezonePackage, "#{identifier}.offsets must not be empty" if offsets.empty?

        offset_ids = {}
        offsets.each do |offset|
          id = validate_offset_value(offset, "#{identifier}.offsets", true)
          raise InvalidTimezonePackage, "#{identifier} has a duplicate offset id: #{id}" if offset_ids[id]
          offset_ids[id] = offset
        end

        transitions = zone['transitions']
        assert_kind("#{identifier}.transitions", transitions, Array)
        raise InvalidTimezonePackage, "#{identifier}.transitions must not be empty" if transitions.empty?

        referenced = {}
        previous_at = nil
        transitions_seen_before_start = 0
        transitions_seen_after_end = 0

        transitions.each_with_index do |transition, index|
          assert_kind("#{identifier}.transitions[#{index}]", transition, Hash)
          assert_keys(transition, ['at', 'offset', 'previous_offset'], "#{identifier}.transitions[#{index}]")
          at = transition['at']
          assert_integer_value(at, "#{identifier}.transitions[#{index}].at")
          if previous_at
            raise InvalidTimezonePackage, "#{identifier} transitions must be strictly increasing" unless at > previous_at
          end
          previous_at = at

          offset_id = transition['offset']
          previous_offset_id = transition['previous_offset']
          assert_offset_id(identifier, offset_ids, offset_id, referenced, "transitions[#{index}].offset")
          assert_offset_id(identifier, offset_ids, previous_offset_id, referenced, "transitions[#{index}].previous_offset")
          transitions_seen_before_start += 1 if at < @data['window']['start_at']
          transitions_seen_after_end += 1 if at > @data['window']['end_at']

          if index > 0
            prior = transitions[index - 1]
            unless previous_offset_id == prior['offset']
              raise InvalidTimezonePackage, "#{identifier} transition #{index} does not continue from the previous transition"
            end
          end
        end

        unless transitions_seen_before_start <= 1 && (transitions_seen_before_end_in_order?(transitions, transitions_seen_before_start))
          raise InvalidTimezonePackage, "#{identifier} includes transitions before the period needed for window start"
        end

        unless transitions_seen_after_end <= 1 && (transitions_seen_after_end_in_order?(transitions, transitions_seen_after_end))
          raise InvalidTimezonePackage, "#{identifier} includes more transitions than are needed for window end"
        end

        first = transitions.first
        unless first['at'] <= @data['window']['end_at']
          raise InvalidTimezonePackage, "#{identifier} has no period covering window end"
        end

        if first['at'] > @data['window']['start_at']
          initial_offset = zone['initial_offset']
          assert_offset_id(identifier, offset_ids, initial_offset, referenced, 'initial_offset')
          unless initial_offset == first['previous_offset']
            raise InvalidTimezonePackage, "#{identifier} initial_offset must be the offset before the first included transition"
          end
        elsif !zone['initial_offset'].nil?
          raise InvalidTimezonePackage, "#{identifier} initial_offset must only be present when coverage starts before the first transition"
        end

        unused = offset_ids.keys - referenced.keys
        raise InvalidTimezonePackage, "#{identifier} has unused offsets: #{unused.join(', ')}" unless unused.empty?
      end

      def validate_offset_value(offset, path, require_id)
        assert_kind(path, offset, Hash)
        expected_keys = require_id ?
          ['id', 'base_utc_offset', 'std_offset', 'observed_utc_offset', 'abbreviation'] :
          ['base_utc_offset', 'std_offset', 'observed_utc_offset', 'abbreviation']
        assert_keys(offset, expected_keys, path)
        id = offset['id']
        if require_id
          assert_string_value(id, "#{path}.id")
        elsif !id.nil?
          raise InvalidTimezonePackage, "#{path}.id must not be present"
        end

        base = offset['base_utc_offset']
        std = offset['std_offset']
        observed = offset['observed_utc_offset']
        abbreviation = offset['abbreviation']
        assert_integer_value(base, "#{path}.base_utc_offset")
        assert_integer_value(std, "#{path}.std_offset")
        assert_integer_value(observed, "#{path}.observed_utc_offset")
        assert_string_value(abbreviation, "#{path}.abbreviation")
        unless observed == base + std
          raise InvalidTimezonePackage, "#{path}.observed_utc_offset must equal base_utc_offset + std_offset"
        end
        id
      end

      def assert_offset_id(identifier, offset_ids, id, referenced, path)
        assert_string_value(id, "#{identifier}.#{path}")
        raise InvalidTimezonePackage, "#{identifier}.#{path} references an unknown offset: #{id}" unless offset_ids.has_key?(id)
        referenced[id] = true
      end

      def transitions_seen_before_end_in_order?(transitions, count)
        count.zero? || transitions.first['at'] < @data['window']['start_at']
      end

      def transitions_seen_after_end_in_order?(transitions, count)
        count.zero? || transitions.last['at'] > @data['window']['end_at']
      end

      def validate_links
        zones = @data['timezones']
        links = {}
        zones.each do |zone|
          next unless zone['type'] == 'linked'
          links[zone['identifier']] = zone['link_to']
        end

        links.each_key {|identifier| validate_link_chain(identifier, links, {}) }
      end

      def validate_link_chain(identifier, links, seen)
        raise InvalidTimezonePackage, "#{identifier} links to an unknown time zone" unless @identifiers[identifier]
        return if @canonical_identifiers[identifier]
        raise InvalidTimezonePackage, "#{identifier} is part of an alias cycle" if seen[identifier]

        seen[identifier] = true
        validate_link_chain(links[identifier], links, seen)
      end

      def assert_kind(path, value, expected_class)
        unless value.kind_of?(expected_class)
          raise InvalidTimezonePackage, "#{path} must be a #{expected_class.name} (got #{value.class.name})"
        end
      end

      def assert_keys(hash, expected_keys, path, optional = false)
        actual_keys = hash.keys
        extra_keys = actual_keys - expected_keys
        raise InvalidTimezonePackage, "#{path} has unexpected fields: #{extra_keys.join(', ')}" unless extra_keys.empty?

        unless optional
          missing_keys = expected_keys - actual_keys
          raise InvalidTimezonePackage, "#{path} is missing fields: #{missing_keys.join(', ')}" unless missing_keys.empty?
        end
      end

      def assert_equal(expected, actual, path)
        raise InvalidTimezonePackage, "#{path} must be #{expected.inspect} (got #{actual.inspect})" unless expected == actual
      end

      def assert_integer_value(value, path)
        unless value.kind_of?(Integer)
          raise InvalidTimezonePackage, "#{path} must be an Integer (got #{value.class.name})"
        end
      end

      def assert_string_value(value, path)
        unless value.kind_of?(String)
          raise InvalidTimezonePackage, "#{path} must be a String (got #{value.class.name})"
        end
        raise InvalidTimezonePackage, "#{path} must not be empty" if value.empty?
      end
    end

    # A finite {DataSource} backed by validated plain JSON package data.
    class JsonPackageDataSource < DataSource
      # (see DataSource#data_timezone_identifiers)
      attr_reader :data_timezone_identifiers

      # (see DataSource#linked_timezone_identifiers)
      attr_reader :linked_timezone_identifiers

      # (see DataSource#country_codes)
      attr_reader :country_codes

      # @api private
      def initialize(data)
        super()

        @data = data
        @start_value = data['window']['start_at']
        @end_value = data['window']['end_at']
        @timezone_infos = {}

        data['timezones'].each {|zone| @timezone_infos[zone['identifier']] = build_info(zone) }

        data_identifiers = []
        linked_identifiers = []
        @timezone_infos.each_key do |identifier|
          if @timezone_infos[identifier].kind_of?(LinkedTimezoneInfo)
            linked_identifiers << identifier
          else
            data_identifiers << identifier
          end
        end

        @data_timezone_identifiers = data_identifiers.sort!.freeze
        @linked_timezone_identifiers = linked_identifiers.sort!.freeze
        @country_codes = [].freeze
      end

      # @return [Hash] the validated JSON-compatible package data.
      def package
        @data
      end

      # (see DataSource#to_s)
      def to_s
        "Limited JSON DataSource (#{@start_value}..#{@end_value})"
      end

      protected

      # (see DataSource#load_timezone_info)
      def load_timezone_info(identifier)
        valid_identifier = validate_timezone_identifier(identifier)
        @timezone_infos[valid_identifier]
      end

      # (see DataSource#load_country_info)
      def load_country_info(code)
        raise InvalidCountryCode, "Invalid country code: #{code.nil? ? 'nil' : code}"
      end

      private

      def build_info(zone)
        identifier = zone['identifier']
        case zone['type']
          when 'constant_offset'
            ConstantOffsetDataTimezoneInfo.new(identifier, build_offset(zone['offset']))
          when 'transitions'
            build_transitions_info(identifier, zone)
          when 'linked'
            LinkedTimezoneInfo.new(identifier, zone['link_to'])
        end
      end

      def build_transitions_info(identifier, zone)
        offsets = {}
        zone['offsets'].each do |offset|
          offsets[offset['id']] = build_offset(offset)
        end

        transitions = zone['transitions'].map do |transition|
          offset = offsets.fetch(transition['offset'])
          previous_offset = offsets.fetch(transition['previous_offset'])
          TimezoneTransition.new(offset, previous_offset, transition['at'])
        end

        BoundedTransitionsDataTimezoneInfo.new(identifier, transitions, @start_value, @end_value)
      end

      def build_offset(offset)
        TimezoneOffset.new(offset['base_utc_offset'], offset['std_offset'], offset['abbreviation'])
      end
    end
  end
end
