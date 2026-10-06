# frozen_string_literal: true

module MessagePack
  class NegotiationError < StandardError
  end

  class TypeNegotiator
    RESERVED_TYPE_IDS = (-128..-1).to_a.freeze
    USER_TYPE_ID_RANGE = (0..127).freeze

    def initialize
      @definitions = {}
    end

    def register_type(name, version, type_ids, klass, required: false,
                      packer: :to_msgpack_ext,
                      unpacker: :from_msgpack_ext, **options)
      name = normalize_name(name)
      validate_version(version)
      type_ids = normalize_type_ids(type_ids)
      validate_class(klass)
      validate_option(required, :required, [true, false])
      validate_callback(packer, klass, :packer)
      validate_callback(unpacker, klass, :unpacker)
      validate_integer_extension_option(klass, options)

      definition = @definitions[name] ||= { required: required, versions: {} }
      unless definition[:required] == required
        raise ArgumentError, "type #{name.inspect} has inconsistent required flags"
      end
      if definition[:versions].key?(version)
        raise ArgumentError, "type #{name.inspect} version #{version.inspect} is already registered"
      end

      @definitions.each do |other_name, other_definition|
        next if other_name == name
        other_definition[:versions].each_value do |other_version|
          if other_version[:class].equal?(klass) && packer && other_version[:options][:packer]
            raise ArgumentError, "#{klass.inspect} is already registered as #{other_name.inspect}"
          end
        end
      end

      definition[:versions][version] = {
        version: version,
        class: klass,
        type_ids: type_ids,
        options: options.merge(packer: packer, unpacker: unpacker).freeze,
      }
      nil
    end

    def offer
      types = @definitions.map do |name, definition|
        versions = definition[:versions].values.map do |version|
          {
            version: version[:version],
            type_ids: version[:type_ids].dup,
          }
        end.sort { |left, right| compare_versions(left[:version], right[:version]) }

        {
          name: name,
          required: definition[:required],
          versions: versions,
        }
      end.sort_by { |type| type[:name] }

      deep_freeze(types: types)
    end

    def negotiate(remote_offer)
      local_index = index_offer(offer)
      remote_index = index_offer(remote_offer)
      agreement = build_agreement(local_index, remote_index)
      deep_freeze(agreement[:enabled_types])
      deep_freeze(agreement[:disabled_types])
      factory = install_factory(agreement[:enabled_types])
      NegotiatedSession.new(agreement[:enabled_types], agreement[:disabled_types], factory)
    end

    private

    def normalize_name(name)
      unless name.is_a?(String) || name.is_a?(Symbol)
        raise TypeError, "expected logical type name to be a String or Symbol"
      end
      name = name.to_s
      if name.empty?
        raise ArgumentError, "logical type name can't be empty"
      end
      name
    end

    def validate_version(version)
      if version.nil?
        raise ArgumentError, "type version can't be nil"
      end
    end

    def normalize_type_ids(type_ids)
      ids = Array(type_ids).flatten
      if ids.empty?
        raise ArgumentError, "at least one type id is required"
      end
      unless ids.all? { |id| id.is_a?(Integer) }
        raise TypeError, "type ids must be Integers"
      end
      if ids.any? { |id| RESERVED_TYPE_IDS.include?(id) }
        raise ArgumentError, "negative MessagePack extension type ids are reserved"
      end
      if ids.any? { |id| !USER_TYPE_ID_RANGE.include?(id) }
        raise RangeError, "type ids must be within 0 to 127"
      end
      if ids.uniq.length != ids.length
        raise ArgumentError, "type ids must be unique"
      end
      ids.freeze
    end

    def validate_class(klass)
      unless klass.is_a?(Module)
        raise TypeError, "expected Module or Class for type class, got #{klass.inspect}"
      end
    end

    def validate_option(value, name, accepted_values)
      unless accepted_values.include?(value)
        raise ArgumentError, "#{name} must be one of #{accepted_values.map(&:inspect).join(', ')}"
      end
    end

    def validate_callback(value, klass, direction)
      valid = case value
              when nil, Proc, Method
                true
              when String, Symbol
                if direction == :unpacker
                  klass.method(value)
                else
                  klass.instance_method(value)
                end
                true
              else
                value.respond_to?(:call)
              end
      unless valid
        raise TypeError, "expected #{direction} to be callable, got: #{value.inspect}"
      end
    end

    def validate_integer_extension_option(klass, options)
      if options[:oversized_integer_extension] && klass != Integer
        raise ArgumentError, "oversized_integer_extension: true is only for Integer class"
      end
    end

    def deep_freeze(value)
      case value
      when Hash
        value.freeze
        value.each_value { |item| deep_freeze(item) }
      when Array
        value.freeze
        value.each { |item| deep_freeze(item) }
      else
        value.freeze
      end
      value
    end

    def index_offer(raw_offer)
      raw_types = raw_offer.is_a?(Hash) ? symbolize_keys(raw_offer)[:types] : raw_offer
      unless raw_types.is_a?(Array)
        raise NegotiationError, "expected a MessagePack type offer with a types array"
      end

      raw_types.each_with_object({}) do |raw_type, index|
        raw_type = symbolize_keys(raw_type)
        name = normalize_remote_name(raw_type[:name])
        required = raw_type.key?(:required) ? raw_type[:required] : false
        unless required.equal?(true) || required.equal?(false)
          raise NegotiationError, "type #{name} has an invalid required flag"
        end
        if index.key?(name)
          raise NegotiationError, "type #{name} is advertised more than once"
        end

        versions = normalize_remote_versions(name, raw_type[:versions])
        index[name] = { required: required, versions: versions }
      end
    rescue NegotiationError
      raise
    rescue => e
      raise NegotiationError, "invalid MessagePack type offer: #{e.message}"
    end

    def symbolize_keys(hash)
      unless hash.is_a?(Hash)
        raise NegotiationError, "expected Hash, got #{hash.class}"
      end
      hash.each_with_object({}) do |(key, value), result|
        unless key.is_a?(String) || key.is_a?(Symbol)
          raise NegotiationError, "invalid offer key #{key.inspect}"
        end
        result[key.to_sym] = value
      end
    end

    def normalize_remote_name(name)
      unless name.is_a?(String) || name.is_a?(Symbol)
        raise NegotiationError, "logical type name must be a String or Symbol"
      end
      name = name.to_s
      if name.empty?
        raise NegotiationError, "logical type name can't be empty"
      end
      name
    end

    def normalize_remote_versions(name, raw_versions)
      version_entries = case raw_versions
                        when Array
                          raw_versions
                        when Hash
                          raw_versions.map { |version, type_ids| { version: version, type_ids: type_ids } }
                        else
                          raise NegotiationError, "type #{name} has invalid versions"
                        end

      version_entries.each_with_object({}) do |raw_version, versions|
        raw_version = symbolize_keys(raw_version)
        version = raw_version[:version]
        if version.nil?
          raise NegotiationError, "type #{name} has a version without a version number"
        end
        if versions.key?(version)
          raise NegotiationError, "type #{name} advertises version #{version.inspect} more than once"
        end
        versions[version] = normalize_type_ids(raw_version[:type_ids])
      end
    end

    def build_agreement(local_index, remote_index)
      candidates = {}
      selected_versions = {}
      disabled = {}
      failures = {}
      required_names = []
      optional_names = []

      (local_index.keys | remote_index.keys).sort.each do |name|
        local = local_index[name]
        remote = remote_index[name]
        required = local && local[:required] || remote && remote[:required] ? true : false
        (required ? required_names : optional_names) << name

        if local.nil? || remote.nil?
          details = {
            local_versions: local ? sort_versions(local[:versions].keys) : [],
            remote_versions: remote ? sort_versions(remote[:versions].keys) : [],
          }
          if required
            failures[name] = details.merge(reason: :required_type_not_advertised_by_peer)
          else
            disabled[name] = details.merge(reason: :not_advertised_by_peer)
          end
          next
        end

        common_versions = sort_versions(local[:versions].keys & remote[:versions].keys)
        if common_versions.empty?
          details = {
            local_versions: sort_versions(local[:versions].keys),
            remote_versions: sort_versions(remote[:versions].keys),
          }
          if required
            failures[name] = details.merge(reason: :no_common_version)
          else
            disabled[name] = details.merge(reason: :no_common_version)
          end
          next
        end

        version = common_versions.reverse.find do |candidate|
          (local[:versions][candidate] & remote[:versions][candidate]).any?
        end
        if version.nil?
          details = {
            local_versions: sort_versions(local[:versions].keys),
            remote_versions: sort_versions(remote[:versions].keys),
          }
          if required
            failures[name] = details.merge(reason: :no_common_type_id)
          else
            disabled[name] = details.merge(reason: :no_common_type_id)
          end
          next
        end
        common_type_ids = (local[:versions][version] & remote[:versions][version]).sort

        selected_versions[name] = version
        candidates[name] = common_type_ids
      end

      assignments = {}
      required_candidates = required_names.select { |name| candidates.key?(name) }
      required_candidates.sort_by! { |name| [candidates[name].length, name] }
      assign_types(required_candidates, candidates, assignments)
      required_candidates.each do |name|
        next if assignments.key?(name)
        local = local_index[name]
        remote = remote_index[name]
        failures[name] = {
          reason: :no_available_type_id,
          local_versions: sort_versions(local[:versions].keys),
          remote_versions: sort_versions(remote[:versions].keys),
        }
      end

      unless failures.empty?
        details = failures.keys.sort.map { |name| "#{name} (#{failures[name][:reason]})" }.join(", ")
        raise NegotiationError, "incompatible MessagePack type negotiation: #{details}"
      end

      assign_types(optional_names.select { |name| candidates.key?(name) }.sort, candidates, assignments)
      candidates.each_key do |name|
        next if assignments.key?(name)
        disabled[name] = {
          reason: :no_available_type_id,
          local_versions: sort_versions(local_index[name][:versions].keys),
          remote_versions: sort_versions(remote_index[name][:versions].keys),
        }
      end

      enabled_types = assignments.sort.each_with_object({}) do |(name, type_id), result|
        result[name] = { version: selected_versions[name], type: type_id }
      end
      disabled_types = disabled.sort.each_with_object({}) do |(name, details), result|
        result[name] = details
      end

      { enabled_types: enabled_types, disabled_types: disabled_types }
    end

    def assign_types(names, candidates, assignments)
      owners = assignments.invert
      names.each do |name|
        next if assignments.key?(name)
        visited = {}
        augment_assignment(name, candidates, assignments, owners, visited)
      end
    end

    def augment_assignment(name, candidates, assignments, owners, visited)
      candidates[name].each do |type_id|
        next if visited[type_id]
        visited[type_id] = true

        owner = owners[type_id]
        if owner.nil? || augment_assignment(owner, candidates, assignments, owners, visited)
          owners[type_id] = name
          assignments[name] = type_id
          return true
        end
      end
      false
    end

    def sort_versions(versions)
      versions.sort { |left, right| compare_versions(left, right) }
    rescue ArgumentError
      versions.sort_by { |version| [version.class.name, version.inspect] }
    end

    def compare_versions(left, right)
      if left.class == right.class
        left <=> right
      else
        left.class.name <=> right.class.name
      end
    end

    def install_factory(enabled_types)
      factory = MessagePack::Factory.new
      enabled_types.each do |name, agreement|
        entry = @definitions.fetch(name).fetch(:versions).fetch(agreement[:version])
        factory.register_type(agreement[:type], entry[:class], entry[:options])
      end
      factory.freeze
    rescue => e
      raise NegotiationError, "failed to install negotiated MessagePack codec: #{e.message}"
    end

    class NegotiatedSession
      attr_reader :factory, :enabled_types, :disabled_types

      def initialize(enabled_types, disabled_types, factory)
        @enabled_types = enabled_types.freeze
        @disabled_types = disabled_types.freeze
        @factory = factory
        freeze
      end

      def packer(*args)
        @factory.packer(*args)
      end

      def unpacker(*args)
        @factory.unpacker(*args)
      end

      def dump(value, *args)
        @factory.dump(value, *args)
      end
      alias pack dump

      def load(source, param = nil)
        @factory.load(source, param)
      end
      alias unpack load

      def enabled?(name)
        @enabled_types.key?(name.to_s)
      end

      def disabled?(name)
        @disabled_types.key?(name.to_s)
      end

      def type_for(name)
        @enabled_types.fetch(name.to_s)
      end
    end
  end
end
