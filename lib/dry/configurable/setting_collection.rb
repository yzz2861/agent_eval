# frozen_string_literal: true

module Dry
  module Configurable
    # A collection of named member configs, all built from a single settings
    # template declared via {ClassMethods#setting_collection}.
    #
    # Members are added by name at runtime, so their names don't need to be
    # known when the settings are declared:
    #
    # @example
    #
    #   class Service
    #     extend Dry::Configurable
    #
    #     setting_collection :connections do
    #       setting :dsn, constructor: ->(v) { v.to_s }
    #       setting :pool_size, default: 5
    #     end
    #   end
    #
    #   Service.config.connections.add(:primary)
    #   Service.config.connections.primary.dsn = "postgres://primary"
    #   Service.config.connections[:primary].pool_size # => 5
    #
    # @api public
    class SettingCollection
      include Dry::Equalizer(:_settings, :_members)

      include Enumerable

      # @api private
      attr_reader :_settings

      # @api private
      attr_reader :_members

      # @api private
      def initialize(settings, config_class: Config, members: {})
        @_settings = settings
        @config_class = config_class
        @_members = members
      end

      # @api private
      private def initialize_copy(source)
        super
        @_members = source._members.transform_values(&:dup)
      end

      # Adds a member config built from the collection's settings template.
      #
      # Member names follow the same rules as setting names, and may not clash
      # with the collection's own API (e.g. +values+ or +finalize!+ would be
      # unreachable through method access).
      #
      # @param [String, Symbol] name
      #
      # @yield [Config] the new member config, for convenience
      #
      # @return [Config] the new member config
      #
      # @api public
      def add(name)
        raise FrozenConfigError, "Cannot modify frozen config" if frozen?

        name = name.to_sym

        ensure_valid_name(name)

        if _members.key?(name)
          raise ArgumentError, "+#{name}+ member is already defined"
        end

        member = @config_class.new(_settings)
        _members[name] = member

        yield(member) if block_given?

        member
      end

      # Returns the member config for the given name.
      #
      # @param [String, Symbol] name
      #
      # @return [Config]
      #
      # @raise [UnknownMemberError] if no member was added under the given name
      #
      # @api public
      def [](name)
        _members.fetch(name.to_sym) {
          raise UnknownMemberError, "+#{name}+ is not a member of this collection"
        }
      end

      # Removes the member config for the given name.
      #
      # @param [String, Symbol] name
      #
      # @return [Config] the removed member config
      #
      # @raise [UnknownMemberError] if no member was added under the given name
      #
      # @api public
      def delete(name)
        raise FrozenConfigError, "Cannot modify frozen config" if frozen?

        name = name.to_sym

        unless _members.key?(name)
          raise UnknownMemberError, "+#{name}+ is not a member of this collection"
        end

        _members.delete(name)
      end

      # Returns true if a member was added under the given name.
      #
      # @return [Boolean]
      #
      # @api public
      def key?(name)
        _members.key?(name.to_sym)
      end

      # Returns the names of all added members.
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def keys
        _members.keys
      end

      # Yields each member as a +name, config+ pair.
      #
      # @api public
      def each(&)
        _members.each(&)
      end

      # Returns member configs as a hash of +name => values hash+.
      #
      # @return [Hash]
      #
      # @api public
      def to_h
        _members.transform_values(&:to_h)
      end

      # Returns member configs as a frozen hash of +name => Data+.
      #
      # Only available once the collection (and thereby its members) has been
      # finalized. See {Config#to_data}.
      #
      # @return [Hash]
      #
      # @api public
      def to_data
        _members.transform_values(&:to_data).freeze
      end

      # @api private
      def finalize!(freeze_values: false)
        return self if frozen?

        _members.each_value { |member| member.finalize!(freeze_values: freeze_values) }

        freeze
      end

      # Returns a copy of the collection without any members.
      #
      # @api private
      def pristine
        self.class.new(_settings, config_class: @config_class)
      end

      private

      def ensure_valid_name(name)
        unless DSL::VALID_NAME.match?(name.to_s)
          raise ArgumentError, "#{name} is not a valid member name"
        end

        if RESERVED_NAMES.include?(name)
          raise ArgumentError,
            "#{name.inspect} is not a valid member name: it conflicts with the " +            "setting collection API"
        end
      end

      def method_missing(name, *args)
        if args.empty? && _members.key?(name)
          _members[name]
        else
          super
        end
      end

      def respond_to_missing?(name, include_private = false)
        _members.key?(name) || super
      end

      # Member names defined on the collection itself cannot be used, since the
      # collection's own methods would shadow them on the method access path.
      RESERVED_NAMES = instance_methods.to_set.freeze
    end
  end
end
