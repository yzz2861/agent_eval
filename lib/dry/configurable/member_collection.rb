# frozen_string_literal: true

module Dry
  module Configurable
    # A collection of independently named configs sharing one member schema
    #
    # @api public
    class MemberCollection
      include Enumerable
      include Dry::Equalizer(:_members)

      # @api private
      attr_reader :_settings

      # @api private
      attr_reader :_members

      # @api private
      def initialize(member_settings, config_class: Config, members: {})
        @_settings = member_settings
        @_config_class = config_class
        @_members = members

        mark_missing_setting_error!(_settings)
      end

      # @api private
      private def initialize_copy(source)
        super
        @_members = source._members.transform_values(&:dup)
      end

      # @api private
      def clone(freeze: nil)
        copy = super
        copy.members.each(&:finalize!) if copy.frozen?
        copy
      end

      # Add a named member to the collection
      #
      # @return [MemberCollection]
      #
      # @api public
      def add(name, values = Undefined)
        raise FrozenConfigError, "Cannot modify frozen config" if frozen?

        key = ensure_valid_member_name(name)

        if _members.key?(key)
          raise ArgumentError, "+#{key}+ is already a member name"
        end

        member = build_member
        update_member(member, values) unless values.equal?(Undefined)
        yield(member) if block_given?
        _members[key] = member

        self
      end

      # Remove a named member from the collection
      #
      # @return [MemberCollection]
      #
      # @api public
      def delete(name)
        raise FrozenConfigError, "Cannot modify frozen config" if frozen?

        key = name.to_sym
        raise UnknownMemberError, key unless _members.key?(key)

        _members.delete(key)
        self
      end

      # Get a member config by name
      #
      # @return [Config]
      #
      # @api public
      def [](name)
        key = name.to_sym
        _members.fetch(key) { raise UnknownMemberError, key }
      end

      # Update an existing member config
      #
      # @return [MemberCollection]
      #
      # @api public
      def []=(name, value)
        raise FrozenConfigError, "Cannot modify frozen config" if frozen?

        key = name.to_sym
        raise UnknownMemberError, key unless _members.key?(key)

        update_member(self[key], value)
        self
      end

      # Update existing member configs from a hash
      #
      # @return [MemberCollection]
      #
      # @api public
      def update(values)
        raise FrozenConfigError, "Cannot modify frozen config" if frozen?

        values.each do |name, member_values|
          update_member(self[name], member_values)
        end
        self
      end

      # @return [Array<Symbol>]
      #
      # @api public
      def keys
        _members.keys
      end
      alias_method :names, :keys

      # @return [Boolean]
      #
      # @api public
      def key?(name)
        _members.key?(name.to_sym)
      end
      alias_method :member?, :key?

      # @return [Array<Config>]
      #
      # @api public
      def members
        _members.values
      end

      # @api public
      def each(&block)
        _members.each(&block)
      end

      # @return [Hash]
      #
      # @api public
      def to_h
        _members.transform_values(&:to_h)
      end

      # Finalize all member configs and freeze the collection
      #
      # @return [MemberCollection]
      #
      # @api public
      def finalize!(freeze_values: false)
        return self if frozen?

        members.each { |member| member.finalize!(freeze_values: freeze_values) }
        freeze
      end

      # @return [MemberCollection]
      #
      # @api public
      def pristine
        self.class.new(_settings, config_class: @_config_class)
      end

      # @api private
      def to_data
        unless frozen?
          raise FrozenConfigError, "config must be finalized before #to_data can be called"
        end

        ::Data.define(*keys).new(
          **_members.transform_values { |member| member.to_data }
        )
      end

      private

      def method_missing(name, *args)
        member_name = name.to_s.delete_suffix("=").to_sym

        if name.end_with?("=")
          self[member_name] = args.first
        else
          self[member_name]
        end
      end

      def respond_to_missing?(name, include_private = false)
        _members.key?(name.to_s.delete_suffix("=").to_sym) || super
      end

      def build_member
        @_config_class.new(_settings)
      end

      def update_member(member, value)
        case value
        when Config
          member.update(value.to_h)
        else
          unless value.respond_to?(:to_hash)
            raise ArgumentError, "#{value.inspect} is not a valid member value"
          end

          member.update(value.to_hash)
        end
      end

      def ensure_valid_member_name(name)
        key = name.to_sym

        unless DSL::VALID_NAME.match?(key.to_s)
          raise ArgumentError, "+#{key}+ is not a valid member name"
        end

        if RESERVED_NAMES.include?(key)
          raise ArgumentError, "+#{key}+ is not a valid member name: it conflicts with a config API method"
        end

        key
      end

      def mark_missing_setting_error!(settings)
        settings.missing_setting_error_class = UnknownMemberFieldError
        settings.each do |setting|
          children = setting.children
          mark_missing_setting_error!(children) if children.is_a?(Settings)
        end
      end

      RESERVED_NAMES = (
        DSL::DATA_RESERVED_NAMES +
          Config.instance_methods(false) +
          instance_methods(false)
      ).freeze
    end
  end
end
