require 'flipper/typecast'

module Flipper
  module Types
    class Prerequisite < Type
      STATES = {
        true => true,
        false => false,
        'true' => true,
        'false' => false,
        :enabled => true,
        :disabled => false,
        'enabled' => true,
        'disabled' => false,
        :on => true,
        :off => false,
        'on' => true,
        'off' => false,
      }.freeze

      def self.wrap(value)
        return value if value.is_a?(self)

        case value
        when String
          parsed = Typecast.from_json(value)
          raise ArgumentError, 'invalid prerequisite value' unless parsed.is_a?(Hash)
          new(parsed['name'], parsed['enabled'])
        when Hash
          state = value.key?(:enabled) ? value[:enabled] : value['enabled']
          new(value[:name] || value['name'], state.nil? ? true : state)
        else
          new(value, true)
        end
      end

      def initialize(name, enabled = true)
        name = Typecast.to_feature_name(name)
        raise ArgumentError, 'prerequisite name cannot be blank' if name.empty?
        raise ArgumentError, "invalid prerequisite state: #{enabled.inspect}" unless STATES.key?(enabled)

        @name = name
        @required_state = STATES.fetch(enabled)
        @value = Typecast.to_json(name: @name, enabled: @required_state)
      end

      attr_reader :name, :required_state

      def matches?(enabled)
        enabled == required_state
      end
    end
  end
end
