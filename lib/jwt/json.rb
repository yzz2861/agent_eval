# frozen_string_literal: true

require 'json'
require 'jwt/strict_json'

module JWT
  # @api private
  class JSON
    class << self
      def generate(data)
        ::JSON.generate(data)
      end

      def parse(data)
        ::JSON.parse(data)
      end

      # Strictly parses JSON, rejecting duplicate object members and
      # enforcing depth, member and number length limits.
      def strict_parse(data, **limits)
        StrictJSON.parse(data, **limits)
      end
    end
  end
end
