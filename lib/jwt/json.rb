# frozen_string_literal: true

require 'json'
require_relative 'strict_json'

module JWT
  # Thin wrapper over the JSON standard library. The generic +parse+ entry
  # keeps the standard library semantics (including "last value wins" for
  # duplicate members) for backwards compatibility. Token segments must be
  # parsed with {#parse_strict}, which rejects ambiguous and abusive input.
  class JSON
    class << self
      def generate(data)
        ::JSON.generate(data)
      end

      # Lenient parse kept for compatibility with non-security callers.
      def parse(data)
        ::JSON.parse(data)
      end

      # Strict parse used for every JWT header and payload segment.
      def parse_strict(data)
        StrictJSON.parse(data)
      end
    end
  end
end
