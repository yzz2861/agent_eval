# frozen_string_literal: true

require 'json'

module JWT
  # @api private
  class JSON
    class << self
      def generate(data)
        ::JSON.generate(data)
      end

      def parse(data, **options)
        ::JSON.parse(data, **options)
      end
    end
  end
end
