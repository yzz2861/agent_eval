# frozen_string_literal: true

module Rack
  class Attack
    class Safelist < Check
      def initialize(name = nil, options = {}, &block)
        super(name, options, &block)
        @type = :safelist
      end
    end
  end
end
