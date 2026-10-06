require "dotenv/missing_keys"

module Dotenv
  class CircularReferenceError < Error
    def initialize(chain)
      super("Circular variable reference detected: #{chain.join(" -> ")}")
    end
  end
end
