module Dotenv
  class CircularDependencyError < StandardError
    def initialize(chain)
      super("Circular variable reference: #{chain.join(" -> ")}")
    end
  end
end
