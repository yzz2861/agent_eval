# frozen_string_literal: true

module Rack
  class Cors
    class Resource
      class CorsMisconfigurationError < StandardError
        DEFAULT_MESSAGE = 'Allowing credentials for wildcard origins is insecure.' \
                          " Please specify more restrictive origins or set 'credentials' to false in your CORS configuration."

        def initialize(message = DEFAULT_MESSAGE)
          super
        end
      end
    end
  end
end
