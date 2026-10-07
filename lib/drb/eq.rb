# frozen_string_literal: false
module DRb
  class DRbObject # :nodoc:
    def ==(other)
      return false unless DRbObject === other
     (@ref == other.__drbref) &&
       (@uri == other.__drburi) &&
       (__drbservice == other.__drbservice)
    end

    def hash
      [@uri, @ref, @service_id].hash
    end

    alias eql? ==
  end
end
