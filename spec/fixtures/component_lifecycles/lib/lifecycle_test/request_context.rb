# frozen_string_literal: true

# lifecycle: scoped
module LifecycleTest
  class RequestContext
    def close
      @closed = true
    end

    def closed?
      @closed == true
    end
  end
end
