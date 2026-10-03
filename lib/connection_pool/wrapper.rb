class ConnectionPool
  class Wrapper < ::BasicObject
    METHODS = [
      :with,
      :pool_shutdown,
      :pool_resize,
      :pool_size,
      :pool_available,
      :pool_idle,
      :pool_checked_out,
      :pool_pending_reaping,
      :pool_stats,
      :wrapped_pool
    ]

    def initialize(**options, &block)
      @pool = options.fetch(:pool) { ::ConnectionPool.new(**options, &block) }
    end

    def wrapped_pool
      @pool
    end

    def with(**kwargs, &block)
      @pool.with(**kwargs, &block)
    end

    def pool_shutdown(&block)
      @pool.shutdown(&block)
    end

    def pool_resize(size, &block)
      @pool.resize(size, &block)
    end

    def pool_size
      @pool.size
    end

    def pool_available
      @pool.available
    end

    def pool_idle
      @pool.idle
    end

    def pool_checked_out
      @pool.checked_out
    end

    def pool_pending_reaping
      @pool.pending_reaping
    end

    def pool_stats
      @pool.stats
    end

    def respond_to?(id, *args, **kwargs)
      METHODS.include?(id) || with { |c| c.respond_to?(id, *args, **kwargs) }
    end

    def respond_to_missing?(id, *args, **kwargs)
      with { |c| c.respond_to?(id, *args, **kwargs) }
    end

    def method_missing(name, *args, **kwargs, &block)
      with do |connection|
        connection.send(name, *args, **kwargs, &block)
      end
    end
  end
end
