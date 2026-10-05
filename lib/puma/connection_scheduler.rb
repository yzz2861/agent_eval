# frozen_string_literal: true

module Puma
  class ConnectionScheduler
    def initialize(thread_pool, requests_per_round)
      @thread_pool = thread_pool
      @requests_per_round = requests_per_round
      @mutex = Mutex.new
      @waiting = []
      @work_queue = Queue.new
      @shutdown = false
    end

    def add(client, releasing: false)
      @mutex.synchronize do
        return false if @shutdown
        return true if @waiting.include?(client)

        client.fair_scheduling_remaining = @requests_per_round
        return true if @thread_pool.ready_push(client, releasing: releasing)

        @waiting << client
        true
      end
    end

    def work_queue
      @work_queue
    end

    def release(client = nil)
      @mutex.synchronize do
        return if @shutdown

        if client && !@waiting.include?(client)
          client.fair_scheduling_remaining = @requests_per_round
          @waiting << client
        end

        dispatch
        true
      end
    end

    def drain
      @mutex.synchronize do
        @shutdown = true
        @waiting.clear
      end
    end

    def size
      @mutex.synchronize { @waiting.size }
    end

    private

    def dispatch
      return if @waiting.empty?

      client = @waiting.first
      return unless @thread_pool.ready_push(client, releasing: true)

      @waiting.shift
    end
  end
end
