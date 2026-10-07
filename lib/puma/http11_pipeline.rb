# frozen_string_literal: true

require 'thread'

module Puma
  class Http11Pipeline
    class PipelinedClient < Client
      attr_accessor :pipeline, :sequence, :keep_alive, :unsafe_barrier,
                    :estimated_buffer_size

      def initialize(root, sequence)
        super(root.io, nil)

        @sequence = sequence
        @env = root.env.dup
        @env[RACK_INPUT] = @body || Client::EmptyBody
        @body = root.body
        @tempfile = root.tempfile
        @requests_served = root.requests_served
        @listener = root.listener
        @remote_addr_header = root.remote_addr_header
        @env_set_http_version = root.env_set_http_version
        @supported_http_methods = root.supported_http_methods
        @http_content_length_limit = root.http_content_length_limit
        @allow_underscore_headers = root.allow_underscore_headers
      end

      def close
        tempfile_close
      end

      def safe?
        method = env[Const::REQUEST_METHOD]
        method == 'GET' || method == Const::HEAD
      end

      def error?
        false
      end
    end

    class ErrorClient < PipelinedClient
      attr_reader :error

      def initialize(root, sequence, error)
        super(root, sequence)
        @error = error
      end

      def error?
        true
      end
    end

    class BufferedIO
      attr_reader :buffer

      def initialize(socket)
        @socket = socket
        @buffer = +''
      end

      def write_nonblock(str, *)
        @buffer << str
        str.bytesize
      end

      def flush
        self
      end

      def cork
      end

      def uncork
      end

      def to_io
        @socket.to_io
      end

      def wait_writable(*)
        true
      end
    end

    def initialize(client, server, max_requests:, buffer_bytes:)
      @client = client
      @server = server
      @max_requests = max_requests
      @buffer_limit = buffer_bytes

      @mutex = Mutex.new
      @condition = ConditionVariable.new

      @sequence = 0
      @queued = []
      @active = {}
      @buffered = {}
      @app_count = 0
      @accepted_unsafe_sequence = 0
      @completed_unsafe_sequence = 0
      @next_write_sequence = 1
      @writer = nil
      @buffered_bytes = 0
      @closing = false
      @hijacked = false
      @failed = false

      @pump_thread = nil
      @pump_needed = false
      @pump_started_work = nil
      @stop_parsing = false
    end

    def start
      @client.pipeline = self
      request = take_ready_request(@client)
      request.pipeline = self
      work = dispatch(request)
      enqueue(work)
      read_available_requests
      :wait
    rescue StandardError => e
      parse_error(e)
      :readd
    rescue => e
      raise
    end

    def request_ready
      request = take_ready_request(@client)
      request.pipeline = self
      dispatch_and_enqueue(request)
      read_available_requests
      :readd
    rescue HttpParserError, HttpParserError501, ConnectionError => e
      parse_error(e)
      :readd
    end

    def shutdown
      @mutex.synchronize do
        @closing = true
        close_queued_requests
        @condition.broadcast
      end
    end

    def begin_write(request, response_info, body, content_length, chunked, hijack, headers_buffer)
      estimated_size = headers_buffer.length + (content_length || 0)

      @mutex.synchronize do
        raise ConnectionError, 'HTTP/1.1 pipeline closed' if @failed
        raise ConnectionError, 'HTTP/1.1 pipeline closing' if @closing && request.keep_alive

        if hijack
          wait_for_turn(request)
          @writer = request
          @hijacked = true
          @condition.broadcast
          next @client.io
        end

        if !request.safe? || (request.sequence == @next_write_sequence && (@writer.nil? || @writer == request))
        @writer = request
          next @client.io
        end

        if response_info && cacheable_response?(response_info, body, content_length, chunked, hijack) &&
            estimated_size <= available_buffer_bytes
          @buffered_bytes += estimated_size
          request.estimated_buffer_size = estimated_size
          next BufferedIO.new(@client.io)
        end

        next wait_for_turn(request)
      end
    end

    def begin_early_hint(request)
      @mutex.synchronize do
        raise ConnectionError, 'HTTP/1.1 pipeline closed' if @failed || @closing
        wait_for_turn(request)
        @writer = request
      end
    end

    def finish_write(request, keep_alive, sink)
      buffered = sink.is_a?(BufferedIO)
      @direct_pump_data = nil

      @mutex.synchronize do
        request.keep_alive = keep_alive

        if buffered
          if @closing || !keep_alive
            @buffered_bytes -= request.estimated_buffer_size.to_i
          else
            bytes = sink.buffer.bytesize
            @buffered_bytes += bytes - request.estimated_buffer_size.to_i
            request.estimated_buffer_size = bytes
            if request.sequence == @next_write_sequence && @writer.nil?
              @direct_pump_data = sink.buffer
              @writer = request
            else
              @buffered[request.sequence] = sink.buffer
              @pump_needed = true
            end
            @condition.broadcast
          end
        else
          @writer = nil
          @next_write_sequence += 1
          @active.delete(request.sequence)
        end

        @closing = true unless keep_alive
        close_queued_requests unless keep_alive
        cleanup_closing
        @condition.broadcast
        @pump_started_work
      end

      unless buffered && keep_alive && !@direct_pump_data
        @pump_started_work = @mutex.synchronize { complete_application_locked(request) }
      end

      start_pump_thread if @pump_needed
      @pump_needed = false
      enqueue(@pump_started_work) if @pump_started_work
      @pump_started_work = nil
      data = nil
      if buffered && keep_alive
        @mutex.synchronize { data = @direct_pump_data }
      end
      if data
        @server.fast_write_str(@client.io, data)
        finish_direct_pumped_response(request)
      end

      keep_alive ? :keep_alive : :close
    end

    def async(request)
      @mutex.synchronize do
        raise ConnectionError, 'HTTP/1.1 pipeline closed' if @failed || @closing
        wait_for_turn(request)
        @writer = request
        @hijacked = true
        @active.delete(request.sequence)
        complete_application(request)
        @condition.broadcast
      end
      :async
    end

    def fail(error = nil)
      @mutex.synchronize do
        return if @failed || @hijacked
        @failed = true
        @closing = true
        close_queued_requests
        @condition.broadcast
      end
      @client.close
      @server.remove_client_from_reactor(@client)
    rescue IOError, SystemCallError
      # Socket is already closed.
    ensure
      @server.log_pipeline_error(error) if error
    end

    def parse_error(error)
      sequence = next_sequence
      request = ErrorClient.new(@client, sequence, error)
      request.pipeline = self
      work = dispatch(request)

      @mutex.synchronize do
        @closing = true
        @condition.broadcast
      end

      enqueue(work)
    end

    private

    def take_ready_request(root)
      sequence = next_sequence
      request = PipelinedClient.new(root, sequence)
      root.release_after_pipelined_request_copy
      root.reset_for_pipelined_request
      request
    end

    def next_sequence
      @sequence += 1
    end

    def dispatch(request)
      @mutex.synchronize do
        if request.safe?
          request.unsafe_barrier = @accepted_unsafe_sequence
        else
          request.unsafe_barrier = @accepted_unsafe_sequence
          @accepted_unsafe_sequence = request.sequence
        end

        @queued << request
      end
      dequeue_work
    end

    def dispatch_and_enqueue(request)
      enqueue(dispatch(request))
    end

    def start_queued_requests
      work = nil
      while (request = @queued.first)
        if request.safe?
          break if @app_count >= @max_requests
          break if request.unsafe_barrier > @completed_unsafe_sequence
        else
          break unless @app_count.zero?
        end

        @queued.shift
        @app_count += 1
        @active[request.sequence] = request
        work = request
        break
      end
      work
    end

    def dequeue_work
      work = @mutex.synchronize { start_queued_requests }
      work
    end

    def complete_application(request)
      started = @mutex.synchronize do
        complete_application_locked(request)
      end
      enqueue(started)
    end

    def complete_application_locked(request)
      @app_count -= 1
      @completed_unsafe_sequence = request.sequence unless request.safe?
      start_queued_requests
    end

    def cacheable_response?(response_info, body, content_length, chunked, hijack)
      return false if hijack || chunked
      return true if response_info[:no_body]
      content_length && body.is_a?(Array)
    end

    def available_buffer_bytes
      @buffer_limit - @buffered_bytes
    end

    def wait_for_turn(request)
      loop do
        ready = @mutex.synchronize do
          raise ConnectionError, 'HTTP/1.1 pipeline closed' if @failed
          if @writer.nil? && request.sequence == @next_write_sequence && !@buffered.key?(@next_write_sequence)
            @writer = request
            true
          else
            false
          end
        end
        return @client.io if ready

        @mutex.synchronize { @condition.wait(@mutex) }
      end
    end

    def start_pump_thread
      @pump_thread ||= Thread.new { pump_loop }
      @pump_thread.abort_on_exception = true
    end

    def pump_loop
      loop do
        sequence, data = @mutex.synchronize do
          until @failed || @hijacked || @closing || ready_to_pump? || closing_with_no_work?
            @condition.wait(@mutex)
          end
          return if @failed || @hijacked || @closing || closing_with_no_work?

          sequence = @next_write_sequence
          data = @buffered.delete(sequence)
          @writer = @active[sequence]
          [sequence, data]
        end

        begin
          @server.fast_write_str(@client.io, data)
        started = finish_pumped_response(sequence)
        enqueue(started)
        rescue ConnectionError, IOError, SystemCallError => e
          fail(e)
          return
        end
      end
    end

    def ready_to_pump?
      @writer.nil? && @buffered.key?(@next_write_sequence)
    end

    def closing_with_no_work?
      @closing && @active.empty? && @buffered.empty?
    end

    def finish_pumped_response(sequence)
      @mutex.synchronize do
        request = @active.delete(sequence)
        @pump_started_work = complete_application_locked(request)
        @writer = nil
        @next_write_sequence += 1
        @buffered_bytes -= request&.estimated_buffer_size.to_i
        cleanup_closing
        @condition.broadcast
      end
    end

    def finish_direct_pumped_response(request)
      @mutex.synchronize do
        @writer = nil
        @next_write_sequence = request.sequence + 1
        @active.delete(request.sequence)
        @buffered_bytes -= request.estimated_buffer_size.to_i
        cleanup_closing
        @pump_started_work = complete_application_locked(request)
        @condition.broadcast
      end
    end

    def cleanup_closing
      return unless @closing

      @buffered.each_key do |sequence|
        request = @active.delete(sequence)
        @buffered_bytes -= request&.estimated_buffer_size.to_i
      end
      @buffered.clear

      close_idle_connection if @active.empty?
      @condition.broadcast
    end

    def close_idle_connection
      @client.close
      @server.remove_client_from_reactor(@client)
    rescue IOError, SystemCallError
      # Socket is already closed.
    end

    def close_queued_requests
      while (request = @queued.shift)
        begin
          request.close
        rescue StandardError
          # Best-effort cleanup.
        end
      end
    end

    def read_available_requests
      return if @closing
      while @client.has_back_to_back_requests?
        break if @stop_parsing
        ready = @client.process_back_to_back_requests
        break unless ready
        request = take_ready_request(@client)
        request.pipeline = self
        if request.env[Const::HTTP_CONNECTION].to_s.downcase.split(/[\s,]+/).include?(Const::CLOSE)
          request.keep_alive = false
          @stop_parsing = true
        end
        dispatch_and_enqueue(request)
      end

      return if @closing || @hijacked || @failed

      if @client.has_back_to_back_requests?
        # Remaining bytes belong to a request after a Connection: close request.
      else
        @client.set_timeout(@server.persistent_timeout)
      end
    rescue HttpParserError, HttpParserError501, ConnectionError => e
      parse_error(e)
    end

    def enqueue(work)
      @server.thread_pool_enqueue(work)
    end

  end
end
