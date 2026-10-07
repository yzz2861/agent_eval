# frozen_string_literal: true

require 'thread'

module Puma
  class HttpPipeline
    class Request
      attr_reader :env, :io, :io_buffer, :pipeline, :requests_served,
                  :sequence, :tempfile

      def initialize(client, pipeline, sequence, buffer_bytes)
        @env = client.env
        @body = client.body
        @tempfile = client.tempfile
        @io_buffer = client.io_buffer
        @requests_served = client.requests_served
        @pipeline = pipeline
        @sequence = sequence
        @hijacked = false
        @completed = false
        @response_hijacked = false
        @io = OrderedSocket.new(pipeline, sequence, client.io, buffer_bytes)

        @env[Const::PUMA_SOCKET] = @io
        @env[Const::HIJACK_IO] = nil
        @env[Const::HIJACK] = method(:full_hijack).to_proc
        @env[Const::RACK_INPUT] = @body
      end

      def exclusive?
        method = @env[Const::REQUEST_METHOD]
        method != 'GET' && method != Const::HEAD
      end

      def close_request?
        @env[Const::HTTP_CONNECTION].to_s.downcase == Const::CLOSE
      end

      def hijacked
        @hijacked
      end
      alias_method :hijacked?, :hijacked

      def full_hijack
        @hijacked = true
        @env[Const::HIJACK_IO] ||= @pipeline.hijack(@sequence)
      end

      def tempfile_close
        tempfile_path = @tempfile&.path
        @tempfile&.close
        File.unlink(tempfile_path) if tempfile_path
        @tempfile = nil
      rescue Errno::ENOENT, IOError
      ensure
        @body = nil
      end

      def close
        tempfile_close
      end

      def timeout!
        raise ConnectionError
      end

      def process(server, processor)
        server.process_pipelined_request(processor, self)
      end
    end

    class ErrorResponse
      attr_reader :env, :error, :io, :io_buffer, :pipeline, :sequence, :status

      def initialize(pipeline, sequence, error, status, socket, buffer_bytes)
        @pipeline = pipeline
        @sequence = sequence
        @error = error
        @status = status
        @io = OrderedSocket.new(pipeline, sequence, socket, buffer_bytes)
        @io_buffer = IOBuffer.new
        @env = {}
      end

      def requests_served
        sequence + 1
      end

      def tempfile_close
      end

      def process(server, processor)
        server.process_pipelined_error_response(processor, self)
      end
    end

    class OrderedSocket
      attr_reader :buffer_limit

      def initialize(pipeline, sequence, socket, buffer_limit)
        @pipeline = pipeline
        @sequence = sequence
        @socket = socket
        @buffer_limit = buffer_limit
        @response_started = false
      end

      def begin_response
        return if @response_started
        @pipeline.begin_write(@sequence)
        @response_started = true
      end

      def end_response(keep_alive)
        return unless @response_started
        @pipeline.end_write(@sequence, keep_alive)
        @response_started = false
      end

      def async_response
        if @response_started
          @response_hijacked = true
          @pipeline.async_after_write(@sequence)
        else
          @pipeline.async(@sequence)
        end
        @response_started = false
      end

      def fail_response
        @pipeline.fail_output(@sequence) if @response_started
      end

      def response_started?
        @response_started
      end

      def write_nonblock(data, *args, **kwargs)
        begin_response unless @response_hijacked
        @socket.write_nonblock(data, *args, **kwargs)
      end

      def write(data)
        begin_response unless @response_hijacked
        @socket.write(data)
      end

      alias_method :syswrite, :write
      alias_method :<<, :write

      def flush
        @socket.flush
      end

      def wait_writable(timeout)
        @socket.wait_writable(timeout)
      end

      def to_io
        @socket.to_io
      end

      def closed?
        @socket.closed?
      end

      def peeraddr
        @socket.peeraddr
      end

      def peercert
        @socket.peercert
      end

      def local_address
        @socket.local_address
      end

      private

      def respond_to_missing?(name, include_private = false)
        @socket.respond_to?(name, include_private) || super
      end

      def method_missing(name, *args, **kwargs, &block)
        @socket.public_send(name, *args, **kwargs, &block)
      end
    end

    attr_reader :client, :socket

    def initialize(client, max_requests:, buffer_bytes:)
      @client = client
      @socket = client.io
      @max_requests = max_requests
      @default_buffer_bytes = buffer_bytes
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @next_sequence = 0
      @next_write_sequence = 0
      @completed_sequence = 0
      @active_requests = 0
      @barrier_sequence = nil
      @state = :running
      @continuation = nil
      @closed = false
      @async = false
      @on_continue = nil
      @on_close = nil
    end

    def on_continue(&block)
      @on_continue = block
    end

    def on_close(&block)
      @on_close = block
    end

    def active?
      @mutex.synchronize { @active_requests.positive? }
    end

    def build_request(client)
      @mutex.synchronize do
        raise ConnectionError if @closed || @state != :running

        sequence = @next_sequence
        @next_sequence += 1
        request = client.detach_for_pipeline(self, sequence, @default_buffer_bytes)
        @active_requests += 1
        @barrier_sequence = sequence if request.exclusive?
        request
      end
    end

    def build_error_response(error, status)
      @mutex.synchronize do
        sequence = @next_sequence
        @next_sequence += 1
        @active_requests += 1
        finish_parser_locked
        ErrorResponse.new(self, sequence, error, status, @socket, @default_buffer_bytes)
      end
    end

    def cancel(work)
      work.close
      close_client = false
      @mutex.synchronize do
        @active_requests -= 1
        @barrier_sequence = nil if @barrier_sequence == work.sequence
        @closed = true
        finish_parser_locked
        close_client = ready_to_close_locked?
        @condition.broadcast
      end
      @on_close&.call if close_client
    end

    def request_completed_after_output
      close_client = false
      @mutex.synchronize do
        close_client = ready_to_close_locked?
      end
      @on_close&.call if close_client
    end

    def can_parse?
      @mutex.synchronize { !@closed && @state == :running && @active_requests < @max_requests }
    end

    def continuation?(client)
      @mutex.synchronize do
        return false unless @state == :running && !@closed
        if @active_requests >= @max_requests || @barrier_sequence
          @continuation = client
          @state = :continuation
          true
        else
          false
        end
      end
    end

    def parser_waiting
      @mutex.synchronize do
        return if @state == :closed
        @state = :waiting
        @continuation = nil
      end
    end

    def parser_finished
      close_client = false
      @mutex.synchronize do
        finish_parser_locked
        close_client = ready_to_close_locked?
      end
      @on_close&.call if close_client
    end

    def mark_closed
      close_client = false
      @mutex.synchronize do
        @closed = true
        finish_parser_locked
        close_client = ready_to_close_locked?
        @condition.broadcast
      end
      @on_close&.call if close_client
    end

    def timeout!
      close_client = false
      keep_waiting = false
      @mutex.synchronize do
        if @active_requests.positive?
          keep_waiting = true
        else
          @closed = true
          finish_parser_locked
          close_client = ready_to_close_locked?
        end
        @condition.broadcast
      end
      :close if close_client || !keep_waiting
    end

    def wait_to_run(request)
      @mutex.synchronize do
        until @closed
          if request.exclusive?
            break if @completed_sequence >= request.sequence
          elsif @barrier_sequence.nil? || request.sequence < @barrier_sequence ||
            @completed_sequence > @barrier_sequence
            break
          end
          @condition.wait(@mutex)
        end
        raise ConnectionError if @closed
      end
    end

    def request_completed(request, result)
      continuation = nil
      close_client = false

      @mutex.synchronize do
        raise ConnectionError if request.instance_variable_get(:@completed)
        request.instance_variable_set(:@completed, true)
        @completed_sequence += 1
        @active_requests -= 1
        @async = result == :async
        @closed = true if result == :close || result == :async
        continuation = resume_continuation_locked
        @barrier_sequence = nil if @barrier_sequence == request.sequence
        close_client = ready_to_close_locked?
        @condition.broadcast
      end

      @on_continue&.call(continuation) if continuation
      @on_close&.call if close_client
    end

    def request_failed(request, response_started: false)
      close_client = false
      @mutex.synchronize do
        return if request.instance_variable_get(:@completed)
        request.instance_variable_set(:@completed, true)
        @completed_sequence += 1
        @active_requests -= 1
        @closed = true
        @next_write_sequence += 1 unless response_started
        finish_parser_locked
        close_client = ready_to_close_locked?
        @condition.broadcast
      end
      @on_close&.call if close_client
    end

    def error_response_completed(response, keep_alive)
      close_client = false
      @mutex.synchronize do
        @completed_sequence += 1
        @active_requests -= 1
        @closed = !keep_alive
        close_client = ready_to_close_locked?
        @condition.broadcast
      end
      @on_close&.call if close_client
    end

    def begin_write(sequence)
      @mutex.synchronize do
        until @closed || @next_write_sequence == sequence
          @condition.wait(@mutex)
        end
        raise ConnectionError if @closed
        @writing_sequence = sequence
      end
    end

    def end_write(sequence, keep_alive)
      close_client = false
      @mutex.synchronize do
        return unless @writing_sequence == sequence
        @writing_sequence = nil
        @next_write_sequence += 1
        @closed = !keep_alive
        close_client = ready_to_close_locked?
        @condition.broadcast
      end
      @on_close&.call if close_client
    end

    def fail_output(sequence)
      close_client = false
      @mutex.synchronize do
        return unless @writing_sequence == sequence
        @writing_sequence = nil
        @closed = true
        @next_write_sequence += 1
        finish_parser_locked
        close_client = ready_to_close_locked?
        @condition.broadcast
      end
      @on_close&.call if close_client
    end

    def hijack(sequence)
      @mutex.synchronize do
        @closed = true
        finish_parser_locked
        @next_write_sequence = sequence
        @condition.broadcast

        until @completed_sequence >= sequence && @active_requests == 1
          @condition.wait(@mutex)
        end
        @writing_sequence = sequence
        @async = true
        @socket
      end
    end

    def async(sequence)
      @mutex.synchronize do
        until @closed || @next_write_sequence == sequence
          @condition.wait(@mutex)
        end
        raise ConnectionError if @closed
        @writing_sequence = sequence
        @async_after_write = true
      end
    end

    def async_after_write(sequence)
      @mutex.synchronize do
        return unless @writing_sequence == sequence
        @closed = true
        @async = true
        finish_parser_locked
        @condition.broadcast
      end
    end

    private

    def finish_parser_locked
      @state = :closed
      @continuation = nil
    end

    def resume_continuation_locked
      return nil unless @state == :continuation && @continuation
      return nil if @closed
      if @barrier_sequence
        return nil unless @completed_sequence > @barrier_sequence
      elsif @active_requests >= @max_requests
        return nil
      end

      client = @continuation
      @continuation = nil
      @state = :running
      client
    end

    def ready_to_close_locked?
      @closed && !@async && @state == :closed && @continuation.nil? &&
        @active_requests.zero?
    end
  end
end
