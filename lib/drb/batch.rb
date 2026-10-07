# frozen_string_literal: false
require 'drb/drb'

module DRb

  # DRb::Batch is an explicit client-side batch builder for DRb calls.
  #
  # A chain such as:
  #
  #   remote.get_account(id).profile.summary
  #
  # normally costs one round trip per call.  With DRb::Batch the calls are
  # recorded first and submitted once; the server executes them in
  # dependency order and returns every result in a single reply:
  #
  #   batch   = DRb::Batch.new(executor)
  #   account = batch.call(remote, :get_account, id)
  #   profile = batch.call(account, :profile)
  #   summary = batch.call(profile, :summary)
  #   pong    = batch.call(remote, :ping)   # independent branch
  #   results = batch.submit                # one round trip
  #
  # Later calls refer to earlier results through DRb::Batch::SlotRef
  # placeholders.  A slot is pure data (a batch token plus an integer
  # index); no Ruby code supplied by the client is ever evaluated on the
  # server.  Forward references, reference cycles and references to slots
  # of another batch are rejected.
  #
  # Execution semantics:
  #
  # * Each recorded call runs at most once, in recording order.  A failed
  #   call is never retried and calls that already ran are never replayed;
  #   a batch is not a transaction and nothing is rolled back.
  # * When a call fails, calls that (transitively) depend on its result are
  #   marked as skipped and keep the original error.  Independent branches
  #   keep running.
  # * Receivers, arguments and return values follow the usual DRb
  #   pass-by-value / pass-by-reference rules (see DRbUndumped): each
  #   result that cannot be marshalled is exported individually as a
  #   DRbObject reference, so one undumpable value never turns the whole
  #   result array into a remote proxy.
  #
  # The server side must expose the +execute_batch+ entry point, easiest by
  # including DRb::Batch::Executor into the front object:
  #
  #   class Front
  #     include DRb::Batch::Executor
  #     ...
  #   end
  #
  class Batch

    # Raised for malformed batches: forward references, reference cycles,
    # slots of another batch, or use after submission.
    class BatchError < StandardError; end

    # A restricted placeholder referring to the result of a previously
    # recorded call in the same batch.  It carries only a batch token and
    # an integer index, and is marshalled by value.
    class SlotRef
      attr_reader :token, :index

      def initialize(token, index)
        @token = token
        @index = index
      end

      def inspect
        "#<DRb::Batch::SlotRef index=#{@index}>"
      end
    end

    # The outcome of a single recorded call.  +status+ is one of :ok,
    # :error or :skipped.  For :error and :skipped, +error+ holds the
    # original exception raised by the failed call.
    class Result
      attr_reader :status, :value, :error

      def initialize(status, value = nil, error = nil)
        @status = status
        @value = value
        @error = error
      end

      def ok?
        @status == :ok
      end

      def skipped?
        @status == :skipped
      end

      def failed?
        @status == :error
      end
    end

    # Substitute raised on the server when the original exception cannot be
    # marshalled back to the client.
    class RemoteError < StandardError
      attr_reader :original_class

      def initialize(original_class, message)
        @original_class = original_class
        super("#{original_class}: #{message}")
      end
    end

    # Server-side executor for batches built with DRb::Batch.  Include it
    # into the object that should accept batches (typically the front
    # object of the DRb server).
    module Executor
      # Executes the recorded calls in dependency order and returns an
      # Array of DRb::Batch::Result, one per call.  Every call runs at
      # most once; there is no retry and no rollback.
      def execute_batch(token, ops)
        plan = ops.map do |receiver, name, args|
          { receiver: receiver, name: name.to_sym, args: args, deps: [] }
        end

        plan.each_with_index do |step, pos|
          each_slot(step[:receiver]) do |slot|
            check_slot(slot, token, pos)
            step[:deps] << slot.index
          end
          each_slot(step[:args]) do |slot|
            check_slot(slot, token, pos)
            step[:deps] << slot.index
          end
          step[:deps].uniq!
        end

        results = []
        plan.each do |step|
          blocker = step[:deps].map { |d| results[d] }.find { |r| !r.ok? }
          if blocker
            results << Result.new(:skipped, nil, blocker.error)
            next
          end
          begin
            receiver = resolve_slots(step[:receiver], results)
            args = resolve_slots(step[:args], results)
            value = receiver.__send__(step[:name], *args)
            results << Result.new(:ok, export_value(value))
          rescue Exception => e
            results << Result.new(:error, nil, safe_error(e))
          end
        end
        results
      end

      private

      def each_slot(obj, &block)
        case obj
        when SlotRef
          yield obj
        when Array
          obj.each { |e| each_slot(e, &block) }
        when Hash
          obj.each { |k, v| each_slot(k, &block); each_slot(v, &block) }
        end
      end

      def check_slot(slot, token, pos)
        unless slot.token == token
          raise BatchError, "slot #{slot.index} belongs to a different batch"
        end
        unless slot.index.is_a?(Integer) && slot.index >= 0 && slot.index < pos
          raise BatchError, "invalid slot reference #{slot.index} at position #{pos} (forward reference or cycle)"
        end
      end

      def resolve_slots(obj, results)
        case obj
        when SlotRef
          results[obj.index].value
        when Array
          obj.map { |e| resolve_slots(e, results) }
        when Hash
          obj.each_with_object({}) do |(k, v), h|
            h[resolve_slots(k, results)] = resolve_slots(v, results)
          end
        else
          obj
        end
      end

      def safe_error(error)
        Marshal.dump(error)
        error
      rescue TypeError
        RemoteError.new(error.class.name, error.message)
      end

      # Keeps the usual DRb pass-by-value / pass-by-reference rules per
      # result: values that cannot be marshalled (e.g. DRbUndumped
      # objects) are exported as a DRbObject reference instead.
      def export_value(value)
        Marshal.dump(value)
        value
      rescue StandardError
        DRb::DRbObject.new(value)
      end
    end

    attr_reader :token

    # Creates an empty batch.  +executor+ is a (usually remote) object
    # exposing +execute_batch+, e.g. a DRbObject for a front object that
    # includes DRb::Batch::Executor.
    def initialize(executor)
      @executor = executor
      @token = "#{Process.pid}:#{object_id}:#{rand(1 << 62)}"
      @steps = []
      @submitted = false
    end

    # Records a call of +name+ on +receiver+ with +args+.  The receiver and
    # the arguments may contain SlotRef placeholders returned by earlier
    # #call invocations of this batch.  Returns a SlotRef identifying the
    # result of this call.
    def call(receiver, name, *args)
      raise BatchError, "batch has already been submitted" if @submitted
      validate_slots!(receiver)
      validate_slots!(args)
      slot = SlotRef.new(@token, @steps.length)
      @steps << [receiver, name.to_sym, args]
      slot
    end

    # Number of recorded calls.
    def size
      @steps.size
    end

    # Submits the recorded calls to the executor in a single request and
    # returns an Array of DRb::Batch::Result in recording order.  A batch
    # can be submitted only once.
    def submit
      raise BatchError, "batch has already been submitted" if @submitted
      @submitted = true
      ops = @steps.map { |receiver, name, args| [receiver, name, args] }
      @executor.execute_batch(@token, ops)
    end

    private

    def validate_slots!(obj)
      case obj
      when SlotRef
        unless obj.token == @token
          raise BatchError, "slot #{obj.index} belongs to a different batch"
        end
        unless obj.index.is_a?(Integer) && obj.index >= 0 && obj.index < @steps.length
          raise BatchError, "slot #{obj.index} does not refer to a previously recorded call (forward reference or cycle)"
        end
      when Array
        obj.each { |e| validate_slots!(e) }
      when Hash
        obj.each { |k, v| validate_slots!(k); validate_slots!(v) }
      end
    end
  end
end
