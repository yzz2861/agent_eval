# frozen_string_literal: false
#
# = drb/batch.rb
#
# Explicit batch invocation for dRuby.
#
# A DRb::DRbBatch collects several remote method calls and submits them
# to the server in a single request.  Later calls may refer to the
# results of earlier calls through restricted slot placeholders, so a
# call chain such as:
#
#   remote.get_account(id).profile.summary
#
# can be expressed as:
#
#   batch = DRb::DRbBatch.new(remote)
#   account = batch.call(:get_account, id)
#   profile = batch.call_on(account, :profile)
#   summary = batch.call_on(profile, :summary)
#   results = batch.commit
#   results[summary]
#
# and executed with one network round trip instead of three.
#
# Slots are pure data (a batch token plus an index).  The server never
# evaluates client supplied Ruby code; it only substitutes the value
# produced by the referenced earlier call.
#
# Batches are not transactional: calls that have already run are not
# rolled back when a later call fails, and no call is ever replayed
# automatically.  When a call fails, calls that (transitively) depend
# on it are marked as skipped and keep the original error, while
# independent branches of the batch still run.
#
# Object arguments and results follow the usual dRuby pass-by-value /
# pass-by-reference rules (see DRb::DRbUndumped).

require_relative 'drb' unless defined?(DRb::DRbError)
require 'securerandom'

module DRb

  # Builder for an explicit batch of remote method calls.
  #
  # See the documentation of drb/batch.rb for an overview.
  class DRbBatch

    # Reserved message id used to submit a batch to a server.
    MESSAGE_ID = :__drb_batch__

    # Superclass of all errors raised by DRb::DRbBatch.
    class Error < DRbError; end

    # Raised when a slot reference is invalid.
    class SlotError < Error; end

    # Raised when a call refers to a slot that is produced by a later
    # call in the same batch.
    class ForwardReferenceError < SlotError; end

    # Raised when slot references form a cycle.
    class CyclicReferenceError < SlotError; end

    # Raised when a slot produced by another batch is referenced.
    class CrossBatchReferenceError < SlotError; end

    # Raised by DRbBatch::ResultSet when reading the value of a call
    # that was skipped because one of its dependencies failed.  The
    # original error is available via #original_error.
    class SkippedError < Error
      attr_reader :original_error

      def initialize(original_error)
        @original_error = original_error
        super("call skipped because a dependency failed: " +              "#{original_error.message} (#{original_error.class})")
      end
    end

    # A restricted, data-only placeholder for the result of a call that
    # was added to a batch.  A slot is identified by the token of the
    # batch that produced it and by the position of that call.
    #
    # Slots carry no executable content; the server only uses them as
    # indices into the results it has already computed for the batch.
    class Slot
      # The token of the batch this slot belongs to.
      attr_reader :token

      # The position of the call whose result this slot refers to.
      attr_reader :index

      def initialize(token, index) # :nodoc:
        @token = token
        @index = index
      end

      def ==(other) # :nodoc:
        Slot === other && @token == other.token && @index == other.index
      end
      alias eql? ==

      def hash # :nodoc:
        [@token, @index].hash
      end

      def inspect # :nodoc:
        "#<#{self.class.name}: ##{@index}>"
      end
    end

    # The outcome of a single call of an executed batch.
    #
    # The status is one of :ok, :error or :skipped.  For :ok, #value
    # holds the result of the call.  For :error, #error holds the
    # exception raised by the call.  For :skipped, #error holds the
    # original exception of the failed dependency that caused this
    # call to be skipped.
    class Outcome
      OK = :ok
      ERROR = :error
      SKIPPED = :skipped

      attr_reader :status, :value, :error

      def initialize(status, value = nil, error = nil) # :nodoc:
        @status = status
        @value = value
        @error = error
      end

      def ok?
        @status == OK
      end

      def error?
        @status == ERROR
      end

      def skipped?
        @status == SKIPPED
      end
    end

    # The results of a committed batch, in call order.
    class ResultSet
      include Enumerable

      def initialize(token, outcomes) # :nodoc:
        @token = token
        @outcomes = outcomes
      end

      # The DRbBatch::Outcome for each call, in call order.
      attr_reader :outcomes

      def each(&block)
        @outcomes.each(&block)
      end

      def size
        @outcomes.size
      end

      # The DRbBatch::Outcome of the call identified by +ref+, which
      # may be a DRbBatch::Slot or an Integer position.
      def outcome(ref)
        @outcomes.fetch(position_of(ref))
      end

      # The value of the call identified by +ref+.
      #
      # Raises the original exception if the call failed, and
      # DRbBatch::SkippedError if the call was skipped.
      def [](ref)
        outcome = outcome(ref)
        case outcome.status
        when Outcome::OK
          outcome.value
        when Outcome::ERROR
          raise outcome.error
        else
          raise SkippedError, outcome.error
        end
      end

      private

      def position_of(ref)
        case ref
        when Slot
          unless ref.token == @token
            raise CrossBatchReferenceError,
                  "slot ##{ref.index} belongs to a different batch"
          end
          ref.index
        when Integer
          ref
        else
          raise SlotError, "not a slot: #{ref.inspect}"
        end
      end
    end

    # Executes a batch payload on the server side.  Each call runs at
    # most once, in submission order; nothing is rolled back or
    # replayed when a call fails.
    class Executor # :nodoc:
      def initialize(server)
        @server = server
      end

      def execute(root, payload)
        unless Array === payload && payload.size == 2 && Array === payload[1]
          raise Error, "malformed batch payload"
        end
        token, calls = payload
        values = []
        outcomes = []
        calls.each_with_index do |call, position|
          outcome, raw = execute_call(token, values, outcomes, root, call, position)
          outcomes << outcome
          values << raw
        end
        outcomes
      end

      private

      def execute_call(token, values, outcomes, root, call, position)
        receiver, msg_id, args = call
        unless Array === args
          raise Error, "malformed batch call: ##{position}"
        end

        slots = []
        DRbBatch.each_slot(receiver) { |slot| slots << slot }
        DRbBatch.each_slot(args) { |slot| slots << slot }
        slots.each do |slot|
          dependency = outcomes[slot.index]
          next if dependency.nil? || dependency.ok?
          return [Outcome.new(Outcome::SKIPPED, nil, dependency.error), nil]
        end

        target = receiver.nil? ? root : resolve(receiver, token, values, position)
        argv = resolve(args, token, values, position)
        msg_id = msg_id.to_sym if String === msg_id
        @server.check_insecure_method(target, msg_id)
        raw = target.__send__(msg_id, *argv)
        [Outcome.new(Outcome::OK, export_value(raw)), raw]
      rescue NoMemoryError, SystemExit, SystemStackError, SecurityError
        raise
      rescue Exception
        [Outcome.new(Outcome::ERROR, nil, export_error($!)), nil]
      end

      def resolve(obj, token, values, position)
        case obj
        when Slot
          unless obj.token == token
            raise CrossBatchReferenceError,
                  "slot ##{obj.index} belongs to a different batch"
          end
          unless obj.index.is_a?(Integer) && obj.index >= 0 && obj.index < position
            raise ForwardReferenceError,
                  "slot ##{obj.index} is not available at call ##{position}"
          end
          values[obj.index]
        when Array
          obj.collect { |element| resolve(element, token, values, position) }
        when Hash
          obj.each_with_object({}) do |(key, value), resolved|
            resolved[resolve(key, token, values, position)] =
              resolve(value, token, values, position)
          end
        else
          obj
        end
      end

      # Applies the usual dRuby pass-by-value / pass-by-reference rules
      # to a single result, so that one undumpable value cannot break
      # the reply of the whole batch.
      def export_value(value)
        case value
        when DRbUndumped
          DRbObject.new(value)
        when Object
          begin
            Marshal.dump(value)
            value
          rescue
            DRbObject.new(value)
          end
        else
          DRbObject.new(value)
        end
      end

      def export_error(error)
        Marshal.dump(error)
        error
      rescue
        DRbRemoteError.new(error)
      end
    end

    # A single call added to a batch.
    Call = Struct.new(:receiver, :msg_id, :args) # :nodoc:

    # Enumerates the slots contained in +obj+.  Only slots appearing
    # directly, or nested inside Arrays and Hashes, are recognized;
    # any other object is left untouched.
    def self.each_slot(obj) # :nodoc:
      case obj
      when Slot
        yield obj
      when Array
        obj.each { |element| each_slot(element) { |slot| yield slot } }
      when Hash
        obj.each do |key, value|
          each_slot(key) { |slot| yield slot }
          each_slot(value) { |slot| yield slot }
        end
      end
    end

    # The root remote object the calls of this batch are sent to.
    attr_reader :root

    # The token identifying this batch.
    attr_reader :token

    # Creates a new batch whose root receiver is +root+, normally a
    # DRb::DRbObject.
    def initialize(root)
      unless DRbObject === root
        raise Error, "batch root must be a DRb::DRbObject"
      end
      @root = root
      @token = SecureRandom.hex(16)
      @calls = []
      @committed = false
    end

    # The number of calls added so far.
    def size
      @calls.size
    end

    # Adds a call of +msg_id+ on the root object of the batch and
    # returns the slot that will hold its result.
    def call(msg_id, *args)
      raise Error, "blocks are not supported in batches" if block_given?
      add(nil, msg_id, args)
    end

    # Adds a call of +msg_id+ on +receiver+ (a slot returned by an
    # earlier call of this batch) and returns the slot that will hold
    # its result.
    def call_on(receiver, msg_id, *args)
      raise Error, "blocks are not supported in batches" if block_given?
      add(receiver, msg_id, args)
    end

    # Validates the batch and submits it to the server in a single
    # request, returning a DRbBatch::ResultSet.
    #
    # A batch can be committed only once; results of a failed call are
    # never recomputed and side-effecting calls are never replayed.
    def commit
      raise Error, "batch has already been committed" if @committed
      validate!
      @committed = true

      uri = @root.__drburi
      if DRb.here?(uri)
        server = DRb.current_server
        outcomes = Executor.new(server).execute(DRb.to_obj(@root.__drbref), payload)
        return ResultSet.new(@token, outcomes)
      end

      succ, result = DRbObject.with_friend(uri) do
        DRbConn.open(uri) do |conn|
          conn.send_message(@root, MESSAGE_ID, [payload], nil)
        end
      end

      if succ
        ResultSet.new(@token, result)
      elsif DRbUnknown === result
        raise result
      else
        bt = DRbObject.prepare_backtrace(uri, result)
        result.set_backtrace(bt + caller)
        raise result
      end
    end

    private

    def add(receiver, msg_id, args)
      raise Error, "batch has already been committed" if @committed
      msg_id = normalize_msg_id(msg_id)
      position = @calls.size
      check_slot!(receiver, position) if receiver
      DRbBatch.each_slot(args) { |slot| check_slot!(slot, position) }
      @calls << Call.new(receiver, msg_id, args)
      Slot.new(@token, position)
    end

    def normalize_msg_id(msg_id)
      case msg_id
      when Symbol
        msg_id
      when String
        msg_id.to_sym
      else
        raise Error, "method name must be a Symbol or String: #{msg_id.inspect}"
      end
    end

    def check_slot!(slot, position)
      unless Slot === slot
        raise SlotError, "not a slot: #{slot.inspect}"
      end
      unless slot.token == @token
        raise CrossBatchReferenceError,
              "slot ##{slot.index} belongs to a different batch"
      end
      unless slot.index.is_a?(Integer) && slot.index >= 0 && slot.index < position
        raise ForwardReferenceError,
              "slot ##{slot.index} is not available at call ##{position}"
      end
    end

    def validate!
      check_cycles!
      @calls.each_with_index do |call, position|
        check_slot!(call.receiver, position) if call.receiver
        DRbBatch.each_slot(call.args) { |slot| check_slot!(slot, position) }
      end
    end

    def check_cycles!
      dependencies = @calls.collect do |call|
        slots = []
        DRbBatch.each_slot(call.receiver) { |slot| slots << slot.index }
        DRbBatch.each_slot(call.args) { |slot| slots << slot.index }
        slots
      end
      state = {}
      visit = lambda do |position|
        case state[position]
        when :visiting
          raise CyclicReferenceError,
                "cyclic slot reference involving call ##{position}"
        when nil
          state[position] = :visiting
          dependencies[position].each do |dep|
            visit.call(dep) if dep.is_a?(Integer) && dep >= 0 && dep < dependencies.size
          end
          state[position] = :done
        end
      end
      dependencies.each_index { |position| visit.call(position) }
    end

    def payload
      [@token, @calls.collect { |call| [call.receiver, call.msg_id, call.args] }]
    end
  end
end
