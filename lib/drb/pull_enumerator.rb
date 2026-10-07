# frozen_string_literal: false
require 'drb/drb'

module DRb
  # Server side of a batched, pull-based enumerator proxy.
  #
  # Wrapping a report-style enumerable with PullEnumerator lets remote
  # clients consume it in batches instead of one DRb round trip per
  # element (per-element +next+) or one giant marshalled array (+to_a+).
  #
  # The wrapped object is only advanced when a client pulls, and every
  # PullEnumerator#open_cursor gets an independent read position, so
  # nested iterations never share state.  Cursors are released when the
  # client finishes, breaks, closes, or disappears (idle cursors are
  # reaped when new cursors are opened or via #close_idle!).
  #
  #   # server
  #   reports = DRb::PullEnumerator.new(-> { Report.each_row })
  #   DRb.start_service(uri, reports)
  #
  #   # client
  #   rows = DRb::RemoteEnumerable.new(DRbObject.new_with_uri(uri),
  #                                    batch_size: 50)
  #   rows.each { |row| ... }
  #
  # Pass a factory (callable) for one-shot sources so every cursor gets
  # a fresh enumerator; a re-iterable enumerable may be given directly.
  class PullEnumerator
    include DRbUndumped

    # Seconds a cursor may sit idle before it is reaped.  Reaping is how
    # cursors whose client crashed or disconnected get released.
    DEFAULT_IDLE_TIMEOUT = 300

    # Raised (and delivered to the client) when one element alone is
    # larger than the agreed per-batch byte limit.
    class ElementTooLarge < StandardError
      attr_reader :size, :max_bytes

      def initialize(size, max_bytes)
        @size = size
        @max_bytes = max_bytes
        super("element of #{size} bytes exceeds the batch byte limit of #{max_bytes} bytes")
      end
    end

    # Raised when pulling from a cursor that has already been closed.
    class ClosedCursor < StandardError; end

    # One response to a pull request.  +items+ holds every element
    # produced before the batch filled up, the source was exhausted, or
    # an error occurred; elements already produced are therefore never
    # confused with the failure position.  When +done?+ is true, +result+
    # carries the source's StopIteration result (the return value of its
    # +each+).  +error+ is set when the source or the framing itself
    # failed mid-batch.
    class Batch
      attr_reader :items, :result, :error

      def initialize(items, done, result, error)
        @items = items
        @done = done
        @result = result
        @error = error
      end

      def done?
        @done
      end
    end

    def initialize(source = nil, idle_timeout: DEFAULT_IDLE_TIMEOUT, &factory)
      factory ||= source if source.respond_to?(:call) && !source.respond_to?(:each)
      factory ||= -> { source } unless source.nil?
      raise ArgumentError, 'pass an enumerable source or a factory block' unless factory
      @factory = factory
      @idle_timeout = idle_timeout
      @cursors = []
      @mutex = Mutex.new
    end

    # Opens an independent cursor over the source.  Called by
    # RemoteEnumerable#each; rarely called directly.
    def open_cursor
      close_idle!
      cursor = Cursor.new(@factory.call, ->(c) { release(c) })
      @mutex.synchronize { @cursors << cursor }
      cursor
    end

    def active_cursor_count
      @mutex.synchronize { @cursors.size }
    end

    # Closes cursors that have been idle for +idle_timeout+ seconds
    # (defaults to the timeout given at construction).  Returns the
    # number of cursors closed.
    def close_idle!(idle_timeout = @idle_timeout)
      return 0 unless idle_timeout
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      stale = @mutex.synchronize do
        @cursors.select { |cursor| cursor.idle_for?(now, idle_timeout) }
      end
      stale.each(&:close)
      stale.size
    end

    private

    def release(cursor)
      @mutex.synchronize { @cursors.delete(cursor) }
    end

    # A single read position over the source.  The source is driven from
    # a private fiber so that closing the cursor unwinds the generator
    # and runs its +ensure+ blocks deterministically.
    class Cursor
      include DRbUndumped

      # Internal signal used to unwind the generator fiber on close.
      class CloseSignal < StandardError; end

      # Internal marker yielded by the fiber when the source is
      # exhausted; carries the StopIteration result.
      class Done
        attr_reader :result

        def initialize(result)
          @result = result
        end
      end

      def initialize(enumerable, on_close)
        @on_close = on_close
        @closed = false
        @finished = false
        @pending = nil
        @has_pending = false
        @mutex = Mutex.new
        touch
        @fiber = Fiber.new do
          result = enumerable.each { |item| Fiber.yield(item) }
          Fiber.yield(Done.new(result))
        end
      end

      # Returns the next Batch of at most +max_items+ elements whose
      # marshalled size stays within +max_bytes+.
      def pull(max_items, max_bytes)
        @mutex.synchronize do
          raise ClosedCursor, 'cursor is already closed' if @closed
          touch
          items = []
          bytes = 0
          done = false
          result = nil
          error = nil
          begin
            while items.length < max_items
              break if @finished
              value = @has_pending ? @pending : @fiber.resume
              if value.is_a?(Done)
                @finished = true
                @has_pending = false
                done = true
                result = value.result
                break
              end
              size = Marshal.dump(value).bytesize
              raise ElementTooLarge.new(size, max_bytes) if size > max_bytes
              if !items.empty? && bytes + size > max_bytes
                @pending = value
                @has_pending = true
                break
              end
              @has_pending = false
              items << value
              bytes += size
            end
          rescue StandardError => e
            error = e
          ensure
            finish_close if done || error
          end
          Batch.new(items, done, result, error)
        end
      end

      # Releases the cursor and unwinds the generator so its +ensure+
      # blocks run.  Idempotent.
      def close
        @mutex.synchronize { finish_close }
        true
      end

      def closed?
        @closed
      end

      def idle_for?(now, timeout)
        now - @touched_at >= timeout
      end

      private

      def touch
        @touched_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def finish_close
        return if @closed
        @closed = true
        terminate_fiber
        @on_close.call(self)
      end

      def terminate_fiber
        return unless @fiber&.alive?
        begin
          @fiber.raise(CloseSignal)
        rescue CloseSignal
          # expected: the generator let the signal propagate
        rescue StandardError
          # a failing ensure in the generator must not break close
        end
      end
    end
  end

  # Client side of the pull enumerator proxy.  Includes Enumerable, so
  # the whole Enumerable API (+map+, +select+, +take+, ...) works while
  # elements are fetched from the server in batches.
  #
  #   rows = DRb::RemoteEnumerable.new(proxy, batch_size: 50,
  #                                           max_bytes: 256 * 1024)
  #   rows.select { |row| row.flagged? }
  #
  # Every #each opens a fresh server-side cursor, so nested iterations
  # are independent.  The cursor is released when iteration completes,
  # is interrupted by +break+/an exception, or #close is called.
  class RemoteEnumerable
    include Enumerable

    DEFAULT_BATCH_SIZE = 100
    DEFAULT_MAX_BYTES = 1 << 20

    attr_reader :batch_size, :max_bytes

    def initialize(source, batch_size: DEFAULT_BATCH_SIZE, max_bytes: DEFAULT_MAX_BYTES)
      @source = source
      @batch_size = batch_size
      @max_bytes = max_bytes
      @cursor = nil
      @mutex = Mutex.new
    end

    # Yields every element, fetching +batch_size+ elements (bounded by
    # +max_bytes+) per round trip.  Returns the source's StopIteration
    # result on normal completion.
    def each
      return to_enum(:each) unless block_given?
      cursor = @source.open_cursor
      @mutex.synchronize { @cursor = cursor }
      begin
        loop do
          batch = cursor.pull(@batch_size, @max_bytes)
          batch.items.each { |item| yield item }
          raise batch.error if batch.error
          return batch.result if batch.done?
        end
      ensure
        @mutex.synchronize { @cursor = nil }
        begin
          cursor.close
        rescue DRb::DRbError
          # the connection is gone; the server reaps the idle cursor
        end
      end
    end

    # Releases the cursor of an in-progress iteration early.
    def close
      cursor = @mutex.synchronize { @cursor }
      cursor&.close
      nil
    end
  end
end
