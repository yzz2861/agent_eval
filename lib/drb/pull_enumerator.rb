# frozen_string_literal: false
require_relative 'drb'

module DRb

  # A pull-based, batch Enumerable for use over DRb.
  #
  # A server-side object is created from an object that responds to #to_enum
  # or from a generator block.  When transferred over DRb, it becomes a
  # client-side proxy.  Each iteration opens an independent server cursor,
  # so nested or repeated iterations do not share a read position.  Cursors
  # are released when iteration stops, when the proxy is closed, or when the
  # DRb connection handling the cursor ends.
  class PullEnumerator
    include Enumerable

    DEFAULT_BATCH_SIZE = 100
    DEFAULT_BYTE_LIMIT = 1 << 20

    class ElementTooLargeError < DRbError; end

    def self.stop_enumerator(enumerator)
      return enumerator.close if enumerator.respond_to?(:close)
      enumerator.each { break } rescue nil
    end

    class PullBatch
      def initialize(elements=[], result=nil, error=nil, error_index=nil,
                     finished=false)
        @elements = elements
        @result = result
        @error = error
        @error_index = error_index
        @finished = finished
        if @error
          @error.instance_variable_set(:@pull_index, error_index) rescue nil
        end
      end

      attr_reader :elements, :result, :error, :error_index

      def finished?
        @finished
      end

      def self._load(data)
        new(*Marshal.load(data))
      end

      def _dump(_limit)
        Marshal.dump([marshalled_elements, @result, @error, @error_index,
                      @finished])
      end

      private

      def marshalled_elements
        @elements.collect do |element|
          if element.kind_of?(DRbUndumped)
            DRbObject.new(element)
          else
            begin
              Marshal.dump(element)
              element
            rescue
              DRbObject.new(element)
            end
          end
        end
      end
    end

    # Server-side cursor store.
    class CursorRegistry
      def initialize
        @mutex = Mutex.new
        @cursors = {}
        @next_id = 0
      end

      def register(cursor)
        @mutex.synchronize do
          @next_id += 1
          @cursors[@next_id] = cursor
          @next_id
        end
      end

      def fetch(id)
        @mutex.synchronize { @cursors.fetch(id) }
      rescue KeyError
        raise ArgumentError, 'invalid pull enumerator cursor'
      end

      def unregister(id)
        cursor = @mutex.synchronize { @cursors.delete(id) }
        cursor&.close
      end
    end

    # The server half of a pull enumerator.
    class Server < PullEnumerator
      def initialize(enumerable=nil, batch_size: DEFAULT_BATCH_SIZE,
                     byte_limit: DEFAULT_BYTE_LIMIT, &generator)
        if (enumerable.nil? && !block_given?) || (enumerable && block_given?)
          raise ArgumentError, 'pass either an enumerable or a block'
        end
        validate_limit(batch_size, 'batch size')
        validate_limit(byte_limit, 'byte limit')
        if enumerable.is_a?(Enumerator)
          raise ArgumentError,
                'use a re-enumerable object or a block that returns a new enumerator'
        end

        @enumerable = enumerable
        @generator = generator
        @batch_size = batch_size
        @byte_limit = byte_limit
        @cursors = CursorRegistry.new
      end

      attr_reader :batch_size, :byte_limit

      def _dump(_limit)
        proxy = DRbObject.new(self)
        Marshal.dump([proxy.__drburi, proxy.__drbref, @batch_size,
                      @byte_limit])
      end

      def each(&block)
        return to_enum(__method__) unless block

        cursor = Cursor.new(new_enumerator, @byte_limit)
        result = nil
        begin
          loop do
            batch = cursor.pull(@batch_size)
            batch.elements.each(&block)
            raise batch.error if batch.error
            result = batch.result
            break if batch.finished?
            break if batch.elements.empty?
          end
          result
        ensure
          cursor.close
        end
      end

      def self._load(data)
        Client.new(*Marshal.load(data))
      end

      def open_cursor(requested_batch_size=nil)
        resolve_batch_size(requested_batch_size)
        cursor = Cursor.new(new_enumerator, @byte_limit)
        id = @cursors.register(cursor)
        track_current_connection(id)
        id
      end

      def pull_cursor(handle, requested_batch_size=nil)
        batch_size = resolve_batch_size(requested_batch_size)
        @cursors.fetch(handle).pull(batch_size)
      end

      def close_cursor(handle)
        @cursors.unregister(handle)
        drb = Thread.current['DRb']
        drb['pull_enumerator_servers']&.delete([self, handle])
        nil
      end

      def track_current_connection(id)
        drb = Thread.current['DRb']
        return unless drb && drb['client']

        drb['pull_enumerator_servers'] ||= []
        handle = [self, id]
        drb['pull_enumerator_servers'] << handle unless
          drb['pull_enumerator_servers'].include?(handle)
      end

      private

      def validate_limit(value, name)
        unless value.is_a?(Integer) && value > 0
          raise ArgumentError, "#{name} must be a positive Integer"
        end
      end

      def resolve_batch_size(requested_batch_size)
        return @batch_size if requested_batch_size.nil?
        validate_limit(requested_batch_size, 'batch size')
        [requested_batch_size, @batch_size].min
      end

      def new_enumerator
        @enumerable ? @enumerable.to_enum : Enumerator.new(&@generator)
      end

      class Cursor
        def initialize(enumerator, byte_limit)
          @enumerator = enumerator
          @byte_limit = byte_limit
          @pending = nil
          @produced_count = 0
          @closed = false
          @finished = false
          @stopped = false
          @mutex = Mutex.new
        end

        def pull(batch_size)
          stop_after_batch = false
          oversized_batch = nil
          batch = @mutex.synchronize do
            raise IOError, 'closed pull enumerator cursor' if @closed

            elements = []
            error = nil
            error_index = nil
            result = nil
            finished = false

            if @pending
              elements << @pending
              @pending = nil
              @produced_count += 1
              size = element_byte_size(elements.last)
              if size > @byte_limit
                close!
                stop_after_batch = true
                oversized_batch = PullBatch.new(
                  [], nil,
                  ElementTooLargeError.new(
                    "element size #{size} exceeds byte limit #{@byte_limit}"),
                  @produced_count, true
                )
                break
              end
            end

            begin
              while elements.size < batch_size
                element = @enumerator.next
                size = element_byte_size(element)
                if size > @byte_limit
                  close!
                  stop_after_batch = true
                  error = ElementTooLargeError.new(
                    "element size #{size} exceeds byte limit #{@byte_limit}")
                  error_index = @produced_count
                  break
                end
                if !elements.empty? &&
                   batch_byte_size(elements + [element]) > @byte_limit
                  @pending = element
                  break
                end
                elements << element
                @produced_count += 1
              end
            rescue StopIteration => stop
              result = stop.result
              finished = true
              @finished = true
              @stopped = true
            rescue Exception => source_error
              close!
              error = source_error
              error_index = @produced_count
              @stopped = true
            end

            oversized_batch ||
              PullBatch.new(elements, result, error, error_index, finished)
          end
          PullEnumerator.stop_enumerator(@enumerator) if stop_after_batch
          batch
        end

        def close
          should_close = @mutex.synchronize do
            return if @closed
            @closed = true
            !@stopped
          end
          PullEnumerator.stop_enumerator(@enumerator) if should_close
          nil
        rescue Exception
          nil
        end

        def close!
          @closed = true
        end

        private

        def element_byte_size(element)
          Marshal.dump(element).bytesize
        rescue
          Marshal.dump(DRbObject.new(element)).bytesize
        end

        def batch_byte_size(elements)
          Marshal.dump(elements).bytesize
        rescue
          elements.inject(6) do |total, element|
            total + element_byte_size(element)
          end
        end
      end
    end

    # The client half of a pull enumerator.
    class Client < PullEnumerator
      def initialize(uri, ref=nil, batch_size=DEFAULT_BATCH_SIZE,
                     byte_limit=DEFAULT_BYTE_LIMIT)
        @server = if uri.nil?
                    ref
                  else
                    DRbObject.new_with(uri, ref)
                  end
        @batch_size = batch_size
        @byte_limit = byte_limit
        @mutex = Mutex.new
        @active_cursors = []
      end

      attr_reader :batch_size, :byte_limit

      def each(&block)
        return to_enum(__method__) unless block

        cursor = @server.open_cursor(@batch_size)
        register_cursor(cursor)
        result = nil
        begin
          loop do
            batch = @server.pull_cursor(cursor, @batch_size)
            if batch.error
              raise batch.error
            end
            batch.elements.each(&block)
            result = batch.result
            if batch.finished?
              break
            end
            break if batch.elements.empty?
          end
          result
        ensure
          close_cursor(cursor)
        end
      end

      def close
        @mutex.synchronize { @active_cursors.dup }.each do |cursor|
          close_cursor(cursor)
        end
        nil
      end

      def open_cursor(batch_size=nil)
        @server.open_cursor(batch_size || @batch_size)
      end

      def pull_cursor(cursor, batch_size=nil)
        @server.pull_cursor(cursor, batch_size || @batch_size)
      end

      def close_cursor(cursor)
        @mutex.synchronize { @active_cursors.delete(cursor) }
        @server.close_cursor(cursor)
      rescue DRbConnError, IOError, ArgumentError
        nil
      end

      private

      def register_cursor(cursor)
        @mutex.synchronize { @active_cursors << cursor }
      end
    end
  end
end
