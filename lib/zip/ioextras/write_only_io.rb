# frozen_string_literal: true

module Zip
  module IOExtras
    class WriteOnlyIO
      attr_reader :tell

      def initialize(io)
        @io = io
        @tell = 0
      end

      def <<(data)
        write(data)
        self
      end

      def write(data)
        data = data.to_s.b
        amount = 0

        while amount < data.bytesize
          chunk = data.byteslice(amount, data.bytesize - amount)
          if @io.respond_to?(:write)
            written = @io.write(chunk)
          else
            @io << chunk
            written = chunk.bytesize
          end
          raise IOError, 'short write' unless written.is_a?(Integer) && written.positive?

          amount += written
          @tell += written
        end

        amount
      end

      def binmode
        @io.binmode if @io.respond_to?(:binmode)
        self
      end

      def flush
        @io.flush if @io.respond_to?(:flush)
      end

      def close
        @io.close if @io.respond_to?(:close)
      end
    end
  end
end
