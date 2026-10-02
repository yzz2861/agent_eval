require_relative 'template'

module Tilt
  # Superclass used for pipeline templates.  Should not be used directly.
  class Pipeline < Template
    # Raised when the bytes flowing between two pipeline stages do not
    # satisfy the declared +:input_encoding+ or +:output_encoding+.  Inherits
    # from EncodingError so existing +rescue EncodingError+ handlers work.
    class EncodingError < EncodingError
      # Pipeline stage that failed.  Stages are numbered starting at 1, in
      # the order in which they are executed.
      attr_reader :stage

      # File extension of the template engine used by the failing stage.
      attr_reader :extension

      # Whether the bytes were checked on the way into (+:input+) or on the
      # way out of (+:output+) the failing stage.
      attr_reader :phase

      # Zero-based byte offset of the first invalid/unconvertible byte.
      attr_reader :byte_offset

      def initialize(stage, extension, phase, byte_offset, reason)
        @stage = stage
        @extension = extension
        @phase = phase
        @byte_offset = byte_offset
        super("pipeline stage #{stage} (#{extension}) #{phase} encoding #{reason} at byte #{byte_offset}")
      end
    end

    # @private
    class Stage
      attr_reader :index, :extension, :klass, :options, :input_encoding, :output_encoding

      def initialize(index, extension, klass, options)
        @index = index
        @extension = extension
        @klass = klass
        @options = options.dup
        @input_encoding = resolve_encoding(@options.delete(:input_encoding))
        @output_encoding = resolve_encoding(@options.delete(:output_encoding))
      end

      def call(previous, file, line, scope, locals, &block)
        input = coerce(previous, input_encoding, :input)

        output = klass.new(file, line, options) do
          input
        end.render(scope, locals, &block)

        coerce(output, output_encoding, :output)
      end

      private

      def resolve_encoding(encoding)
        return nil if encoding.nil?
        encoding = Encoding.find(encoding) unless encoding.is_a?(Encoding)
        encoding
      rescue ArgumentError
        raise ArgumentError, "pipeline stage #{index} (#{extension}) uses unknown encoding: #{encoding.inspect}"
      end

      def coerce(string, declared, phase)
        return string if declared.nil?

        if string.encoding != declared
          if string.encoding == Encoding::BINARY
            # A binary string carries raw bytes from an engine that does
            # not tag its output.  Declaring an encoding only labels the
            # bytes; it never transcodes or repairs them.  Copy the bytes
            # into a fresh buffer so the engine's own string (frozen or
            # not) is never mutated.
            labeled = String.new
            labeled.force_encoding(Encoding::BINARY) << string
            string = labeled.force_encoding(declared)
          else
            return transcode(string, declared, phase)
          end
        end

        validate(string, declared, phase)
        string
      end

      def transcode(string, declared, phase)
        converter = Encoding::Converter.new(string.encoding, declared)
        probe = string.dup
        destination = String.new
        result = converter.primitive_convert(probe, destination)

        if result != :finished
          error = converter.primitive_errinfo
          consumed = string.bytesize - probe.bytesize
          bad_bytes = error[3].bytesize
          offset = result == :undefined_conversion ? consumed - bad_bytes : consumed
          reason = if result == :undefined_conversion
            "cannot transcode #{string.encoding.name} to #{declared.name}"
          else
            "produced bytes that are not valid #{string.encoding.name}"
          end
          raise Pipeline::EncodingError.new(index, extension, phase, offset, reason)
        end

        # String#encode also raises InvalidByteSequenceError and
        # UndefinedConversionError; it never substitutes replacement
        # characters silently.
        string.encode(declared)
      end

      def validate(string, encoding, phase)
        return if string.valid_encoding?

        # Find the first byte that cannot be part of a valid prefix.
        low = 0
        high = string.bytesize
        while low < high
          middle = (low + high + 1) / 2
          if string.byteslice(0, middle).valid_encoding?
            low = middle
          else
            high = middle - 1
          end
        end

        raise Pipeline::EncodingError.new(index, extension, phase, low,
          "produced bytes that are not valid #{encoding.name}")
      end
    end

    def prepare
      innermost = proc { |*| data }

      @pipeline = self.class::TEMPLATES.each_with_index.inject(innermost) do |previous, (entry, position)|
        extension, klass, options = entry
        stage = Stage.new(position + 1, extension, klass, options)

        proc do |scope, locals, &block|
          input = previous.call(scope, locals, &block)
          stage.call(input, file, line, scope, locals, &block)
        end
      end
    end

    def evaluate(scope, locals, &block)
      @pipeline.call(scope, locals, &block)
    end
  end
end
