# frozen_string_literal: true

module Liquid
  # Output buffer used by Template#render_to. Instead of accumulating the
  # whole template output into one big String, every chunk written to this
  # buffer is forwarded to a caller-provided sink immediately.
  #
  # The sink can be:
  # * a callable responding to +#call+ (e.g. a Proc),
  # * an IO-like object responding to +#write+,
  # * or any object responding to +#<<+ (e.g. an Array or a String).
  #
  # Tags that genuinely need a complete value (like {% capture %} or
  # {% ifchanged %}) still render into their own local String buffers, so
  # only those fragments are ever materialized in full.
  class StreamOutput
    def initialize(sink)
      @writer = if sink.respond_to?(:call)
        sink
      elsif sink.respond_to?(:write)
        ->(chunk) { sink.write(chunk) }
      elsif sink.respond_to?(:<<)
        ->(chunk) { sink << chunk }
      else
        raise ArgumentError, "output sink must respond to #call, #write or #<<"
      end
      @bytesize = 0
    end

    # Total number of bytes emitted to the sink so far. ResourceLimits uses
    # this to enforce +render_length_limit+ on the final output, even though
    # the emitted chunks themselves are not retained.
    attr_reader :bytesize

    def <<(chunk)
      chunk = chunk.to_s
      return self if chunk.empty?

      @bytesize += chunk.bytesize
      emit(chunk)
      self
    end

    private

    def emit(chunk)
      @writer.call(chunk)
    rescue SinkError
      raise
    rescue => e
      raise SinkError, "Liquid output sink failed: #{e.message} (#{e.class})"
    end
  end
end
