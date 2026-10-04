# frozen_string_literal: true

module Liquid
  # An output destination that forwards every rendered chunk to a caller
  # supplied sink, so templates can be rendered without materializing the whole
  # result into one giant String.
  #
  # It quacks enough like a String (+<<+, +bytesize+) to be passed through the
  # existing +render_to_output_buffer+ pipeline. Content is delivered to the
  # sink as soon as the node that produced it has finished rendering, which
  # means plain text, variables and loop iterations can reach the caller while
  # the rest of the template is still executing.
  #
  # Tags that genuinely need the complete value of their body (e.g. capture)
  # keep rendering into their own local String buffers and only push their
  # finished result here, so the final output stays incremental while local
  # buffering remains bounded independently.
  class StreamingOutput
    # Mixin used to tag exceptions raised by the sink. It lets a tagged
    # exception survive the per-node error handling (which would otherwise turn
    # it into rendered Liquid error text and re-invoke the sink) and propagate
    # all the way out of the render, unwinding every context stack on the way.
    module SinkError
    end

    attr_reader :sink, :bytesize

    # @param sink [#call] receives each rendered String chunk as its argument
    def initialize(sink)
      @sink     = sink
      @bytesize = 0
    end

    # Forwards +content+ to the sink immediately and returns self so that it
    # can be used as a drop-in replacement for a String output buffer.
    def <<(content)
      return self if content.nil?
      chunk = case content
      when Integer
        content.chr(Encoding::UTF_8)
      else
        content.respond_to?(:to_str) ? content.to_str : content.to_s
      end
      unless chunk.empty?
        @bytesize += chunk.bytesize
        begin
          @sink.call(chunk)
        rescue SinkError
          raise # already tagged (e.g. the sink re-raised a previous failure)
        rescue => e
          e.extend(SinkError)
          raise
        end
      end
      self
    end

    # Nothing is retained; +to_s+ is only there for compatibility with code
    # paths that stringify the output buffer.
    def to_s
      ''
    end

    alias_method :to_str, :to_s
  end
end
