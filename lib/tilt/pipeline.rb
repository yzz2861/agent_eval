require_relative 'template'

module Tilt
  # Superclass used for pipeline templates.  Should not be used directly.
  class Pipeline < Template
    # Optional return value for a pipeline stage that can map lines in
    # its output back to lines in its input.  Stages that only return a
    # String (the common case) are treated as having no line mapping,
    # and positions inside their output are reported as intermediate
    # text instead of being guessed.
    class StageOutput
      # The rendered output of the stage, used as input for the next
      # stage in the pipeline.
      attr_reader :text

      # Maps a 1-based line number in #text to the 1-based line number
      # in the stage's input it was derived from.  Any object responding
      # to #[] (such as a Hash) can be used.  Output lines without an
      # entry cannot be mapped back.
      attr_reader :line_mapping

      def initialize(text, line_mapping)
        @text = text
        @line_mapping = line_mapping
      end
    end

    # Error raised when a stage of the pipeline fails.  The exception
    # raised by the stage itself is preserved and available via #cause.
    class StageError < StandardError
      # Name of the failing stage.  For nested pipelines this is a
      # >-separated path from the outermost to the innermost stage.
      attr_reader :stage_name

      # 1-based index of the failing stage inside its pipeline.
      attr_reader :stage_index

      # 1-based line in the failing stage's input (the output of the
      # preceding stages) where the error occurred, or nil if the
      # position could not be confirmed.
      attr_reader :output_line

      # 1-based line in the pipeline's template source corresponding
      # to #output_line, or nil when the position is in intermediate
      # text that cannot be mapped back to the template source.
      attr_reader :input_line

      # The file of the pipeline template, if any.
      attr_reader :file

      def initialize(stage_name, stage_index, output_line, input_line, file=nil)
        @stage_name = stage_name
        @stage_index = stage_index
        @output_line = output_line
        @input_line = input_line
        @file = file
        super(build_message)
      end

      # Returns a copy of this error for a failing stage of a nested
      # pipeline, with the outer stage name prepended to the stage path
      # and the template source line translated through the outer
      # pipeline's line mappings.
      def nested_in(outer_stage_name, input_line)
        self.class.new("#{outer_stage_name}>#{stage_name}", stage_index, output_line, input_line, file)
      end

      private

      def build_message
        message = +"pipeline stage #{stage_index} (#{stage_name}) failed"
        message << " in #{file}" if file
        if output_line
          message << " at line #{output_line} of the stage input"
          if input_line
            message << " (line #{input_line} of the template source)"
          else
            message << " (intermediate text, template source line unknown)"
          end
        else
          message << " (line in stage input unknown)"
        end
        message
      end
    end

    def prepare
      @stages = self.class::TEMPLATES.each_with_index.map do |entry, index|
        klass, options, name = entry
        name ||= klass.name || "stage #{index + 1}"
        [name.to_s, klass, options]
      end
    end

    def evaluate(scope, locals, &block)
      text = data
      # Line mappings of finished stages, each mapping a line in the
      # stage's output back to a line in the stage's input.
      mappings = []

      @stages.each_with_index do |(name, klass, options), index|
        begin
          stage = klass.new(file, line, options) { |*| text }
          result = stage.render(scope, locals, &block)
        rescue StageError => error
          # A nested pipeline failed.  Prepend this stage's name to the
          # stage path, and translate the source line through this
          # pipeline's mappings, since the nested pipeline's input is
          # intermediate text from this pipeline's point of view.
          nested = error.nested_in(name, source_line_for(error.input_line, index, mappings))
          nested.set_backtrace(error.backtrace)
          raise nested
        rescue StandardError, ScriptError => error
          raise stage_error(error, name, index, stage, mappings)
        end

        if result.is_a?(StageOutput)
          text = result.text
          mappings << result.line_mapping
        else
          text = result
          mappings << nil
        end
      end

      text
    end

    private

    # Builds a StageError for +error+ raised by the stage at +index+,
    # keeping the original backtrace.  The original exception is
    # preserved as the cause since this is called from a rescue block.
    def stage_error(error, name, index, stage, mappings)
      output_line = stage && error_output_line(error, stage)
      StageError.new(name, index + 1, output_line, source_line_for(output_line, index, mappings), file).tap do |error_with_stage|
        error_with_stage.set_backtrace(error.backtrace)
      end
    end

    # Best-effort extraction of the 1-based line in the stage's input
    # where the error occurred, from backtrace frames or an error
    # message referring to the stage's eval file.  Returns nil when no
    # position can be confirmed.
    def error_output_line(error, stage)
      pattern = /#{Regexp.escape(stage.eval_file)}:(\d+)/
      if (backtrace = error.backtrace)
        backtrace.each do |frame|
          return $1.to_i - stage.line + 1 if frame =~ pattern
        end
      end
      return $1.to_i - stage.line + 1 if error.message =~ pattern
      nil
    end

    # Translates a 1-based line in the input of the stage at +index+
    # back to a 1-based line in the pipeline's template source, using
    # the line mappings of the preceding stages.  Returns nil if any
    # preceding stage did not provide a mapping for the line, in which
    # case the position is in intermediate text.
    def source_line_for(line, index, mappings)
      return nil unless line
      (index - 1).downto(0) do |i|
        mapping = mappings[i]
        return nil unless mapping
        line = mapping[line]
        return nil unless line
      end
      line
    end
  end
end
