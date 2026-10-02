require_relative 'template'

module Tilt
  # Superclass used for pipeline templates.  Should not be used directly.
  #
  # Pipelines provide diagnostics for their stages.  Each stage has a
  # stable name, and a stage template may optionally provide a line
  # mapping (via a #line_mapping method returning a Hash, Array, or
  # callable) translating its output line numbers back to its input
  # line numbers.  When a stage raises an exception, the pipeline
  # raises a StageError that preserves the original exception as its
  # #cause and reports the confirmable stage name, input position, and
  # output position.  Positions that cannot be mapped back to the
  # template source are explicitly marked as intermediate text; the
  # pipeline never guesses line numbers in the original file.
  class Pipeline < Template
    # A position reported by pipeline stage diagnostics.  A position is
    # either a confirmed location in the template source file, or a
    # location in intermediate text produced by a pipeline stage.
    class Position
      # Line number (1-based), or nil if the line could not be
      # determined.
      attr_reader :line

      # The text the line refers to: the template file for confirmed
      # source positions, or a description of the intermediate text
      # for positions that could not be mapped back to the source.
      attr_reader :source

      def initialize(line, source, intermediate=false)
        @line = line
        @source = source
        @intermediate = intermediate
      end

      # True if this position refers to intermediate text rather than
      # the original template source.
      def intermediate?
        @intermediate
      end

      def ==(other)
        other.instance_of?(Position) && line == other.line &&
          source == other.source && intermediate? == other.intermediate?
      end

      def to_s
        if line
          intermediate? ? "line #{line} of #{source}" : "#{source}:#{line}"
        else
          intermediate? ? "unknown line of #{source}" : source.to_s
        end
      end
    end

    # Error raised when a pipeline stage fails.  The original exception
    # is preserved as the #cause of this error.
    class StageError < StandardError
      # Name of the pipeline stage that failed.  For nested pipelines,
      # the names of the outer and inner stages are joined with '>'.
      attr_reader :stage_name

      # Position in the pipeline's input (the original template
      # source).  Marked as intermediate text if the position could
      # not be mapped back to the source.
      attr_reader :input_position

      # Position in the text the failing stage was processing (the
      # intermediate text, or the original source for the first
      # stage).
      attr_reader :output_position

      # @private
      # Line number in the raising pipeline's own input data, or nil
      # if it could not be confirmed.  Used by outer pipelines to
      # continue mapping positions when pipelines are nested.
      attr_reader :pipeline_input_line

      def initialize(stage_name, input_position, output_position, pipeline_input_line=nil, original=nil)
        @stage_name = stage_name
        @input_position = input_position
        @output_position = output_position
        @pipeline_input_line = pipeline_input_line

        message = "pipeline stage #{stage_name.inspect} failed at #{output_position}"
        message << " (input: #{input_position})" unless input_position == output_position
        message << ": #{original.class}: #{original.message}" if original
        super(message)
      end
    end

    # @private
    # A single stage of the pipeline, wrapping one entry of the
    # TEMPLATES constant with a stable name.
    class Stage
      attr_reader :name

      def initialize(entry, index)
        @template_class, @options, name = entry
        @options ||= {}
        name = @template_class.name if name.nil? && @template_class.respond_to?(:name)
        name = nil if name.respond_to?(:empty?) && name.empty?
        @name = (name || "stage-#{index}").to_s
      end

      def build(file, line, input)
        @template_class.new(file, line, @options, &proc{|*| input})
      end

      def run(template, scope, locals, &block)
        output = template.render(scope, locals, &block)
        line_map = template.line_mapping if template.respond_to?(:line_mapping)
        [output, line_map]
      end
    end

    def prepare
      @stages = self.class::TEMPLATES.each_with_index.map{|entry, index| Stage.new(entry, index + 1)}
    end

    def evaluate(scope, locals, &block)
      input = data
      line_maps = []

      @stages.each_with_index do |stage, index|
        template = nil

        begin
          template = stage.build(file, line, input)
          input, line_map = stage.run(template, scope, locals, &block)
        rescue StageError => error
          raise nested_stage_error(stage, index, error, line_maps)
        rescue StandardError, ScriptError => error
          raise stage_error(stage, index, template, error, line_maps)
        end

        line_maps << line_map
      end

      input
    end

    private

    # Build a StageError for an exception raised by a stage of a
    # nested pipeline, continuing to map the position back through
    # this pipeline's stages.
    def nested_stage_error(stage, index, error, line_maps)
      if error.pipeline_input_line
        input_position, pipeline_input_line = map_back(error.pipeline_input_line, index, line_maps)
      else
        input_position = error.input_position
        pipeline_input_line = nil
      end

      StageError.new("#{stage.name}>#{error.stage_name}", input_position,
        error.output_position, pipeline_input_line)
    end

    # Build a StageError for an exception raised directly by one of
    # this pipeline's stages.
    def stage_error(stage, index, template, error, line_maps)
      error_line = error_input_line(error, template)
      input_position, pipeline_input_line = map_back(error_line, index, line_maps)
      output_position = Position.new(error_line, stage_input_source(index), index > 0)
      StageError.new(stage.name, input_position, output_position, pipeline_input_line, error)
    end

    # Map a line number in the input of the stage at the given index
    # back towards the pipeline's input, using the line maps provided
    # by earlier stages.  Returns a Position for the pipeline's input
    # and the line number in the pipeline's own input data (nil unless
    # every earlier stage provided a mapping).
    def map_back(error_line, stage_index, line_maps)
      if error_line.nil?
        return [Position.new(nil, stage_input_source(stage_index), stage_index > 0), nil]
      end

      current = error_line
      (stage_index - 1).downto(0) do |i|
        map = line_maps[i]
        mapped = map && map_line(map, current)
        unless mapped
          return [Position.new(current, "intermediate text (output of stage #{@stages[i].name.inspect})", true), nil]
        end
        current = mapped
      end

      [Position.new(current + line - 1, eval_file), current]
    end

    # The source description for the input text of the stage at the
    # given index.
    def stage_input_source(index)
      if index.zero?
        eval_file
      else
        "intermediate text (output of stage #{@stages[index - 1].name.inspect})"
      end
    end

    # Extract the line number in the stage's input text from the
    # exception's backtrace or message, or nil if it cannot be
    # determined.
    def error_input_line(error, template)
      eval_file = template ? template.eval_file : self.eval_file
      template_line = template ? template.line : line
      error_line = nil

      if error.backtrace
        frame = error.backtrace.find{|f| f.start_with?("#{eval_file}:")}
        error_line = frame[eval_file.length + 1..-1][/\A\d+/].to_i if frame
      end

      if error_line.nil? && error.message
        first_line = error.message.lines.first
        if first_line && first_line.start_with?("#{eval_file}:")
          error_line = first_line[eval_file.length + 1..-1][/\A\d+/].to_i
        end
      end

      error_line && error_line - template_line + 1
    end

    def map_line(map, line)
      map[line]
    rescue StandardError
      nil
    end
  end
end
