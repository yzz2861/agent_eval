module IceCube
  # Raised when an iCalendar content line cannot be parsed.
  # Carries the 1-based line number and character position of the
  # offending input so callers can locate the problem.
  class InvalidIcalError < ArgumentError
    attr_reader :line_number, :position

    def initialize(message, line_number: nil, position: nil)
      @line_number = line_number
      @position = position
      location = []
      location << "line #{line_number}" if line_number
      location << "position #{position}" if position
      message = "#{message} (#{location.join(", ")})" unless location.empty?
      super(message)
    end
  end
end
