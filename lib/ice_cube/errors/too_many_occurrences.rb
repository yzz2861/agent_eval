module IceCube
  # Raised when expanding occurrences inside a query window would exceed the
  # configured safety cap. Increase max_occurrences or narrow the window.
  class TooManyOccurrences < StandardError
    attr_reader :schedule, :count, :max_occurrences

    def initialize(schedule, count, max_occurrences)
      @schedule = schedule
      @count = count
      @max_occurrences = max_occurrences
      super(
        "expanded #{count} occurrences, exceeding the max_occurrences limit " \
        "of #{max_occurrences}; narrow the query window or raise the limit"
      )
    end
  end
end
