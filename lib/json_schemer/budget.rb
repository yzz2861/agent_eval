# frozen_string_literal: true
module JSONSchemer
  # Execution budget shared by a single validation. Limits are optional; a
  # budget without limits is still useful for cancellation. Exhausting a
  # limit (or cancelling) raises a ValidationIncomplete error because the
  # validation could not be completed.
  class Budget
    attr_reader :max_keyword_evaluations, :max_ref_depth, :max_errors
    attr_reader :keyword_evaluations, :ref_depth, :errors

    def initialize(max_keyword_evaluations: nil, max_ref_depth: nil, max_errors: nil)
      @max_keyword_evaluations = max_keyword_evaluations
      @max_ref_depth = max_ref_depth
      @max_errors = max_errors
      @keyword_evaluations = 0
      @ref_depth = 0
      @errors = 0
      @cancelled = false
    end

    def cancel!
      @cancelled = true
    end

    def cancelled?
      @cancelled
    end

    def evaluate_keyword!
      check_cancelled!
      @keyword_evaluations += 1
      if @max_keyword_evaluations && @keyword_evaluations > @max_keyword_evaluations
        raise BudgetExceeded, "keyword evaluation budget exceeded (#{@max_keyword_evaluations})"
      end
    end

    def enter_ref!
      check_cancelled!
      @ref_depth += 1
      if @max_ref_depth && @ref_depth > @max_ref_depth
        raise BudgetExceeded, "reference depth budget exceeded (#{@max_ref_depth})"
      end
    end

    def exit_ref!
      @ref_depth -= 1
    end

    def record_error!
      check_cancelled!
      @errors += 1
      if @max_errors && @errors > @max_errors
        raise BudgetExceeded, "error budget exceeded (#{@max_errors})"
      end
    end

    def check_cancelled!
      raise ValidationCancelled, 'validation cancelled' if @cancelled
    end
  end
end
