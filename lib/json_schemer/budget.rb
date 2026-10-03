# frozen_string_literal: true
module JSONSchemer
  # Raised when validation cannot run to completion. Rescue this class to
  # distinguish an unfinished validation from an ordinary invalid result.
  class IncompleteValidation < StandardError; end

  # Raised when an execution budget limit is reached during validation.
  class BudgetExceeded < IncompleteValidation
    attr_reader :budget, :limit, :used

    def initialize(message, budget, limit, used)
      @budget = budget
      @limit = limit
      @used = used
      super(message)
    end
  end

  # Raised when validation is stopped by `Budget#cancel!`.
  class ValidationCancelled < IncompleteValidation
    attr_reader :budget

    def initialize(budget)
      @budget = budget
      super('validation was cancelled')
    end
  end

  # Per-validation execution budget. A single budget instance is shared across
  # subschemas, `$ref` expansion, combinator branches and output enumeration
  # for one `validate` call. Reusing a {Schema} never shares remaining budget
  # because a fresh budget is created per call unless one is explicitly passed.
  class Budget
    attr_reader :max_keyword_evaluations, :max_ref_depth, :max_errors
    attr_reader :keyword_evaluations, :ref_depth, :errors

    def self.coerce(budget, **options)
      return budget if budget.is_a?(Budget)
      options = budget if budget.is_a?(Hash)
      new(**options)
    end

    def initialize(max_keyword_evaluations: nil, max_ref_depth: nil, max_errors: nil)
      @max_keyword_evaluations = max_keyword_evaluations
      @max_ref_depth = max_ref_depth
      @max_errors = max_errors
      @keyword_evaluations = 0
      @ref_depth = 0
      @errors = 0
      @cancelled = false
    end

    def keyword_evaluation!
      raise ValidationCancelled, self if @cancelled
      @keyword_evaluations += 1
      exceeded!('keyword evaluations', @max_keyword_evaluations, @keyword_evaluations)
    end

    def check_cancelled!
      raise ValidationCancelled, self if @cancelled
    end

    def enter_ref!
      @ref_depth += 1
      exceeded!('reference expansion depth', @max_ref_depth, @ref_depth)
      @ref_depth
    end

    def exit_ref!
      @ref_depth -= 1
    end

    def error_emitted!
      raise ValidationCancelled, self if @cancelled
      @errors += 1
      exceeded!('output errors', @max_errors, @errors)
    end

    def cancelled?
      @cancelled
    end

    # Stops an in-progress validation. Safe to call from another thread, for
    # example from a custom keyword or a before-property hook. The budget is
    # checked at keyword, reference and error output boundaries, so a
    # validation may evaluate one more keyword before stopping.
    def cancel!
      @cancelled = true
    end

    private

    def exceeded!(name, limit, used)
      return unless limit && used > limit
      raise BudgetExceeded.new(
        "execution budget exceeded: #{used} #{name} (limit #{limit})", self, limit, used
      )
    end
  end
end
