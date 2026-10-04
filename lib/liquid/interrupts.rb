# frozen_string_literal: true

module Liquid
  # An interrupt is any command that breaks processing of a block (ex: a for loop).
  class Interrupt
    attr_reader :message

    def initialize(message = nil)
      @message = message || "interrupt"
    end
  end

  # Base class for interrupts raised by break and continue tags.
  # Carries an optional loop label so nested loops can tell whether the
  # interrupt targets them or an enclosing loop.
  class LoopInterrupt < Interrupt
    attr_reader :label

    def initialize(label = nil)
      super()
      @label = label
    end

    # An interrupt without a label is handled by the innermost loop,
    # a labeled one only by the loop declaring that label.
    def targets?(loop_label)
      @label.nil? || @label == loop_label
    end
  end

  # Interrupt that is thrown whenever a {% break %} is called.
  class BreakInterrupt < LoopInterrupt; end

  # Interrupt that is thrown whenever a {% continue %} is called.
  class ContinueInterrupt < LoopInterrupt; end
end
