# frozen_string_literal: true

module Liquid
  # An interrupt is any command that breaks processing of a block (ex: a for loop).
  class Interrupt
    attr_reader :message, :label

    def initialize(message = nil, label: nil)
      @message = message || "interrupt"
      @label   = label
    end
  end

  # Interrupt that is thrown whenever a {% break %} is called.
  class BreakInterrupt < Interrupt
    def initialize(label = nil)
      super(label ? "break" : nil, label: label)
    end
  end

  # Interrupt that is thrown whenever a {% continue %} is called.
  class ContinueInterrupt < Interrupt
    def initialize(label = nil)
      super(label ? "continue" : nil, label: label)
    end
  end
end
