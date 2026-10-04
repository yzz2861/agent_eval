# frozen_string_literal: true

module Liquid
  module Bytecode
    # An ordered list of Instructions and Labels. Each sequence corresponds to a
    # rendered Liquid::BlockBody, so +node_count+ mirrors the interpreter's
    # per-body render score charge.
    class InstructionSequence
      attr_reader :name, :node_count, :instructions

      def initialize(name, node_count)
        @name        = name
        @node_count  = node_count
        @instructions = []
      end

      def emit(opcode, operands = nil, line_number: nil, blank_tag: false, terminal: false,
        rescue_label: nil)
        instruction = Instruction.new(
          opcode, operands, line_number: line_number, blank_tag: blank_tag,
          terminal: terminal, rescue_label: rescue_label
        )
        @instructions << instruction
        instruction
      end

      def place(label)
        @instructions << label
        label
      end

      def new_label(name = nil)
        Label.new(name)
      end

      # Resolves all labels to instruction offsets and removes them from the
      # stream. Called once, after compilation, before the sequence is executed.
      def finalize!
        # A label marks the address of the following instruction. Consecutive
        # labels share the same address; a trailing label points just past the
        # final instruction.
        ip = 0
        @instructions.each do |entry|
          if entry.is_a?(Label)
            raise InternalError, "label #{entry.name} placed twice" unless entry.index.nil?
            entry.index = ip
          else
            ip += 1
          end
        end

        @instructions.filter! { |entry| entry.is_a?(Instruction) }
        @instructions.each(&:resolve!)
        @instructions.freeze
        freeze
      end
    end
  end
end
