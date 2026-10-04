# frozen_string_literal: true

module Liquid
  module Bytecode
    # A single bytecode instruction.
    #
    # +opcode+ is a Symbol. +operands+ is a frozen Array of opcode specific
    # values (parsed expression objects, jump targets, runtime descriptors).
    # +line_number+ is the 1-based line of the template node that produced the
    # instruction and +blank+ mirrors whether the originating node is a "blank"
    # tag, which affects error text suppression exactly like the interpreter.
    class Instruction
      attr_reader :opcode, :operands, :line_number, :blank

      def initialize(opcode, operands, line_number: nil, blank: false)
        @opcode = opcode
        @operands = operands
        @line_number = line_number
        @blank = blank
        freeze
      end

      def operand(index = 0)
        @operands[index]
      end

      def inspect
        "#<Liquid::Bytecode::Instruction #{disassemble_line}>"
      end

      # Human readable form used by the disassembler, e.g. "JUMP_IF_FALSE ->12".
      def disassemble_line
        rendered_operands = @operands.map { |op| Instruction.format_operand(op) }
        ([@opcode.to_s] + rendered_operands).join(' ')
      end

      def self.format_operand(operand)
        case operand
        when Array
          # BREAK/CONTINUE hold a mutable one-element target resolved after
          # the enclosing FOR_INC is emitted.
          operand[0] ? "->#{operand[0]}" : "->?"
        when String
          operand.inspect
        when LoopDescriptor
          "loop:#{operand.name}"
        when Condition, ElseCondition
          "condition(#{condition_summary(operand)})"
        when Variable
          "var:#{operand.raw.strip}"
        when Assign
          "assign:#{operand.to}"
        when true
          "negated"
        when false
          "false"
        when nil
          "nil"
        when Integer
          "->#{operand}"
        else
          operand.inspect
        end
      end

      def self.condition_summary(condition)
        left = condition.left
        op = condition.operator
        right = condition.right
        parts = [inspect_value(left)]
        parts << op if op
        parts << inspect_value(right) if right
        parts.join(' ')
      end

      def self.inspect_value(value)
        case value
        when Liquid::VariableLookup
          ([value.name] + value.lookups).map(&:to_s).join('.')
        when String
          value.inspect
        else
          value.inspect
        end
      end
    end
  end
end
