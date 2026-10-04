# frozen_string_literal: true

module Liquid
  module Bytecode
    # A single bytecode instruction.
    #
    # +terminal+ marks instructions that correspond to the boundary of a single
    # BlockBody node: after executing them the VM checks for interrupts and
    # charges the output write score, mirroring BlockBody#render_to_output_buffer.
    #
    # +rescue_label+ points at the instruction where execution resumes after the
    # node's runtime error has been handled, mirroring BlockBody.render_node.
    class Instruction
      JUMP_OPCODES = [:jump, :jump_if_false, :jump_if_true].freeze

      attr_reader :opcode, :operands, :line_number, :blank_tag, :terminal, :rescue_label
      attr_accessor :rescue_ip

      def initialize(opcode, operands = nil, line_number: nil, blank_tag: false, terminal: false,
        rescue_label: nil)
        @opcode       = opcode
        @operands     = operands || Const::EMPTY_ARRAY
        @line_number  = line_number
        @blank_tag    = blank_tag
        @terminal     = terminal
        @rescue_label = rescue_label
        @rescue_ip    = nil
      end

      def jump?
        JUMP_OPCODES.include?(@opcode)
      end

      # Replaces Label operands with their resolved addresses.
      def resolve!
        if jump?
          target = @operands[0]
          raise InternalError, "unresolved jump target in #{@opcode}" unless target.is_a?(Label)
          @operands = [target.index]
        end
        @rescue_ip = @rescue_label.index if @rescue_label
      end
    end
  end
end
