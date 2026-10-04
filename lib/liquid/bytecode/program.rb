# frozen_string_literal: true

module Liquid
  module Bytecode
    # A compiled sequence of instructions plus metadata for debugging.
    class Program
      attr_reader :instructions

      def initialize(instructions)
        @instructions = instructions.freeze
        freeze
      end

      def length
        @instructions.length
      end
      alias_method :size, :length

      # Returns a human readable disassembly of the instruction stream.
      #
      # Each line is rendered as:
      #
      #   0000  line 3  TEXT "hello"
      #
      # Jump targets point at instruction indexes ("->12"), making control
      # flow straightforward to follow when debugging compiled templates.
      def disassemble
        index_width = [(@instructions.length - 1).to_s.length, 4].max

        @instructions.each_with_index.map do |instruction, index|
          line = if instruction.line_number
            format("line %-4d", instruction.line_number)
          else
            "         "
          end
          "%0#{index_width}d  %s  %s" % [index, line, instruction.disassemble_line]
        end.join("\n")
      end

      alias_method :to_s, :disassemble

      def inspect
        "#<Liquid::Bytecode::Program #{@instructions.length} instructions>"
      end
    end
  end
end
