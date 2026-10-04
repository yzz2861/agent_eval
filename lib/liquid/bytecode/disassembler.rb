# frozen_string_literal: true

module Liquid
  module Bytecode
    # Renders a human readable listing of a finalized instruction sequence.
    #
    # Example output:
    #
    #   == document ==
    #   0000  push_expression   x          (line 1)
    #   0001  jump_if_false     0004       (line 1)
    #   0002  text              "yes"      (line 1)
    #   0003  jump              0004       (line 1)
    class Disassembler
      def disassemble(iseq)
        io = +''
        render_iseq(iseq, io, 0)
        io
      end

      private

      def render_iseq(iseq, io, indent)
        io << ('  ' * indent) << "== #{iseq.name} (#{iseq.node_count} nodes) ==\n"

        nested = []
        iseq.instructions.each_with_index do |instruction, index|
          io << ('  ' * indent)
          io << format('%04d', index)
          io << '  '
          io << format('%-17s', instruction.opcode.to_s)
          io << ' '
          io << render_operands(instruction, nested)
          io << render_meta(instruction)
          io << "\n"
        end

        nested.each { |child| render_iseq(child, io, indent + 1) }
      end

      def render_operands(instruction, nested)
        case instruction.opcode
        when :text
          text = instruction.operands[0]
          shown = text.length > 30 ? "#{text[0, 30]}…" : text
          shown.inspect
        when :jump, :jump_if_false, :jump_if_true
          format('%04d', instruction.operands[0])
        when :exec
          child = instruction.operands[0]
          nested << child
          "<iseq #{child.name}>"
        when :for
          for_tag, for_body, else_body = instruction.operands
          nested << for_body
          nested << else_body if else_body
          "#{for_tag.variable_name} in #{operand_inspect(for_tag.collection_name)} (else=#{else_body ? 'yes' : 'no'})"
        when :test_leaf
          left, operator, right = instruction.operands
          [operand_inspect(left), operator, operand_inspect(right)].compact.join(' ')
        else
          instruction.operands.map { |operand| operand_inspect(operand) }.join(' ')
        end
      end

      def operand_inspect(operand)
        case operand
        when VariableLookup
          [operand.name, *operand.lookups].join('.')
        when RangeLookup
          "(#{operand_inspect(operand.start_obj)}..#{operand_inspect(operand.end_obj)})"
        when Range
          "(#{operand.min}..#{operand.max})"
        when String, Symbol
          operand.inspect
        else
          operand.inspect
        end
      end

      def render_meta(instruction)
        meta = []
        meta << "line #{instruction.line_number}" if instruction.line_number
        meta << 'blank' if instruction.blank_tag
        meta << "rescue #{format('%04d', instruction.rescue_ip)}" if instruction.rescue_ip
        meta << 'terminal' if instruction.terminal
        meta.empty? ? '' : "    (#{meta.join(', ')})"
      end
    end
  end
end
