# frozen_string_literal: true

module Liquid
  module Bytecode
    # Compiles a tree-walking Liquid AST (a Liquid::Document produced by the
    # normal parser) into an explicit instruction stream executed by
    # Liquid::Bytecode::VM.
    #
    # Supported subset:
    #
    # * raw text and {{ variable }} / {% echo %} output (including filters)
    # * {% assign %}
    # * {% if %}/{% elsif %}/{% else %}/{% endif %} and {% unless %}
    # * {% for %} (limit/offset/reversed/ranges), {% break %} and {% continue %}
    #
    # Every other tag, including user-registered custom tags, is rejected at
    # compile time with Liquid::Bytecode::UnsupportedTagError so that it can
    # never be silently mis-executed at runtime. Tree-walking rendering is
    # unaffected and remains the default.
    class Compiler
      class UnsupportedTagError < SyntaxError
      end

      def self.compile(document)
        new(document).compile
      end

      def initialize(document)
        @document = document
        @instructions = []
        # Targets for enclosing for loops. Each target (the FOR_INC index) is
        # stored in BREAK/CONTINUE operands and filled in once the enclosing
        # FOR_INC instruction is emitted; both interrupts route through it.
        @loop_frames = []
      end

      def compile
        compile_body(@document.body)
        emit(:halt)
        Program.new(@instructions)
      end

      private

      # Mirrors BlockBody#render_to_output_buffer: a render score is charged
      # once per node in the body and a write score is checked after each node
      # that returns control normally (a break/continue transfers control away
      # and is charged like in the interpreter).
      def compile_body(body)
        nodes = body.nodelist
        emit(:render_score, [nodes.length])
        nodes.each do |node|
          compile_node(node)
          emit(:write_score) unless control_transfer?(node)
        end
      end

      def control_transfer?(node)
        node.is_a?(Break) || node.is_a?(Continue)
      end

      def compile_node(node)
        case node
        when String
          emit(:text, [node])
        when Variable
          emit(:render_variable, [node], line_number: node.line_number)
        when Assign
          emit(:assign, [node], line_number: node.line_number, blank: node.blank?)
        when Echo
          emit(:render_variable, [node.variable], line_number: node.line_number)
        when If
          # Unless is an If subclass whose first condition is negated.
          compile_if(node, negated: node.is_a?(Unless))
        when For
          compile_for(node)
        when Break, Continue
          compile_interrupt(node)
        else
          raise_unsupported(node)
        end
      end

      # if/elsif/else compiles to a linear conditional-jump chain:
      #
      #   JUMP_IF_FALSE cond negated ->next ->end
      #   <body>
      #   JUMP ->end
      # next:
      #   ...
      #   <else body>
      # end:
      def compile_if(if_tag, negated:)
        end_jumps = []
        conditional_jumps = []

        if_tag.blocks.each_with_index do |condition_block, index|
          if condition_block.is_a?(ElseCondition)
            compile_body(condition_block.attachment)
            next
          end

          negated_first = negated && index.zero?
          conditional_jump = emit(
            :jump_if_false,
            [condition_block, negated_first, nil, nil],
            line_number: if_tag.line_number,
            blank: if_tag.blank?,
          )
          conditional_jumps << conditional_jump
          compile_body(condition_block.attachment)
          end_jumps << emit(:jump, [nil])
          # A false condition continues at the next branch instruction; the
          # run loop adds one after the instruction handler, so the stored
          # target is exactly the next instruction index.
          patch(conditional_jump, 2, @instructions.length)
        end

        end_index = @instructions.length
        end_jumps.each { |idx| patch(idx, 0, end_index) }
        # A failed condition jumps "next" to evaluate another branch; an error
        # while evaluating the condition or a taken-but-failed branch abandons
        # the whole tag by jumping to its end.
        conditional_jumps.each { |idx| patch(idx, 3, end_index) }
      end

      # Layout:
      #
      #   FOR_BEGIN descriptor ->inc ->else ->cleanup
      #   <body>
      # inc:
      #   FOR_INC descriptor ->body ->cleanup
      # else:
      #   <else body>
      # cleanup:
      #   FOR_CLEANUP descriptor
      def compile_for(for_tag)
        descriptor = LoopDescriptor.new(for_tag)
        frame_holder = [nil]
        @loop_frames.push(frame_holder)

        emit(:for_begin, [descriptor, nil, nil, nil],
          line_number: for_tag.line_number, blank: for_tag.blank?)

        body_start = @instructions.length
        compile_body(for_tag.for_block)

        inc_index = emit(:for_inc, [descriptor, nil, nil],
          line_number: for_tag.line_number, blank: for_tag.blank?)
        patch(inc_index, 1, body_start)

        else_start = @instructions.length
        compile_body(for_tag.else_block) if for_tag.else_block

        cleanup_index = emit(:for_cleanup, [descriptor],
          line_number: for_tag.line_number, blank: for_tag.blank?)

        @loop_frames.pop
        frame_holder[0] = inc_index

        patch_index_of(:for_begin, descriptor, 1, inc_index)
        patch_index_of(:for_begin, descriptor, 2, else_start)
        patch_index_of(:for_begin, descriptor, 3, cleanup_index)
        patch(inc_index, 2, cleanup_index)
      end

      def compile_interrupt(node)
        frame_holder = @loop_frames.last
        target = frame_holder || [nil] # outside a loop the holder stays nil
        emit(node.is_a?(Break) ? :break_interrupt : :continue_interrupt, [target],
          line_number: node.line_number, blank: true)
      end

      def emit(opcode, operands = [], line_number: nil, blank: false)
        @instructions << Instruction.new(opcode, operands, line_number: line_number, blank: blank)
        @instructions.length - 1
      end

      # Rebuilds the frozen instruction at +index+ replacing one operand.
      # Negative indexes count from the end (relative to the last emit).
      def patch(index, operand_index, value)
        index += @instructions.length if index.negative?
        instruction = @instructions[index]
        operands = instruction.operands.dup
        operands[operand_index] = value
        @instructions[index] = Instruction.new(
          instruction.opcode,
          operands,
          line_number: instruction.line_number,
          blank: instruction.blank,
        )
      end

      def patch_index_of(opcode, descriptor, operand_index, value)
        idx = @instructions.rindex { |i| i.opcode == opcode && i.operand(0).equal?(descriptor) }
        patch(idx, operand_index, value)
      end

      def raise_unsupported(node)
        tag_name = node.respond_to?(:tag_name) ? node.tag_name : node.class.name
        line = node.respond_to?(:line_number) ? node.line_number : nil
        error = UnsupportedTagError.new(
          "bytecode VM does not support the #{tag_name.inspect} tag"
        )
        error.line_number = line
        raise error
      end
    end
  end
end
