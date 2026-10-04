# frozen_string_literal: true

module Liquid
  module Bytecode
    # Small stack based virtual machine that executes finalized instruction
    # sequences.
    #
    # The VM deliberately reuses the interpreter's runtime semantics:
    # variable lookup goes through Context, filters through the Strainer, for
    # loops share the same registers and ForloopDrop, break/continue use the
    # same interrupts, and every node is charged through ResourceLimits.
    class VM
      def initialize(context, output)
        @context = context
        @output  = output
        @stack   = []
      end

      def run(program)
        result = execute_iseq(program.iseq)
        raise InternalError, "unexpected frame result #{result.inspect}" unless result.nil?
        @output
      end

      private

      # Executes a frame corresponding to one BlockBody. Returns nil when it
      # ran to completion, or :interrupted when a break/continue stopped it.
      # A pending interrupt is always meant for the nearest enclosing :for,
      # which consumes it; the document root mirrors the interpreter by simply
      # stopping.
      def execute_iseq(iseq)
        instructions = iseq.instructions
        @context.resource_limits.increment_render_score(iseq.node_count)

        frame_base = @stack.length

        ip = 0
        while (instruction = instructions[ip])
          begin
            result = execute_instruction(instruction, ip)
            return result if result == :interrupted
            ip = result
          rescue MemoryError
            raise
          rescue => exc
            rescue_node(instruction, exc)
            # Discard any partial operands left on the stack by the failed node.
            @stack.pop(@stack.length - frame_base)
            ip = instruction.rescue_ip
          end

          if instruction.terminal
            if @context.interrupt?
              # Mirrors BlockBody#render_to_output_buffer: an interrupt stops
              # the body before the node's write score is charged.
              return :interrupted
            end
            @context.resource_limits.increment_write_score(@output)
          end
        end

        nil
      end

      def rescue_node(instruction, exc)
        exc.line_number ||= instruction.line_number if exc.is_a?(Liquid::Error)
        BlockBody.rescue_render_node(
          @context,
          @output,
          instruction.line_number,
          exc,
          instruction.blank_tag,
        )
      end

      def execute_instruction(instruction, ip)
        case instruction.opcode
        when :text
          @output << instruction.operands[0]
        when :push_expression
          @stack << @context.evaluate(instruction.operands[0])
        when :new_hash
          @stack << {}
        when :hash_pair
          key = instruction.operands[0]
          value = @stack.pop
          @stack.last[key] = value
        when :filter
          invoke_filter(instruction.operands)
        when :filter_kwargs
          invoke_filter_kwargs(instruction.operands)
        when :apply_global_filter
          @stack << @context.apply_global_filter(@stack.pop)
        when :render_output
          Variable.render_obj_to_output(@stack.pop, @output)
        when :store_assign
          Assign.store_assignment(@context, instruction.operands[0], @stack.pop)
        when :test_leaf
          interpret_test_leaf(instruction.operands)
        when :push_interrupt
          @context.push_interrupt(instruction.operands[0])
        when :jump
          return instruction.operands[0]
        when :jump_if_false
          return instruction.operands[0] unless Utils.to_liquid_value(@stack.last)
        when :jump_if_true
          return instruction.operands[0] if Utils.to_liquid_value(@stack.last)
        when :exec
          result = execute_iseq(instruction.operands[0])
          return result if result == :interrupted

          # The exec node itself is charged by the caller's terminal handling.
        when :for
          execute_for(instruction.operands)
        else
          raise InternalError, "unknown bytecode opcode #{instruction.opcode.inspect}"
        end
        ip + 1
      end

      def invoke_filter(operands)
        filter_name, arg_count = operands
        args = @stack.pop(arg_count)
        value = @stack.pop
        @stack << @context.invoke(filter_name, value, *args)
      end

      def invoke_filter_kwargs(operands)
        filter_name, arg_count, _kwargs_count = operands
        kwargs = @stack.pop
        args = @stack.pop(arg_count)
        value = @stack.pop
        @stack << @context.invoke(filter_name, value, *args, **kwargs)
      end

      # Mirrors Condition#interpret_condition for a single leaf comparison.
      def interpret_test_leaf(operands)
        left, operator, right = operands
        @stack << Condition.interpret_leaf(left, operator, right, @context)
      end

      def execute_for(operands)
        for_tag, for_body, else_body = operands

        segment = for_tag.send(:collection_segment, @context)

        if segment.empty?
          execute_iseq(else_body) if else_body
          return
        end

        for_stack = @context.registers[:for_stack] ||= []
        length = segment.length

        @context.stack do
          loop_vars = ForloopDrop.new(for_tag.name, length, for_stack[-1])
          for_stack.push(loop_vars)

          begin
            @context['forloop'] = loop_vars

            stopping = false
            segment.each do |item|
              break if stopping
              @context[for_tag.variable_name] = item
              execute_iseq(for_body)
              loop_vars.send(:increment!)

              # Any interrupt left after the body is this loop's break/continue
              # (possibly raised deep inside nested if/for bodies); consume it
              # exactly like For#render_segment. A ContinueInterrupt simply
              # lets this iteration block finish so #each advances to the next.
              if @context.interrupt?
                interrupt = @context.pop_interrupt
                stopping = true if interrupt.is_a?(BreakInterrupt)
              end
            end
          ensure
            for_stack.pop
          end
        end
      end
    end
  end
end
