# frozen_string_literal: true

module Liquid
  module Bytecode
    # A small register machine that executes a compiled Program.
    #
    # It deliberately reuses Liquid's Context for variable scoping, filter
    # invocation, interrupts and resource accounting so that behaviour stays
    # in lock-step with the tree-walking interpreter.
    class VM
      # Runtime state for an active {% for %} loop. Stored on the VM's own
      # stack rather than on the Program, which is reusable across renders.
      class LoopState
        attr_reader :segment, :enumerator
        attr_accessor :loop_vars, :for_stack_entry, :scope_pushed, :phase

        # phase is :fetch before a body run (bind the next item) and :advance
        # after a body run (increment metadata and handle interrupts).
        def initialize(segment)
          @segment = segment
          @enumerator = segment.each
          @phase = :fetch
          @scope_pushed = false
          @loop_vars = nil
          @for_stack_entry = nil
        end

        def next_item
          @enumerator.next
        rescue StopIteration
          nil
        end
      end

      def self.execute(program, context, output = +'')
        new(program, context).run(output)
      end

      def initialize(program, context)
        @instructions = program.instructions
        @context = context
        @loop_stack = []
        @pc = 0
      end

      def run(output)
        while (instruction = @instructions[@pc])
          break if instruction.opcode == :halt
          execute_instruction(instruction, output)
          @pc += 1
        end
        output
      ensure
        # An exception unwinding through active for loops must pop their
        # Context scopes/for_stack entries like Liquid::For's ensure block.
        unwind_loops while @loop_stack.any?
      end

      private

      def execute_instruction(instruction, output)
        case instruction.opcode
        when :text
          output << instruction.operand(0)
        when :render_variable
          instruction.operand(0).render_to_output_buffer(@context, output)
        when :assign
          instruction.operand(0).render_to_output_buffer(@context, output)
        when :jump
          @pc = instruction.operand(0) - 1 # run loop adds one
        when :jump_if_false
          jump_if_false(instruction, output)
        when :render_score
          @context.resource_limits.increment_render_score(instruction.operand(0))
        when :write_score
          @context.resource_limits.increment_write_score(output)
        when :for_begin
          for_begin(instruction)
        when :for_inc
          for_inc(instruction)
        when :for_cleanup
          for_cleanup
        when :break_interrupt
          push_interrupt(Break::INTERRUPT, instruction)
        when :continue_interrupt
          push_interrupt(Continue::INTERRUPT, instruction)
        else
          raise InternalError, "unknown bytecode opcode #{instruction.opcode.inspect}"
        end
      rescue => exc
        raise if exc.is_a?(MemoryError)
        handle_instruction_error(instruction, exc, output)
      end

      def jump_if_false(instruction, output)
        condition = instruction.operand(0)
        negated = instruction.operand(1)

        result = Liquid::Utils.to_liquid_value(condition.evaluate(@context))
        result = !result if negated

        unless result
          # Evaluate the next branch (elsif/else); the run loop adds one.
          @pc = instruction.operand(2) - 1
        end
      rescue => exc
        # A condition error abandons the whole tag, matching the interpreter
        # rescuing at the If node and continuing after it.
        # rescue_render_node appends the rendered error text (or nothing for
        # blank-tag suppression) onto the buffer it is given, matching what
        # the If node would append to template output.
        BlockBody.rescue_render_node(
          @context, output, instruction.line_number, exc, instruction.blank
        )
        @pc = instruction.operand(3) - 1
      end

      # Operands: [descriptor, for_inc_index, else_index, cleanup_index]
      def for_begin(instruction)
        descriptor = instruction.operand(0)
        segment = descriptor.collection_segment(@context)

        if segment.empty?
          @pc = instruction.operand(2) - 1 # else
          return
        end

        start_loop(descriptor, segment)
        @pc = instruction.operand(1) - 1 # FOR_INC drives the first iteration
      end

      def start_loop(descriptor, segment)
        for_stack = @context.registers[:for_stack] ||= []
        state = LoopState.new(segment)

        @context.push({})
        state.scope_pushed = true

        loop_vars = Liquid::ForloopDrop.new(descriptor.name, segment.length, for_stack.last)
        state.loop_vars = loop_vars
        for_stack.push(loop_vars)
        state.for_stack_entry = loop_vars

        @context['forloop'] = loop_vars
        @loop_stack.push(state)
      end

      # Operands: [descriptor, body_start, cleanup_index]
      #
      # Before the body runs this binds the next item. After the body returns
      # here it increments forloop metadata and processes any interrupt pushed
      # by break/continue, exactly as Liquid::For#render_segment does.
      def for_inc(instruction)
        descriptor = instruction.operand(0)
        state = @loop_stack.last

        if state.phase == :fetch
          item = state.next_item
          if item.nil?
            @pc = instruction.operand(2) - 1 # cleanup
            return
          end
          @context[descriptor.variable_name] = item
          state.phase = :advance
          # Jump into the body. When it returns control to FOR_INC the phase
          # will be :advance, which increments metadata/handles interrupts.
          @pc = instruction.operand(1) - 1
        else
          state.loop_vars.send(:increment!)
          state.phase = :fetch

          if @context.interrupt?
            interrupt_obj = @context.pop_interrupt
            if interrupt_obj.is_a?(BreakInterrupt)
              @pc = instruction.operand(2) - 1 # cleanup after consuming break
            else # ContinueInterrupt: fetch/bind the next item at FOR_INC
              # Re-enter FOR_INC in :fetch phase to bind the next item.
              @pc -= 1
            end
          else
            # Normal iteration: re-enter FOR_INC to fetch the next item.
            @pc -= 1
          end
        end
      end

      def for_cleanup
        state = @loop_stack.pop
        return unless state

        @context.registers[:for_stack]&.pop if state.for_stack_entry
        @context.pop if state.scope_pushed
      end

      def unwind_loops
        while (state = @loop_stack.pop)
          @context.registers[:for_stack]&.pop if state.for_stack_entry
          @context.pop if state.scope_pushed
        end
      end

      def push_interrupt(interrupt_obj, instruction)
        @context.push_interrupt(interrupt_obj)
        operand = instruction.operand(0)
        target = operand.is_a?(Array) ? operand[0] : operand
        if target
          # Both break and continue land on FOR_INC; the advance phase pops
          # the interrupt and routes break to cleanup, continue to next item.
          @pc = target - 1
        else
          # break/continue outside of any loop stops the current BlockBody;
          # at document level that halts all rendering.
          @pc = @instructions.length - 1 # HALT
        end
      end

      def handle_instruction_error(instruction, exc, output)
        blank_tag = instruction.opcode != :render_variable && instruction.blank
        BlockBody.rescue_render_node(
          @context, output, instruction.line_number, exc, blank_tag
        )
      end
    end
  end
end
