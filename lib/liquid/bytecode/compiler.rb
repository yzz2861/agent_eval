# frozen_string_literal: true

module Liquid
  module Bytecode
    # Compiles the interpreted Liquid AST into instruction sequences.
    #
    # Supported nodes: literal text, Variable output (including filters),
    # Assign, If/Unless with elsif/else, and For (with limit/offset/reversed,
    # else, break and continue). Every other tag is rejected explicitly at
    # compile time so unsupported templates never silently fall back.
    class Compiler
      def compile_block_body(block_body, name:)
        iseq = InstructionSequence.new(name, block_body.nodelist.length)
        block_body.nodelist.each { |node| compile_node(iseq, node) }
        iseq.finalize!
        iseq
      end

      private

      def compile_node(iseq, node)
        rescue_label = iseq.new_label("rescue_#{iseq.instructions.length}")

        case node
        when ::String
          compile_text(iseq, node, rescue_label)
        when Variable
          compile_variable(iseq, node, rescue_label)
        when Assign
          compile_assign(iseq, node, rescue_label)
        when If
          compile_if(iseq, node, unless_tag: node.is_a?(Unless), rescue_label: rescue_label)
        when For
          compile_for(iseq, node, rescue_label)
        when Break, Continue
          compile_interrupt(iseq, node, rescue_label)
        else
          raise UnsupportedSyntaxError.new(
            "bytecode execution is experimental and does not support the #{node_tag_name(node)} tag yet"
          ).tap { |error| error.line_number = node.line_number }
        end

        iseq.place(rescue_label)
      end

      def node_tag_name(node)
        if node.respond_to?(:tag_name)
          node.tag_name.to_s
        else
          node.class.name
        end
      end

      def compile_text(iseq, text, rescue_label)
        iseq.emit(:text, [text], terminal: true, rescue_label: rescue_label)
      end

      def compile_variable(iseq, variable, rescue_label)
        iseq.emit(:push_expression, [variable.name], line_number: variable.line_number,
          rescue_label: rescue_label)
        variable.filters.each do |filter_name, filter_args, filter_kwargs|
          filter_args.each do |arg|
            iseq.emit(:push_expression, [arg], line_number: variable.line_number,
              rescue_label: rescue_label)
          end
          if filter_kwargs
            iseq.emit(:new_hash, line_number: variable.line_number, rescue_label: rescue_label)
            filter_kwargs.each do |key, arg|
              iseq.emit(:push_expression, [arg], line_number: variable.line_number,
                rescue_label: rescue_label)
              iseq.emit(:hash_pair, [key], line_number: variable.line_number,
                rescue_label: rescue_label)
            end
            iseq.emit(:filter_kwargs, [filter_name, filter_args.length, filter_kwargs.length],
              line_number: variable.line_number, rescue_label: rescue_label)
          else
            iseq.emit(:filter, [filter_name, filter_args.length], line_number: variable.line_number,
              rescue_label: rescue_label)
          end
        end
        iseq.emit(:apply_global_filter, line_number: variable.line_number, rescue_label: rescue_label)
        iseq.emit(:render_output, line_number: variable.line_number, terminal: true,
          rescue_label: rescue_label)
      end

      def compile_assign(iseq, assign, rescue_label)
        variable = assign.from
        iseq.emit(:push_expression, [variable.name], line_number: variable.line_number,
          rescue_label: rescue_label)
        variable.filters.each do |filter_name, filter_args, filter_kwargs|
          filter_args.each do |arg|
            iseq.emit(:push_expression, [arg], line_number: assign.line_number,
              rescue_label: rescue_label)
          end
          if filter_kwargs
            iseq.emit(:new_hash, line_number: assign.line_number, rescue_label: rescue_label)
            filter_kwargs.each do |key, arg|
              iseq.emit(:push_expression, [arg], line_number: assign.line_number,
                rescue_label: rescue_label)
              iseq.emit(:hash_pair, [key], line_number: assign.line_number,
                rescue_label: rescue_label)
            end
            iseq.emit(:filter_kwargs, [filter_name, filter_args.length, filter_kwargs.length],
              line_number: assign.line_number, rescue_label: rescue_label)
          else
            iseq.emit(:filter, [filter_name, filter_args.length], line_number: assign.line_number,
              rescue_label: rescue_label)
          end
        end
        iseq.emit(:apply_global_filter, line_number: assign.line_number, rescue_label: rescue_label)
        iseq.emit(:store_assign, [assign.to], line_number: assign.line_number, blank_tag: true,
          terminal: true, rescue_label: rescue_label)
      end

      def compile_interrupt(iseq, node, rescue_label)
        interrupt = node.is_a?(Break) ? Break::INTERRUPT : Continue::INTERRUPT
        iseq.emit(:push_interrupt, [interrupt], line_number: node.line_number, blank_tag: true,
          terminal: true, rescue_label: rescue_label)
      end

      def compile_if(iseq, if_tag, unless_tag:, rescue_label:)
        end_jump_labels = []

        if_tag.blocks.each_with_index do |block, index|
          first_block_of_unless = unless_tag && index == 0
          body = compile_block_body(block.attachment, name: "#{unless_tag ? 'unless' : 'if'}:#{index}")

          if block.else?
            iseq.emit(:exec, [body], line_number: if_tag.line_number, blank_tag: if_tag.blank?,
              terminal: true, rescue_label: rescue_label)
          else
            after_chain = iseq.new_label("if_after_chain_#{index}")
            compile_condition_chain(iseq, block, after_chain, if_tag.line_number, rescue_label)
            iseq.place(after_chain)

            jump_opcode = first_block_of_unless ? :jump_if_false : :jump_if_true
            # When the condition matches, skip the unconditional jump that
            # otherwise leads to the next branch.
            body_label = iseq.new_label("if_body_#{index}")
            iseq.emit(jump_opcode, [body_label], line_number: if_tag.line_number,
              rescue_label: rescue_label)
            next_branch_label = iseq.new_label("if_next_branch_target_#{index}")
            iseq.emit(:jump, [next_branch_label], rescue_label: rescue_label)
            iseq.place(body_label)
            iseq.emit(:exec, [body], line_number: if_tag.line_number, blank_tag: if_tag.blank?,
              terminal: true, rescue_label: rescue_label)
            end_jump = iseq.new_label("if_end_#{index}")
            end_jump_labels << end_jump
            iseq.emit(:jump, [end_jump], line_number: if_tag.line_number,
              rescue_label: rescue_label)
            # A non-matching condition continues with the next branch (or the
            # else body), which starts immediately after the body's end jump.
            iseq.place(next_branch_label)
          end
        end

        end_jump_labels.each { |label| iseq.place(label) }
      end

      # Emits short-circuiting tests for an and/or condition chain.
      #
      # The value of the final tested leaf remains on the stack, matching
      # Condition#evaluate, which returns the last interpreted result.
      def compile_condition_chain(iseq, condition, after_chain, line_number, node_rescue_label)
        current = condition
        while current
          iseq.emit(
            :test_leaf,
            [current.left, current.operator, current.right],
            line_number: line_number,
            rescue_label: node_rescue_label,
          )

          relation = current.child_relation
          break unless relation

          # For `or`, a truthy leaf short-circuits the whole chain; for `and`,
          # a falsey leaf does. Any other result continues to the next leaf.
          continue_leaf = iseq.new_label("if_continue_leaf_#{iseq.instructions.length}")
          short_circuit = iseq.new_label("if_short_circuit_#{iseq.instructions.length}")
          case relation
          when :or
            iseq.emit(:jump_if_true, [short_circuit], rescue_label: node_rescue_label)
          when :and
            iseq.emit(:jump_if_false, [short_circuit], rescue_label: node_rescue_label)
          end
          iseq.emit(:jump, [continue_leaf], rescue_label: node_rescue_label)
          iseq.place(short_circuit)
          iseq.emit(:jump, [after_chain], rescue_label: node_rescue_label)
          iseq.place(continue_leaf)
          current = current.child_condition
        end
      end

      def compile_for(iseq, for_tag, rescue_label)
        for_body = compile_block_body(for_tag.for_block, name: 'for:body')
        else_body = if for_tag.else_block
          compile_block_body(for_tag.else_block, name: 'for:else')
        end

        iseq.emit(:for, [for_tag, for_body, else_body], line_number: for_tag.line_number,
          blank_tag: for_tag.blank?, terminal: true, rescue_label: rescue_label)
      end
    end
  end
end
