# frozen_string_literal: true

module Liquid
  # Experimental bytecode execution path.
  #
  # A parsed Liquid document can be compiled into an explicit sequence of
  # instructions (see Liquid::Bytecode::Compiler) and executed by a small stack
  # based virtual machine (see Liquid::Bytecode::VM) instead of walking the
  # interpreted AST. The instruction stream can be disassembled for debugging
  # (see Liquid::Bytecode::Disassembler).
  #
  # This path never generates Ruby source code and never calls eval.
  module Bytecode
    # Raised at compile time when the document contains a tag or node that the
    # experimental compiler does not support yet.
    class UnsupportedSyntaxError < SyntaxError
    end

    class << self
      # Compiles a Liquid::Template (or Liquid::Document) into a reusable
      # bytecode Program.
      def compile(template_or_document)
        document = if template_or_document.is_a?(Template)
          template_or_document.root
        else
          template_or_document
        end
        Program.new(Compiler.new.compile_block_body(document.body, name: 'document'))
      end

      # Executes a compiled Program against a Context, writing into output.
      def execute(program, context, output)
        VM.new(context, output).run(program)
      end

      # Returns the human readable disassembly of a Program or Template.
      def disassemble(program_or_template)
        program = program_or_template.is_a?(Program) ? program_or_template : compile(program_or_template)
        Disassembler.new.disassemble(program.iseq)
      end
    end
  end
end

require_relative 'bytecode/label'
require_relative 'bytecode/instruction'
require_relative 'bytecode/instruction_sequence'
require_relative 'bytecode/compiler'
require_relative 'bytecode/vm'
require_relative 'bytecode/program'
require_relative 'bytecode/disassembler'
