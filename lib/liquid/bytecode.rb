# frozen_string_literal: true

require 'liquid/bytecode/instruction'
require 'liquid/bytecode/loop_descriptor'
require 'liquid/bytecode/program'
require 'liquid/bytecode/compiler'
require 'liquid/bytecode/vm'

module Liquid
  # Experimental bytecode execution path.
  #
  # A parsed Liquid::Document can be compiled once with Liquid::Bytecode.compile
  # into a Liquid::Bytecode::Program and rendered repeatedly with
  # Liquid::Bytecode.render. The compiler accepts only text, variable/filter
  # output, assign, if/unless and for (with break/continue) and raises
  # Liquid::Bytecode::Compiler::UnsupportedTagError for anything else.
  module Bytecode
    class << self
      # Compiles a parsed Liquid::Template (or Document) to a Program.
      def compile(template_or_document)
        document = template_or_document.respond_to?(:root) ? template_or_document.root : template_or_document
        Compiler.compile(document)
      end

      # Executes a compiled Program against a Liquid::Context.
      def render(program, context, output = +'')
        VM.execute(program, context, output)
      end

      # Convenience: compiles and renders a template in one call.
      def render_template(template, context, output = +'')
        render(compile(template), context, output)
      end
    end
  end
end
