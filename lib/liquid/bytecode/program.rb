# frozen_string_literal: true

module Liquid
  module Bytecode
    # A finalized, reusable, immutable compiled template.
    class Program
      attr_reader :iseq

      def initialize(iseq)
        @iseq = iseq
      end

      def disassemble
        Disassembler.new.disassemble(@iseq)
      end
    end
  end
end
