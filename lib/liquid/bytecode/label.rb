# frozen_string_literal: true

module Liquid
  module Bytecode
    # Placeholder instruction marking a jump target. Labels are removed and
    # resolved to integer instruction addresses during finalization.
    class Label
      attr_accessor :index
      attr_reader :name

      def initialize(name = nil)
        @name  = name
        @index = nil
      end

      def inspect
        "#<Liquid::Bytecode::Label #{@name}#{@index ? " @#{@index}" : ''}>"
      end
    end
  end
end
