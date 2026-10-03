# frozen_string_literal: true
require 'mustermann/ast/translator'

module Mustermann
  module AST
    # Checks the AST for certain validations, like correct capture names.
    #
    # Internally a poor man's visitor (abusing translator to not have to implement a visitor).
    # @!visibility private
    class Validation < Translator
      # Strategies for handling duplicate capture names.
      # @!visibility private
      ON_DUPLICATE = [nil, :error, :check, :collect].freeze

      # Runs validations.
      #
      # @param [Mustermann::AST::Node] ast to be validated
      # @param [Symbol] on_duplicate how to handle duplicate capture names:
      #   +nil+ or +:error+ rejects them (the default), +:check+ requires all
      #   occurrences to be equal, +:collect+ collects all values in order
      # @return [Mustermann::AST::Node] the validated ast
      # @raise [Mustermann::AST::CompileError] if validation fails
      # @raise [ArgumentError] if on_duplicate is not a supported strategy
      # @!visibility private
      def self.validate(ast, on_duplicate: nil)
        new(on_duplicate: on_duplicate).translate(ast)
        ast
      end

      # @!visibility private
      def initialize(on_duplicate: nil)
        unless ON_DUPLICATE.include? on_duplicate
          raise ArgumentError, "unsupported on_duplicate strategy %p, expected :check or :collect" % on_duplicate
        end
        @allow_duplicates = on_duplicate == :check || on_duplicate == :collect
        super()
      end

      translate(Object, :splat) {}
      translate(:node) { t(payload) }
      translate(Array) { each { |p| t(p)} }
      translate(:capture) { t.check_name(name, forbidden: ['captures', 'splat'])}
      translate(:variable, :named_splat) { t.check_name(name, forbidden: 'captures')}

      # @raise [Mustermann::CompileError] if name is not acceptable
      # @!visibility private
      def check_name(name, forbidden: EMPTY_ARRAY)
        raise CompileError, "capture name can't be empty" if name.nil? or name.empty?
        raise CompileError, "capture name must start with underscore or lower case letter" unless name =~ /^[a-z_]/
        raise CompileError, "capture name can't be #{name}" if Array(forbidden).include? name
        raise CompileError, "can't use the same capture name twice" if !@allow_duplicates && names.include?(name)
        names << name
      end

      # @return [Array<String>] list of capture names in tree
      # @!visibility private
      def names
        @names ||= []
      end
    end
  end
end
