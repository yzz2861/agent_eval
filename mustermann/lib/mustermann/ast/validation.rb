# frozen_string_literal: true
require 'mustermann/ast/translator'

module Mustermann
  module AST
    # Checks the AST for certain validations, like correct capture names.
    #
    # Internally a poor man's visitor (abusing translator to not have to implement a visitor).
    # @!visibility private
    class Validation < Translator
      # Strategies supported by the +duplicate_captures+ option.
      # @!visibility private
      DUPLICATE_STRATEGIES = %i[raise equal collect].freeze

      # Runs validations.
      #
      # @param [Mustermann::AST::Node] ast to be validated
      # @param [Hash] options pattern options (uses +duplicate_captures+)
      # @return [Mustermann::AST::Node] the validated ast
      # @raise [Mustermann::AST::CompileError] if validation fails
      # @!visibility private
      def self.validate(ast, duplicate_captures: :raise, **)
        unless DUPLICATE_STRATEGIES.include?(duplicate_captures)
          raise ArgumentError, "unsupported value %p for duplicate_captures, expected one of %p" % [duplicate_captures, DUPLICATE_STRATEGIES]
        end
        new.tap { |v| v.duplicate_strategy = duplicate_captures }.translate(ast)
        ast
      end

      # Counts how often every capture name occurs in the tree.
      # @return [Hash{String => Integer}]
      # @!visibility private
      def self.occurrences(ast) = Occurrences.translate(ast)

      translate(Object, :splat) {}
      translate(:node) { t(payload) }
      translate(Array) { each { |p| t(p)} }
      translate(:capture) { t.check_name(name, forbidden: ['captures', 'splat'])}
      translate(:variable, :named_splat) { t.check_name(name, forbidden: 'captures')}
      attr_accessor :duplicate_strategy

      # @raise [Mustermann::CompileError] if name is not acceptable
      # @!visibility private
      def check_name(name, forbidden: EMPTY_ARRAY)
        raise CompileError, "capture name can't be empty" if name.nil? or name.empty?
        raise CompileError, "capture name must start with underscore or lower case letter" unless name =~ /^[a-z_]/
        raise CompileError, "capture name can't be #{name}" if Array(forbidden).include? name
        raise CompileError, "can't use the same capture name twice" if duplicate_strategy == :raise and names.include?(name)
        names << name
      end

      # @return [Array<String>] list of capture names in tree
      # @!visibility private
      def names
        @names ||= []
      end
    end

    # Collects the names of all capturing nodes in order.
    # @!visibility private
    class Occurrences < Translator
      translate(Object) { EMPTY_ARRAY }
      translate(:node) { t(payload) }
      translate(Array) { flat_map { |p| t(p) } }
      translate(:capture, :variable, :named_splat) { [name] }

      def self.translate(ast) = new.translate(ast).tally
    end
  end
end
