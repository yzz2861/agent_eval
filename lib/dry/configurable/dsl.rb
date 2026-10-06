# frozen_string_literal: true

module Dry
  module Configurable
    # Setting DSL used by the class API
    #
    # @api private
    class DSL
      VALID_NAME = /\A[a-z_]\w*\z/i

      # Method names defined on `Data` (and its ancestors) that cannot be used as setting
      # names because `Data.define` would reject them, which would break {Config#to_data}.
      DATA_RESERVED_NAMES = ::Data.instance_methods.to_set.freeze

      attr_reader :compiler

      attr_reader :ast

      attr_reader :options

      def initialize(member_allowed: false, **options, &block)
        @compiler = Compiler.new
        @ast = []
        @options = options.merge(member_allowed: member_allowed)
        instance_exec(&block) if block
      end

      # Registers a new setting node and compile it into a setting object
      #
      # @see ClassMethods.setting
      # @api private
      # @return Setting
      def setting(name, **options, &block)
        member_allowed = options.delete(:member_allowed) { true }

        unless VALID_NAME.match?(name.to_s)
          raise ArgumentError, "#{name} is not a valid setting name"
        end

        if DATA_RESERVED_NAMES.include?(name.to_sym)
          raise ArgumentError,
            "#{name.inspect} is not a valid setting name: it conflicts with a Data " \
            "instance method, which would break Config#to_data"
        end

        ensure_valid_options(options)

        options = {default: default, config_class: config_class, **options}

        node = [:setting, [name.to_sym, options]]

        if block
          child_ast = DSL.new(**@options, member_allowed: member_allowed, &block).ast
          member_node = child_ast.first if child_ast.one? && child_ast.first.first == :member

          if child_ast.any? { |child_node| child_node.first == :member } && member_node.nil?
            raise ArgumentError, "member cannot be mixed with other settings"
          end

          if member_node
            ast << [:member_setting, [node, member_node.last]]
          else
            ast << [:nested, [node, child_ast]]
          end
        else
          ast << node
        end

        compiler.visit(ast.last)
      end

      # Registers a member schema and compiles it into settings
      #
      # @api private
      def member(&block)
        raise ArgumentError, "member requires a block" unless block

        unless @options.fetch(:member_allowed, false)
          raise ArgumentError, "member can only be declared directly within a setting block"
        end

        ast << [:member, DSL.new(**@options, member_allowed: false, &block).ast]

        compiler.visit(ast.last)
      end

      def config_class
        options[:config_class]
      end

      def default
        options[:default_undefined] ? Undefined : nil
      end

      private

      def ensure_valid_options(options)
        return if options.none?

        invalid_keys = options.keys - Setting::OPTIONS

        raise ArgumentError, "Invalid options: #{invalid_keys.inspect}" unless invalid_keys.empty?
      end

      # Returns a tuple of valid and invalid options hashes derived from the options hash
      # given to the setting
      def valid_and_invalid_options(options)
        options.partition { |k, _| Setting::OPTIONS.include?(k) }.map(&:to_h)
      end
    end
  end
end
