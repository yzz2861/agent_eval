# frozen_string_literal: true

module Dry
  module Configurable
    # Setting compiler used internally by the DSL
    #
    # @api private
    class Compiler
      def call(ast)
        Settings.new.tap do |settings|
          ast.each do |node|
            settings << visit(node)
          end
        end
      end

      # @api private
      def visit(node)
        type, rest = node
        public_send(:"visit_#{type}", rest)
      end

      # @api private
      def visit_setting(node)
        name, opts = node
        Setting.new(name, **opts)
      end

      # @api private
      def visit_nested(node)
        parent, children = node
        name, opts = parent[1]

        Setting.new(name, **opts, children: Settings.new(call(children)))
      end

      # @api private
      def visit_member(node)
        Settings.new(call(node))
      end

      # @api private
      def visit_member_setting(node)
        parent, member_settings_ast = node
        name, opts = parent[1]

        Setting.new(
          name,
          **opts,
          member_settings: Settings.new(call(member_settings_ast))
        )
      end
    end
  end
end
