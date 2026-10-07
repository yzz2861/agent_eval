# frozen_string_literal: true
module Slim
  # @api private
  class CodeAttributes < Filter
    define_options :merge_attrs

    # Handle attributes expression `[:html, :attrs, *attrs]`
    #
    # @param [Array] attrs Array of temple expressions
    # @return [Array] Compiled temple expression
    def on_html_attrs(*attrs)
      [:multi, *attrs.map { |a| compile(a) }]
    end

    # Handle attribute expression `[:html, :attr, name, value]`
    #
    # @param [String] name Attribute name
    # @param [Array] value Value expression
    # @return [Array] Compiled temple expression
    def on_html_attr(name, value)
      if value[0] == :slim && value[1] == :attrvalue && !options[:merge_attrs][name]
        # We handle the attribute as a boolean attribute
        escape, code = value[2], value[3]
        case code
        when 'true'
          [:html, :attr, name, [:multi]]
        when 'false', 'nil'
          [:multi]
        else
          tmp = unique_name
          [:multi,
           [:code, "#{tmp} = #{code}"],
           [:if, tmp,
            [:if, "#{tmp} == true",
             [:html, :attr, name, [:multi]],
             [:html, :attr, name, [:escape, escape, [:dynamic, tmp]]]]]]
        end
      else
        # Attribute with merging
        @attr = name
        super
      end
    end

    # Handle attribute expression `[:slim, :attrvalue, escape, code]`
    #
    # @param [Boolean] escape Escape html
    # @param [String] code Ruby code
    # @return [Array] Compiled temple expression
    def on_slim_attrvalue(escape, code)
      # We perform attribute merging on Array values, false and nil are not effective
      case rule = options[:merge_attrs][@attr]
      when String
        tmp = unique_name
        [:multi,
         [:code, "#{tmp} = #{code}"],
         [:if, "Array === #{tmp}",
          [:multi,
           [:code, "#{tmp} = #{tmp}.flatten"],
           [:code, "#{tmp}.map!(&:to_s)"],
           [:code, "#{tmp}.reject!(&:empty?)"],
           [:escape, escape, [:dynamic, "#{tmp}.join(#{rule.inspect})"]]],
          [:if, tmp,
           [:escape, escape, [:dynamic, tmp]]]]]
      when nil
        [:escape, escape, [:dynamic, code]]
      else
        # Attribute with :first, :last or :reject conflict rule
        tmp = unique_name
        [:multi,
         [:code, "#{tmp} = #{code}"],
         [:if, tmp,
          [:escape, escape, [:dynamic, tmp]]]]
      end
    end
  end
end
