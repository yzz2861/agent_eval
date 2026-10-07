# frozen_string_literal: true
module Slim
  # This filter resolves conflicts between multiple html attributes
  # of the same name according to the rules configured in the
  # :merge_attrs option:
  #
  # - String delimiter: values are joined with the delimiter
  # - :first: the first effective value wins
  # - :last: the last effective value wins
  # - :reject: an error is raised (default for unlisted attributes)
  #
  # Values of false and nil are not effective and never occupy
  # the attribute name.
  #
  # @api private
  class AttributeMerger < Filter
    define_options merge_attrs: {'class' => ' '}

    def initialize(opts = {})
      super
      options[:merge_attrs].each do |name, rule|
        unless String === rule || rule == :first || rule == :last || rule == :reject
          raise ArgumentError, "Invalid :merge_attrs rule #{rule.inspect} for attribute #{name.inspect} " \
                               '(expected a String delimiter, :first, :last or :reject)'
        end
      end
    end

    # Handle attributes expression `[:html, :attrs, *attrs]`
    #
    # @param [Array] attrs Array of temple expressions
    # @return [Array] Compiled temple expression
    def on_html_attrs(*attrs)
      values = {}

      attrs.each do |_, _, name, value|
        name = name.to_s
        if values[name]
          rule = options[:merge_attrs][name]
          unless String === rule || rule == :first || rule == :last
            raise(::Temple::FilterError, "Multiple #{name} attributes specified")
          end
          values[name] << value
        else
          values[name] = [value]
        end
      end

      attrs = values.map do |name, value|
        exp =
          if value.size > 1
            case rule = options[:merge_attrs][name]
            when String
              merge_values(value, rule)
            when :first, :last
              select_value(value, rule)
            end
          else
            value.first
          end
        [:html, :attr, name, exp]
      end
      [:html, :attrs, *attrs]
    end

    private

    # Join multiple attribute values with the delimiter,
    # empty values are dropped
    def merge_values(values, delimiter)
      exp = [:multi]
      if values.all? {|v| contains_nonempty_static?(v) }
        exp << values.first
        values[1..-1].each {|v| exp << [:static, delimiter] << v }
      else
        captures = unique_name
        exp << [:code, "#{captures} = []"]
        values.each_with_index {|v, i| exp << [:capture, "#{captures}[#{i}]", v] }
        exp << [:dynamic, "#{captures}.reject(&:empty?).join(#{delimiter.inspect})"]
      end
      exp
    end

    # Select the first/last effective (non-empty) attribute value
    def select_value(values, rule)
      if values.all? {|v| static_string(v) }
        effective = values.reject {|v| static_string(v).empty? }
        (rule == :first ? effective.first : effective.last) || [:multi]
      else
        captures = unique_name
        exp = [:multi, [:code, "#{captures} = []"]]
        values.each_with_index {|v, i| exp << [:capture, "#{captures}[#{i}]", v] }
        exp << [:dynamic, "#{captures}.reject(&:empty?).#{rule}"]
        exp
      end
    end

    # Return the string if the expression is fully static, nil otherwise
    def static_string(exp)
      case exp[0]
      when :static
        exp[1]
      when :escape
        exp[2][0] == :static ? exp[2][1] : nil
      end
    end
  end
end
