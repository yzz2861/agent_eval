# frozen_string_literal: true
module Slim
  # @api private
  class XMLSplatFilter < Splat::Filter
    define_options xml_namespaces: false

    def call(exp)
      return exp unless options[:xml_namespaces]
      @splat_options = nil
      exp = compile(exp)
      if @splat_options
        opts = options.to_hash.reject { |k, v| !Splat::Filter.options.valid_key?(k) }.inspect
        [:multi, [:code, "#{@splat_options} = #{opts}"], exp]
      else
        exp
      end
    end

    def on_slim_xml_tag(builder, scope, dynamic, attrs, content = nil)
      options_var = splat_options
      result = [:multi, [:code, "#{builder} = ::Slim::Splat::Builder.new(#{options_var}, #{scope}, true, #{dynamic})"]]
      compile(attrs)[1..-1].each do |attr|
        result << xml_attr_code(builder, attr)
      end
      if content
        result << [:slim, :output, false,
                   "#{builder}.build_tag #{empty_exp?(content) ? '{}' : 'do'}",
                   compile(content)]
      else
        result << [:dynamic, builder + '.build_tag']
      end
      result
    end

    private

    def splat_options
      @splat_options ||= unique_name(:slim_xml_options)
    end

    def xml_attr_code(builder, attr)
      case attr[0]
      when :slim
        case attr[1]
        when :xml
          case attr[2]
          when XMLNamespaces::STATIC_TAG
            [:code, "#{builder}.static_tag(#{attr[3].inspect})"]
          when XMLNamespaces::DYNAMIC_TAG
            [:multi]
          when XMLNamespaces::STATIC_XMLNS
            [:code, "#{builder}.xmlns_attr(#{attr[3].inspect}, #{attr[4].inspect})"]
          else
            attr
          end
        when :splat
          [:code, "#{builder}.splat_attrs((#{attr[2]}))"]
        else
          attr
        end
      when :html, :attr
        if attr[3][0] == :slim && attr[3][1] == :attrvalue
          [:code, "#{builder}.code_attr(#{attr[2].inspect}, #{attr[3][2]}, (#{attr[3][3]}))"]
        else
          tmp = unique_name(:slim_xml_attr)
          [:multi,
           [:capture, tmp, attr[3]],
           [:code, "#{builder}.attr(#{attr[2].inspect}, #{tmp})"]]
        end
      else
        attr
      end
    end
  end
end
