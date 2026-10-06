# frozen_string_literal: true
module Slim
  module Splat
    # @api private
    class Filter < ::Slim::Filter
      define_options :merge_attrs, :attr_quote, :sort_attrs, :default_tag, :format, :disable_capture,
                     hyphen_attrs: %w(data aria), use_html_safe: ''.respond_to?(:html_safe?),
                     hyphen_underscore_attrs: false, xml_namespaces: false

      def call(exp)
        @splat_options = nil
        @namespace_context = nil
        @xml_scopes = [::Slim::XMLNamespaces::Scope.new]
        @xml_dynamic_depth = 0
        if options[:xml_namespaces]
          static_scope = ::Slim::XMLNamespaces::Scope.new.concrete_bindings.reject do |_, uri|
            uri.equal?(::Slim::XMLNamespaces::UNBOUND_NAMESPACE)
          end
        end
        exp = compile(exp)

        preamble = []
        if @splat_options
          opts = options.to_hash.reject { |k, v| !Filter.options.valid_key?(k) }.inspect
          preamble << [:code, "#{@splat_options} = #{opts}"]
        end
        if @namespace_context
          preamble << [:code, "#{@namespace_context} = ::Slim::XMLNamespaces::Context.new(#{static_scope.inspect})"]
        end
        preamble.empty? ? exp : [:multi, *preamble, exp]
      end

      # Handle tag expression
      def on_html_tag(name, attrs, content = nil)
        return on_xml_tag(name, attrs, content) if options[:xml_namespaces]
        return super if name != '*'

        builder, block = make_builder(attrs[2..-1])
        if content
          [:multi,
           block,
           [:slim, :output, false,
            "#{builder}.build_tag #{empty_exp?(content) ? '{}' : 'do'}",
            compile(content)]]
        else
          [:multi,
           block,
           [:dynamic, "#{builder}.build_tag"]]
        end
      end

      # Handle attributes expression
      def on_html_attrs(*attrs)
        if attrs.any? { |attr| splat?(attr) }
          builder, block = make_builder(attrs)
          [:multi,
           block,
           [:dynamic, "#{builder}.build_attrs"]]
        else
          super
        end
      end

      protected

      def on_multi(*exps)
        return super unless options[:xml_namespaces] && @xml_dynamic_depth > 0

        @xml_dynamic_depth += 1
        result = [:multi, *exps.map { |exp| compile(exp) }]
        @xml_dynamic_depth -= 1
        result
      end

      def on_xml_tag(name, attrs, content)
        tag_attrs = attrs[2..-1]
        use_builder = @xml_dynamic_depth > 0 ||
                      tag_attrs.any? { |attr| splat?(attr) || xml_declaration?(attr) } ||
                      dynamic_xml_scope?
        unless use_builder
          return xml_plain_tag(name, attrs, content)
        end

        scope = @xml_scopes.last.child(xml_declaration_bindings(tag_attrs))
        @xml_scopes.push(scope)
        builder, block = make_builder(tag_attrs)
        if content
          begin
            [:multi,
             block,
             [:slim, :output, false,
              "#{builder}.build_tag(name: #{name.inspect}) do",
              xml_tag_content(builder, tag_attrs, content)]]
          ensure
            @xml_scopes.pop
          end
        else
          @xml_scopes.pop
          [:multi,
           block,
           [:dynamic, "#{builder}.build_tag(name: #{name.inspect})"]]
        end
      end

      def xml_declaration?(attr)
        attr[0] == :html && attr[1] == :attr && ::Slim::XMLNamespaces.declaration?(attr[2])
      end

      def dynamic_xml_scope?
        @xml_scopes.last.bindings.values.any? do |uri|
          uri.equal?(::Slim::XMLNamespaces::DYNAMIC_NAMESPACE)
        end
      end

      def xml_plain_tag(name, attrs, content)
        result = [:html, :tag, name, compile(attrs)]
        result << compile(content) if content
        result
      end

      def xml_declaration_bindings(attrs)
        attrs.each_with_object({}) do |attr, result|
          next unless xml_declaration?(attr)

          prefix = ::Slim::XMLNamespaces.declaration_prefix(attr[2])
          uri = ::Slim::XMLNamespaces.static_literal(attr[3])
          result[prefix] = uri.nil? ? ::Slim::XMLNamespaces::DYNAMIC_NAMESPACE : uri
        end
      end

      def xml_tag_content(builder, attrs, content)
        if attrs.any? { |attr| attr[0] == :slim && attr[1] == :splat }
          frame = unique_name
          @xml_dynamic_depth += 1
          begin
            [:multi,
             [:code, "#{frame} = #{builder}.namespace_context.dynamic_frame!"],
             compile(content),
             [:code, "#{frame}.pop_frame!"]]
          ensure
            @xml_dynamic_depth -= 1
          end
        else
          compile(content)
        end
      end

      def xml_static_attr_key(attr)
        name = attr[2]
        if ::Slim::XMLNamespaces.declaration?(name)
          return 'nil' if ::Slim::XMLNamespaces.static_literal(attr[3]).nil?
          [::Slim::XMLNamespaces::XMLNS_NAMESPACE,
           ::Slim::XMLNamespaces.declaration_prefix(name) || 'xmlns'].inspect
        else
          @xml_scopes.last.static_resolve(name, true).inspect
        end
      end

      def splat?(attr)
        attr[0] == :slim && attr[1] == :splat ||
          (attr[0] == :html && attr[1] == :attr && options[:hyphen_attrs].include?(attr[2]) &&
           attr[3][0] == :slim && attr[3][1] == :attrvalue)
      end

      def make_builder(attrs)
        @splat_options ||= unique_name
        builder = unique_name
        result = [:multi, [:code, "#{builder} = ::Slim::Splat::Builder.new(#{@splat_options})"]]
        if options[:xml_namespaces]
          @namespace_context ||= unique_name
          result << [:code, "#{builder}.namespace_context = #{@namespace_context}"]
        end

        attrs.each do |attr|
          result <<
            if attr[0] == :html && attr[1] == :attr
              if attr[3][0] == :slim && attr[3][1] == :attrvalue
                [:code, "#{builder}.code_attr(#{attr[2].inspect}, #{attr[3][2]}, (#{attr[3][3]}))"]
              else
                tmp = unique_name
                key = options[:xml_namespaces] ? xml_static_attr_key(attr) : nil
                [:multi,
                 [:capture, tmp, compile(attr[3])],
                 [:code, "#{builder}.attr(#{attr[2].inspect}, #{tmp}, false, #{key})"]]
              end
            elsif attr[0] == :slim && attr[1] == :splat
              [:code, "#{builder}.splat_attrs((#{attr[2]}))"]
            else
              attr
            end
        end
        [builder, result]
      end
    end
  end
end
