# frozen_string_literal: true
module Slim
  # @api private
  class XMLNamespaces < Filter
    STATIC_TAG = :static_tag
    DYNAMIC_TAG = :dynamic_tag
    STATIC_XMLNS = :xmlns

    define_options xml_namespaces: false

    def call(exp)
      return exp unless options[:xml_namespaces]
      @tag_stack = []
      compile(exp)
    end

    def on_html_tag(name, attrs, content = nil)
      parent = @tag_stack.last
      outer_scope = parent ? parent[:scope] : Scope.new
      scope_expression = parent ? "#{parent[:builder]}.current_scope" : outer_scope.initializer

      declarations, attributes = partition_attrs(attrs)
      local_bindings = {}
      declaration_exps = []
      declaration_prefixes = {}

      declarations.each do |attr|
        prefix = declaration_prefix(attr[2])
        validate_declaration_prefix(prefix, attr[2])
        syntax_error!("Multiple namespace #{prefix.inspect} declarations") if declaration_prefixes[prefix]
        declaration_prefixes[prefix] = true
        value = static_value(attr[3])
        if value == :dynamic
          local_bindings[prefix] = :dynamic
          declaration_exps << compile(attr)
        elsif prefix && value.empty?
          syntax_error!("Invalid XML namespace declaration #{attr[2]}")
        else
          local_bindings[prefix] = value
          declaration_exps << [:slim, :xml, STATIC_XMLNS, attr[2], value]
        end
      end

      dynamic_scope = attributes.any? { |attr| attr[0] == :slim && attr[1] == :splat }
      tag_scope = outer_scope.merge(local_bindings, dynamic_scope)
      if name != '*'
        validate_name(name, tag_scope, :element)
      end

      seen = {}
      attributes.each do |attr|
        next unless attr[0] == :html && attr[1] == :attr
        expanded = expanded_name(attr[2], tag_scope)
        next if expanded == :dynamic
        syntax_error!("Multiple #{attr[2]} attributes specified") if seen[expanded]
        seen[expanded] = true
      end

      builder = unique_name(:slim_xml_ns)
      marker = [:slim, :xml, name == '*' ? DYNAMIC_TAG : STATIC_TAG, name == '*' ? nil : name]
      compiled_attrs = [:multi, marker]
      declaration_exps.each { |exp| compiled_attrs << exp }
      attributes.each { |attr| compiled_attrs << compile(attr) }

      @tag_stack << { scope: tag_scope, builder: builder }
      compiled_content = content ? compile(content) : nil
      @tag_stack.pop

      [:slim, :xml, :tag, builder, scope_expression, tag_scope.dynamic?, compiled_attrs, compiled_content]
    end

    private

    def partition_attrs(attrs)
      attrs[2..-1].partition do |attr|
        attr[0] == :html && attr[1] == :attr &&
          (attr[2] == 'xmlns' || attr[2].to_s.start_with?('xmlns:'))
      end
    end

    def declaration_prefix(name)
      name == 'xmlns' ? nil : name.split(':', 3)[1]
    end

    def static_value(exp)
      value = literal_value(exp)
      return value unless value.nil?
      return :nil if static_nil?(exp)
      :dynamic
    end

    def literal_value(exp)
      return nil unless exp
      case exp[0]
      when :multi
        values = exp[1..-1].map { |child| literal_value(child) }
        return nil if values.empty? || values.include?(nil)
        values.join
      when :static
        exp[1]
      when :escape
        literal_value(exp.last)
      end
    end

    def static_nil?(exp)
      exp.is_a?(Array) && exp[0] == :slim && exp[1] == :attrvalue && exp[3] == 'nil'
    end

    def expanded_name(name, scope, type = :attribute)
      prefix, local = scope.resolve(name, type)
      known = prefix.nil? || XMLNamespaces::Scope::BUILTIN.key?(prefix) || scope.bindings.key?(prefix)
      statically_known = known && (prefix.nil? || scope.static?(prefix))
      unless local && prefix != 'xmlns' && (statically_known || (!known && scope.dynamic?))
        qprefix = name.include?(':'.freeze) ? name.split(':'.freeze, 2).first : nil
        syntax_error!(qprefix ? "Unbound XML namespace prefix #{qprefix.inspect}" : 'Unbound default XML namespace')
      end
      return :dynamic unless known
      [prefix.nil? ? nil : scope.uri(prefix), local]
    end

    def validate_name(name, scope, type)
      prefix, local = scope.resolve(name, type)
      unbound = prefix && !XMLNamespaces::Scope::BUILTIN.key?(prefix) && !scope.bindings.key?(prefix) && !scope.dynamic?
      if !local || prefix == 'xmlns' || unbound
        qprefix = name.include?(':'.freeze) ? name.split(':'.freeze, 2).first : nil
        syntax_error!(qprefix ? "Unbound XML namespace prefix #{qprefix.inspect}" : 'Unbound default XML namespace')
      end
    end

    def validate_declaration_prefix(prefix, name)
      if prefix && (prefix.empty? || name.split(':'.freeze).size != 2 || prefix == 'xmlns')
        syntax_error!("Invalid XML namespace declaration #{name}")
      end
    end

    def syntax_error!(message)
      raise ::Slim::Parser::SyntaxError.new(message, options[:file], nil, 1, 1)
    end

    # @api private
    class Scope
      DYNAMIC = :__slim_xml_dynamic_namespace__
      BUILTIN = {
        'xml' => 'http://www.w3.org/XML/1998/namespace',
        'xmlns' => 'http://www.w3.org/2000/xmlns/'
      }.freeze

      attr_reader :bindings

      def initialize(bindings = nil, dynamic = false)
        @bindings = bindings || {}
        @dynamic = dynamic
      end

      def merge(local_bindings, dynamic = false)
        self.class.new(bindings.merge(local_bindings), @dynamic || dynamic)
      end

      def resolve(name, type)
        prefix, local = split(name)
        return nil unless local
        if prefix.nil?
          [nil, local]
        elsif BUILTIN.key?(prefix) || bindings.key?(prefix)
          [prefix, local]
        elsif @dynamic
          [prefix, local]
        end
      end

      def static?(prefix)
        return true if prefix.nil? || BUILTIN.key?(prefix)
        return false unless bindings.key?(prefix)
        bindings[prefix] != DYNAMIC
      end

      def dynamic?
        @dynamic
      end

      def uri(prefix)
        BUILTIN.fetch(prefix) { bindings[prefix] }
      end

      def initializer
        hash = bindings.reject { |_, value| value == DYNAMIC }
        "::Slim::XMLNamespaces::Scope.new(#{hash.inspect})"
      end

      private

      def split(name)
        parts = name.to_s.split(':'.freeze)
        return [nil, nil] if parts.size > 2 || parts.include?('')
        return [nil, parts.first] if parts.size == 1
        parts
      end
    end
  end
end
