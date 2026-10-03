# frozen_string_literal: true
require 'mustermann'
require 'mustermann/error'
require 'strscan'

module Mustermann
  class Template < AST::Pattern
    # Direct, RFC 6570 compliant expansion for URI templates.
    #
    # In contrast to the generic {Mustermann::Expander}, this renderer walks
    # the raw template AST and therefore supports every operator (path style,
    # query style, fragments, dot/path segments, lists and maps) and allows
    # partial expansion (see {Mustermann::Template#expand_partial}).
    #
    # @!visibility private
    class Expansion
      # Per-operator rendering metadata (RFC 6570 section 3.2.1).
      #
      # first:   separator introduced before the first rendered variable
      # sep:     separator between two rendered variables
      # named:   whether values are rendered as `name=value`
      # ifemp:   separator between name and an empty value
      # reserve: whether reserved characters may stay unescaped in values
      Operator = Struct.new(:first, :sep, :named, :ifemp, :reserve, keyword_init: true)

      OPERATORS = {
        nil => Operator.new(first: '',  sep: ',', named: false, ifemp: '',  reserve: false),
        ?+  => Operator.new(first: '',  sep: ',', named: false, ifemp: '',  reserve: true),
        ?#  => Operator.new(first: ?#,  sep: ',', named: false, ifemp: '',  reserve: true),
        ?.  => Operator.new(first: ?.,  sep: '.', named: false, ifemp: '',  reserve: false),
        ?/  => Operator.new(first: ?/,  sep: '/', named: false, ifemp: '',  reserve: false),
        ?;  => Operator.new(first: ?;,  sep: ';', named: true,  ifemp: '',  reserve: false),
        ??  => Operator.new(first: ??,  sep: '&', named: true,  ifemp: '=', reserve: false),
        ?&  => Operator.new(first: ?&,  sep: '&', named: true,  ifemp: '=', reserve: false)
      }.freeze

      UNRESERVED = /[A-Za-z0-9\-._~]/
      RESERVED   = %r{[:/?#\[\]@!$&'()*+,;=]}
      TRIPLET    = /%(?=[0-9A-Fa-f]{2})[0-9A-Fa-f]{2}/
      LITERAL    = /[A-Za-z0-9\-._~%\/?#&=;,+:@\[\]!$'()*]/

      # @param pattern [Mustermann::Template] pattern to expand
      # @param values [Hash] values known so far
      # @param behavior [Symbol, nil] how to deal with unknown keys
      def initialize(pattern, values = EMPTY_HASH, behavior = nil)
        @pattern  = pattern
        @behavior = behavior
        @values   = normalize(values)
        @known    = flatten_keys(pattern.send(:raw_ast))
        validate_keys unless behavior == :ignore
      end

      # Full expansion. Raises {Mustermann::ExpandError} if a variable is missing.
      # @return [String]
      def expand
        render(:full)
      end

      # Partial expansion: expands known variables and keeps valid URI
      # template expressions for everything still unknown.
      # @return [Mustermann::Template::PartialExpansion]
      def expand_partial
        template = render(:partial)
        PartialExpansion.new(template, behavior: @behavior)
      end

      # @return [Array<Symbol>] variable names present in the template
      def known_keys
        @known.dup
      end

      # Percent-encodes an extra query key/value (used for +:append+).
      # @param [Object] value value to encode
      # @return [String]
      def encode(value)
        escape_value(stringify(value), false)
      end

      private

      def normalize(values)
        hash = values.respond_to?(:to_hash) ? values.to_hash : values.to_h
        hash.each_with_object({}) { |(key, value), normalized| normalized[key.to_sym] = value }
      rescue NoMethodError
        raise ExpandError, "cannot expand from %p, expected a Hash" % values
      end

      def validate_keys
        extra = @values.keys - @known
        return if extra.empty?
        raise ExpandError, "cannot expand with keys %p, possible expansions: %s" %
          [extra.sort, @known.sort]
      end

      def flatten_keys(node)
        case node
        when AST::Node::Variable then [node.name.to_sym]
        when AST::Node then Array(node.payload).flat_map { |child| flatten_keys(child) }
        else []
        end.uniq
      end

      def render(mode)
        missing  = []
        @missing = missing
        validate_order if mode == :partial
        result   = render_node(@pattern.send(:raw_ast), mode)
        unless missing.empty?
          raise ExpandError, "missing values for %p while expanding %p" % [missing, @pattern.to_s]
        end
        result
      end

      # Within an expression values have to be supplied in order: once an
      # earlier variable is unknown, a value for a later variable in the same
      # expression would be ambiguous (continuations change their operator
      # depending on what was rendered). Independent later expressions (e.g.
      # the query part after a path variable) may be expanded freely.
      def validate_order
        each_expression(@pattern.send(:raw_ast)) do |expression|
          seen_unknown = nil
          expression.payload.each do |variable|
            name = variable.name.to_sym
            provided = @values.key?(name) && !@values[name].nil?
            if provided && seen_unknown
              raise ExpandError,
                "cannot expand %p: %p is missing but %p was given" % [@pattern.to_s, seen_unknown, name.to_s]
            elsif !provided
              seen_unknown ||= variable.name
            end
          end
        end
      end

      def each_expression(node)
        case node
        when AST::Node::Expression then yield(node)
        when AST::Node then Array(node.payload).each { |child| each_expression(child) { |e| yield(e) } }
        end
      end

      def render_node(node, mode)
        case node
        when AST::Node::Root, AST::Node::Group then render_children(node, mode)
        when AST::Node::Expression then render_expression(node, mode)
        when AST::Node::Char then escape_literal(node.payload)
        when AST::Node::Separator then node.payload
        end
      end

      def render_children(node, mode)
        node.payload.map { |child| render_node(child, mode) }.join
      end

      def render_expression(node, mode)
        operator  = OPERATORS.fetch(node.operator) { raise ExpandError, "%p operator not supported" % node.operator }
        rendered  = +EMPTY_STRING
        remaining = []

        node.payload.each do |variable|
          name = variable.name.to_sym
          defined = @values.key?(name) && !@values[name].nil? &&
            !(mode == :partial && empty_collection?(@values[name]))
          if remaining.empty? && defined
            fragment = render_variable(variable, @values[name], operator)
            unless fragment.nil?
              rendered << (rendered.empty? ? operator.first : operator.sep)
              rendered << fragment
            end
          else
            remaining << variable
          end
        end

        unless remaining.empty?
          if mode == :full && !operator.named
            @missing.concat(remaining.map { |variable| variable.name.to_sym })
          elsif mode == :partial
            rendered << residual_expression(node.operator, remaining, rendered.empty?)
          end
        end
        rendered
      end

      # Rebuilds a valid URI template expression for the remaining variables.
      # When variables have already been rendered, the operator's first
      # separator is spelled with the matching continuation operator (a
      # query start `?` becomes `&`, while the comma family keeps a literal
      # comma and a plain expression).
      def residual_expression(operator_char, variables, untouched)
        body   = variables.map { |variable| variable_source(variable) }.join(?,)
        return "{#{operator_char}#{body}}" if untouched
        case operator_char
        when nil then ",{#{body}}"
        when ?+  then ",{+#{body}}"
        when ?#  then ",{+#{body}}"
        when ?? then "{&#{body}}"
        else "{#{operator_char}#{body}}"
        end
      end

      def variable_source(variable)
        source = variable.name.dup
        source << ?: << variable.prefix if variable.prefix
        source << variable.explode      if variable.explode
        source
      end

      def empty_collection?(value)
        (value.is_a?(Array) || value.is_a?(Hash)) && value.empty?
      end

      def render_variable(variable, value, operator)
        name = variable.name
        case value
        when Hash
          raise ExpandError, "prefix modifier is not allowed for map variable %p" % name if variable.prefix
          render_map(name, value, variable, operator)
        when Array
          raise ExpandError, "prefix modifier is not allowed for list variable %p" % name if variable.prefix
          return nil if value.empty?
          render_list(name, value, variable, operator)
        else
          scalar = stringify(value, name)
          scalar = scalar[0, variable.prefix.to_i] if variable.prefix
          escaped = escape_value(scalar, operator.reserve)
          if operator.named
            escaped.empty? ? "#{name}#{operator.ifemp}" : "#{name}=#{escaped}"
          else
            escaped
          end
        end
      end

      def render_list(name, list, variable, operator)
        elements = list.map { |element| escape_value(stringify(element, name), operator.reserve) }
        if variable.explode
          if operator.named
            elements.map { |element| element.empty? ? name : "#{name}=#{element}" }.join(operator.sep)
          else
            elements.join(operator.sep)
          end
        else
          joined = elements.join(?,)
          operator.named ? "#{name}=#{joined}" : joined
        end
      end

      def render_map(name, map, variable, operator)
        pairs = map.map do |key, value|
          [escape_value(stringify(key, name), operator.reserve),
           escape_value(stringify(value, name), operator.reserve)]
        end
        if variable.explode
          pairs.map do |key, value|
            if operator.named
              value.empty? ? key : "#{key}=#{value}"
            else
              "#{key}=#{value}"
            end
          end.join(operator.sep)
        else
          joined = pairs.flat_map { |key, value| [key, value] }.join(?,)
          operator.named ? "#{name}=#{joined}" : joined
        end
      end

      def stringify(value, name = nil)
        return value.to_str if begin; value.respond_to?(:to_str); rescue StandardError; false; end
        return value.to_s   if begin; value.respond_to?(:to_s); rescue StandardError; false; end
        raise ExpandError, "cannot use %p as value for %p" % [value, name]
      end

      # Percent-encodes an expanded value. Already percent-encoded triplets
      # (e.g. %2F) are passed through untouched, so expanding a template in
      # several steps never double-encodes them.
      def escape_value(string, reserved)
        return string if string.ascii_only? && string =~ /\A[\w\-\.~]*\Z/
        result  = +''
        scanner = StringScanner.new(string)
        until scanner.eos?
          if matched = scanner.scan(TRIPLET)
            result << matched
          elsif matched = scanner.scan(/[^%]+/)
            result << escape_plain(matched, reserved)
          else
            result << '%25'
            scanner.pos += 1
          end
        end
        result
      end

      def escape_plain(string, reserved)
        string.each_char.map do |char|
          if char =~ UNRESERVED || (reserved && char =~ RESERVED)
            char
          else
            char.bytes.map { |byte| '%%%02X' % byte }.join
          end
        end.join
      end

      # Escapes literal characters from the pattern. Existing percent
      # encodings are preserved so chained expansions never double-encode.
      def escape_literal(string)
        return string if string.ascii_only? && string =~ /\A#{LITERAL.source}\Z/
        escape_value(string, false)
      end
    end

    # Result of a partial expansion: a URI template that still contains
    # expressions for values not yet supplied.
    #
    # @example
    #   partial = Mustermann.new('/t/{tenant}/{id}', type: :template).
    #     expand_partial(tenant: 'acme')
    #   partial.to_s            # => "/t/acme/{id}"
    #   partial.expand(id: 42)  # => "/t/acme/42"
    class PartialExpansion
      # @param template [String] remaining URI template
      # @param behavior [Symbol, nil] additional-values behavior
      def initialize(template, behavior: nil)
        @template = template
        @behavior = behavior
      end

      # @return [String] the partially expanded URI template
      def to_s
        @template.dup
      end

      alias_method :to_str, :to_s

      # @return [Mustermann::Template] pattern matching the remaining template
      def to_pattern
        Mustermann::Template.new(@template)
      end

      # Supplies more values; variables still missing stay in the template.
      # @param (see Mustermann::Template#expand_partial)
      # @return [Mustermann::Template::PartialExpansion]
      def expand_partial(behavior = nil, **values)
        behavior, values = nil, behavior if behavior.is_a?(Hash)
        to_pattern.expand_partial(behavior || @behavior, **values)
      end

      # Supplies the remaining values and produces the final link.
      # @param (see Mustermann::Template#expand_partial)
      # @return [String] fully expanded URI
      # @raise [Mustermann::ExpandError] if a variable is still missing
      def expand(behavior = nil, **values)
        behavior, values = nil, behavior if behavior.is_a?(Hash)
        to_pattern.expand(behavior || @behavior, **values)
      end

      # @return [Boolean] whether any variables are still missing
      def partial?
        @template.include?(?{)
      end

      def inspect
        "#<#{self.class.name}: #{@template.inspect}>"
      end

      def ==(other)
        to_s == other.to_s
      end
    end
  end
end
