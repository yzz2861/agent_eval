# frozen_string_literal: true
require 'mustermann/ast/translator'

module Mustermann
  module AST
    # Expands RFC 6570 URI template expressions while allowing some variables
    # to remain unknown.
    #
    # Known variables are expanded into literal URI text, unknown variables
    # are kept as URI template expressions that may be expanded in a later
    # pass. Expanding a set of values in one call or in several calls always
    # produces the same result.
    #
    # @!visibility private
    class PartialExpander < Translator
      raises ExpandError

      # Per-operator behavior.
      #
      # @param separator [String] separator placed between two values
      # @param prefix [String, nil] prefix placed in front of the first value
      # @param reserved [Boolean] reserved characters stay unescaped
      # @param named [Boolean] the variable name is emitted (; ? &)
      # @param continuation [String] operator used for a trailing expression
      #   that holds the remaining unknown variables
      # @param continuation_separator [String, nil] literal separator emitted
      #   before the trailing expression (needed for reserved expansions)
      SETTINGS = {
        ?,   => { separator: ?,, prefix: ?,, reserved: false, named: false,
                  continuation: ?,, continuation_separator: nil },
        nil => { separator: ?,, prefix: nil, reserved: false, named: false,
                 continuation: ?,, continuation_separator: nil },
        ?+  => { separator: ?,, prefix: nil, reserved: true,  named: false,
                 continuation: ?+, continuation_separator: ?, },
        ?#  => { separator: ?,, prefix: ?#, reserved: true,  named: false,
                 continuation: ?+, continuation_separator: ?, },
        ?.  => { separator: ?., prefix: ?., reserved: false, named: false,
                 continuation: ?., continuation_separator: nil },
        ?/  => { separator: ?/, prefix: ?/, reserved: false, named: false,
                 continuation: ?/, continuation_separator: nil },
        ?;  => { separator: ?;, prefix: ?;, reserved: false, named: true,
                 continuation: ?;, continuation_separator: nil },
        ??  => { separator: ?&, prefix: ??, reserved: false, named: true,
                 continuation: ?&, continuation_separator: nil },
        ?&  => { separator: ?&, prefix: ?&, reserved: false, named: true,
                 continuation: ?&, continuation_separator: nil }
      }.freeze

      # RFC 6570 unreserved characters.
      UNRESERVED = /[A-Za-z0-9\-._~]/

      # Characters allowed to stay unescaped during reserved expansion (+, #):
      # the unreserved set plus the RFC 3986 reserved set.
      RESERVED_PASS = /[A-Za-z0-9\-._~:\/?#\[\]@!$&'()*+,;=]/

      # Sentinel for variables that have no value in the current expansion pass.
      UNKNOWN = Object.new.freeze

      # Fully expands the template and raises if a variable is missing.
      # @param ast [Mustermann::AST::Node] raw (untransformed) template AST
      # @param values [Hash{Symbol, String => Object}] variable values
      # @return [String] expanded URI
      def self.expand(ast, values)
        expander = new
        result   = expander.translate(ast, values: values)
        if expander.missing_keys.any?
          names = expander.missing_keys.uniq.sort.map(&:inspect).join(", ")
          raise ExpandError, "missing values for %s" % names
        end
        result
      end

      # Expands known variables and keeps a template for the unknown ones.
      # @param (see .expand)
      # @return [String] partially expanded template string
      def self.partial_expand(ast, values)
        new.translate(ast, values: values)
      end

      # Expands known variables and drops unknown ones, yielding a plain URI.
      # @param (see .partial_expand)
      # @return [String] expanded URI with unknown variables omitted
      def self.expand_known(ast, values)
        new.translate(ast, values: values, keep_unknown: false)
      end

      # Appends additional key/value pairs to a URI as a query string, using
      # the same escaping rules as {Mustermann::Expander#append}.
      # @param uri [String] URI to append to
      # @param values [Hash{#to_s => #to_s}] extra query parameters
      # @return [String]
      def self.append_query(uri, values)
        return uri if values.empty?
        expander = new
        entries = values.map do |key, value|
          "#{expander.escape_additional(key)}=#{expander.escape_additional(value)}"
        end
        "#{uri}#{uri.include?(??) ? ?& : ??}#{entries.join(?&)}"
      end

      # @return [Array<Symbol>] names of variables encountered without a value
      attr_reader :missing_keys

      def initialize(*)
        @missing_keys = []
        super
      end

      translate(:root, :group) do |*_args, values:, keep_unknown: true|
        t(payload, values: values, keep_unknown: keep_unknown)
      end

      translate(Array) do |*_args, values:, keep_unknown: true|
        map { |element| t(element, values: values, keep_unknown: keep_unknown) }.join
      end

      translate(:char, :separator) { |*_args, **_options| EMPTY_STRING + payload }

      translate(:expression) do |*_args, values:, keep_unknown: true|
        t.expression(node, values, keep_unknown)
      end

      # @!visibility private
      def expression(node, values, keep_unknown = true)
        settings  = settings_for(node.operator)
        variables = node.payload.select { |child| child.is_a?(Node[:variable]) }
        variables = reorder(variables, values) if node.operator == ??

        expanded = []
        pending  = []
        variables.each do |variable|
          value = value_for(variable, values)
          if value.equal?(UNKNOWN)
            @missing_keys << variable.name.to_sym
            pending << variable
          else
            expanded << [variable, value]
          end
        end

        return EMPTY_STRING if expanded.empty? && !keep_unknown
        return wrap(node.operator, pending) if expanded.empty?

        result = settings[:prefix].to_s + expanded.map {
          |variable, value| render_variable(variable, value, settings)
        }.join(settings[:separator])
        if pending.any? and keep_unknown
          result += settings[:continuation_separator].to_s
          result += wrap(settings[:continuation], pending)
        end
        result
      end

      private

      def settings_for(operator)
        SETTINGS.fetch(operator) { raise error_class, "%p operator is not supported" % operator }
      end

      # For {?a,b} the ? prefix belongs to the first expanded variable. Known
      # variables are emitted in their original order and unknown ones move into
      # a trailing {&...} expression. This makes two-step expansion identical
      # to expanding all values at once with the same partial mapping.
      def reorder(variables, values)
        known, pending = variables.partition { |variable| !value_for(variable, values).equal?(UNKNOWN) }
        known + pending
      end

      # Rebuilds a template expression for the given pending variables.
      def wrap(operator, variables)
        character = operator == nil ? EMPTY_STRING : operator.to_s
        ?{ + character + variables.map { |variable| varspec(variable) }.join(?,) + ?}
      end

      def varspec(variable)
        return variable.name + ?* if variable.explode
        return variable.name + ?: + variable.prefix if variable.prefix
        variable.name
      end

      def render_variable(variable, value, settings)
        return settings[:named] ? variable.name : EMPTY_STRING if value.equal?(nil)
        case value
        when Hash then return render_map(variable, coerce_map(variable, value), settings)
        when Array then return render_list(variable, coerce_list(variable, value), settings)
        end
        return render_map(variable, coerce_map(variable, value.to_hash), settings) if duck_type?(value, :to_hash)
        return render_list(variable, coerce_list(variable, value.to_ary), settings) if duck_type?(value, :to_ary)

        string = encode(variable, value, settings)
        string = string[0, variable.prefix.to_i] if variable.prefix
        named_pair(variable.name, string, settings)
      end

      # Verifies that a scalar value can be turned into a String.
      def coerce_scalar(variable, value)
        value.to_s
        value
      rescue NoMethodError => error
        raise error_class, "cannot use %s as value for %s (%s)" %
          [value_class(value), variable.name, error.message]
      end

      def value_class(value)
        value.class
      rescue StandardError
        "uncoercible value"
      end

      def coerce_list(variable, value)
        Array(value).each { |entry| coerce_scalar(variable, entry) }
      end

      def coerce_map(variable, value)
        value.each do |key, val|
          coerce_scalar(variable, key)
          coerce_scalar(variable, val) unless val.equal?(nil)
        end
      end

      def render_list(variable, list, settings)
        values = list.map { |entry| encode(variable, entry, settings) }
        if variable.explode
          if settings[:named]
            # Mustermann represents exploded query/path parameters by repeating
            # the parameter name (?a=1&a=2), which is also what its matcher
            # expects when recognizing an expanded link.
            values.map { |value| named_pair(variable.name, value, settings) }
                  .join(settings[:separator])
          else
            values.join(settings[:separator])
          end
        else
          rendered = values.join(?,)
          rendered = rendered[0, variable.prefix.to_i] if variable.prefix
          named_pair(variable.name, rendered, settings)
        end
      end

      # The ; operator renders an empty value as the bare name, ? and & keep
      # the equals sign.
      def named_pair(name, value, settings)
        return name if value.empty? && settings[:separator] == ?;
        settings[:named] ? "#{name}=#{value}" : value
      end

      def render_map(variable, hash, settings)
        pairs = hash.map do |key, value|
          [encode(variable, key, settings),
           value.equal?(nil) ? EMPTY_STRING : encode(variable, value, settings)]
        end
        rendered = if variable.explode
          pairs.map { |key, value| "#{key}=#{value}" }.join(settings[:separator])
        else
          pairs.map { |key, value| "#{key},#{value}" }.join(?,)
        end
        settings[:named] ? "#{variable.name}=#{rendered}" : rendered
      end

      def value_for(variable, values)
        key = variable.name.to_sym
        return UNKNOWN unless values.key?(key)
        value = values[key]
        value.equal?(nil) ? UNKNOWN : value
      end

      def duck_type?(value, method)
        value.respond_to?(method)
      rescue NoMethodError
        false
      end

      def encode(variable, value, settings)
        encode_value(coerce_scalar(variable, value), settings[:reserved])
      end

      public

      # @!visibility private
      def encode_value(value, reserved)
        string = value.to_s
        return string if string =~ /\A\w*\Z/
        allowed = reserved ? RESERVED_PASS : UNRESERVED
        URI_PARSER.escape(string, /[^#{allowed.source}]/)
      end

      # Escapes a query key or value appended beyond the template variables.
      def escape_additional(value)
        escape(value, also_escape: /[\/\?#\&=%]/)
      end
    end
  end
end
