# frozen_string_literal: true
require 'mustermann'
require 'mustermann/ast/pattern'
require 'mustermann/ast/partial_expander'

module Mustermann
  # URI template pattern implementation.
  #
  # @example
  #   Mustermann.new('/{foo}') === '/bar' # => true
  #
  # @see Mustermann::Pattern
  # @see file:README.md#template Syntax description in the README
  # @see http://tools.ietf.org/html/rfc6570 RFC 6570
  class Template < AST::Pattern
    include Concat::Native
    register :template, :uri_template

    on ?{ do |char|
      variable = proc do
        start  = pos
        match  = expect(/(?<name>\w+)(?:\:(?<prefix>\d{1,4})|(?<explode>\*))?/)
        node(:variable, match[:name], prefix: match[:prefix], explode: match[:explode], start: start)
      end

      operator   = buffer.scan(/[\+\#\.\/;\?\&\=\,\!\@\|]/)
      expression = node(:expression, [variable[]], operator: operator) { variable[] if scan(?,) }
      expression if expect(?})
    end

    on(?}) { |c| unexpected(c) }

    # @!visibility private
    def compile(*args, **options)
      @split_params = {}
      super(*args, split_params: @split_params, **options)
    end

    # @!visibility private
    def map_param(key, value)
      return super unless variable = @split_params[key]
      value = value.split variable[:separator]
      value.map! { |e| e.sub(/\A#{key}=/, '') } if variable[:parametric]
      value.map! { |e| super(key, e) }
    end

    # @!visibility private
    def always_array?(key)
      @split_params.include? key
    end

    # Identity patterns support generating templates (the logic is quite complex, though).
    #
    # @example (see Mustermann::Pattern#to_templates)
    # @param (see Mustermann::Pattern#to_templates)
    # @return (see Mustermann::Pattern#to_templates)
    # @see Mustermann::Pattern#to_templates
    def to_templates
      [to_s]
    end

    # Partially expands the pattern: known values are expanded into the
    # resulting URI template, while missing variables are kept as template
    # expressions that may be expanded in a later step.
    #
    # This is useful for building links in stages, e.g. when only the tenant is
    # known at first and the resource id or query parameters become available
    # later.
    #
    # @example expanding in two steps
    #   pattern = Mustermann.new('/tenants/{tenant}/users/{id}{?q,lang}', type: :template)
    #   partial = pattern.partial_expand(tenant: 'acme')
    #   partial.to_s # => "/tenants/acme/users/{id}{?q,lang}"
    #   partial.expand(id: 42, q: 'ruby', lang: 'en')
    #   # => "/tenants/acme/users/42?q=ruby&lang=en"
    #
    # Expanding in two steps yields the same result as expanding all values at
    # once. Already expanded values are literal URI text and are therefore not
    # escaped a second time. Invalid values are reported at the stage they are
    # passed in, and the fully expanded URI is recognized by the original
    # pattern.
    #
    # @param [Hash{Symbol, String => #to_s, Array<#to_s>, Hash}] values
    #   Values known at this point.
    #
    # @return [Mustermann::Template] a new, partially expanded template
    # @raise [Mustermann::ExpandError] raised if a value cannot be expanded
    def partial_expand(values = EMPTY_HASH)
      expanded = AST::PartialExpander.partial_expand(raw_ast, normalize_values(values))
      self.class.new(expanded, **expand_options)
    end

    # @example (see Mustermann::Pattern#expand)
    # @param (see Mustermann::Pattern#expand)
    # @return (see Mustermann::Pattern#expand)
    # @raise (see Mustermann::Pattern#expand)
    def expand(behavior = nil, values = EMPTY_HASH)
      behavior, values = nil, behavior if behavior.is_a? Hash
      normalized = normalize_values(values)
      case behavior
      when nil, :raise then AST::PartialExpander.expand(raw_ast, normalized)
      when :ignore    then AST::PartialExpander.expand_known(raw_ast, normalized)
      when :append    then append_additional(AST::PartialExpander.expand_known(raw_ast, normalized), normalized)
      else raise ArgumentError, "unknown behavior %p" % behavior
      end
    end

    # @!visibility private
    def expand_known(values = EMPTY_HASH)
      AST::PartialExpander.expand_known(raw_ast, normalize_values(values))
    end

    # @return [Array<Symbol>] names of all variables used in the template
    # @!visibility private
    def template_variable_names
      @template_variable_names ||= raw_ast.each_leaf.with_object([]) do |node, names|
        names << node.name.to_sym if node.respond_to?(:name)
      end.uniq
    end

    private

    def raw_ast
      parse(to_s, pattern: self)
    end

    def normalize_values(values)
      values.each_with_object({}) do |(key, value), normalized|
        normalized[key.to_sym] = value
      end
    end

    def expand_options
      options.slice(:uri_decode, :space_matches_plus, :capture, :except, :greedy)
    end

    def append_additional(uri, values)
      extra = values.reject { |key, _| template_variable_names.include?(key) }
      return uri if extra.empty?
      AST::PartialExpander.append_query(uri, extra)
    end

    private :compile, :map_param, :always_array?
  end
end
