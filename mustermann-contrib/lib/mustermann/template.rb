# frozen_string_literal: true
require 'mustermann'
require 'mustermann/ast/pattern'
require 'mustermann/template/partial_expansion'

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

    # Marker wrapping a value parsed as a RFC 6570 map, so #params can replace
    # the enclosing array with the hash.
    # @!visibility private
    class MapValue
      attr_reader :hash
      def initialize(hash) = @hash = hash
    end

    # @!visibility private
    def map_param(key, value)
      return super unless variable = @split_params[key]
      entries = value.split(variable[:separator])
      entries.map! { |entry| entry.sub(/\A#{key}=/, '') } if variable[:parametric]
      entries.map! { |entry| super(key, entry) }
      return entries unless (map = parse_map(key, entries))
      [MapValue.new(map)]
    end

    # Exploded parametric expressions capture a level-4 map as `key=value`
    # pairs with dynamic keys (keys different from the variable's own name).
    # Returns the parsed Hash, or nil when the segments describe a list.
    # @!visibility private
    def parse_map(key, entries)
      return unless variable = @split_params[key]
      return unless entries.length >= 2
      return unless entries.all? { |entry| entry.to_s.include?(?=) }
      if variable[:parametric]
        return if entries.any? { |entry| entry == key || entry.to_s.start_with?("#{key}=") }
      end
      pairs = entries.map { |entry| entry.split(?=, 2) }
      return if pairs.any? { |pair| pair.length != 2 }
      keys = pairs.map(&:first)
      return unless keys.uniq.length == keys.length
      pairs.to_h
    end

    # @!visibility private
    def always_array?(key)
      @split_params.include? key
    end

    # Replaces {MapValue} markers with their hashes.
    # @!visibility private
    def params(string = nil)
      result = super
      return result unless result
      result.each do |key, value|
        next unless value.is_a?(Array)
        marker = value.find { |entry| entry.is_a?(MapValue) }
        result[key] = marker.hash if marker
      end
      result
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

    # The raw (pre-transform) parse tree directly exposes the URI template
    # expressions and their operators, which the expander renders itself.
    # @return [Mustermann::AST::Node] raw parse tree
    # @!visibility private
    def raw_ast
      @raw_ast ||= parse(@string, pattern: self)
    end

    # Expands the template into a URI following RFC 6570.
    #
    # @overload expand(behavior = nil, **values)
    #   @param [Symbol] behavior +:raise+ (default), +:ignore+ or +:append+
    #     for additional key/value pairs not part of the template.
    #   @param [Hash{Symbol, String => #to_s, Array<#to_s>, Hash}] values
    #   @return [String] expanded URI
    #   @raise [Mustermann::ExpandError] if a value is missing or invalid
    def expand(behavior = nil, values = EMPTY_HASH)
      behavior, values = nil, behavior unless behavior.nil? || behavior.is_a?(Symbol)
      case behavior
      when nil, :raise then Expansion.new(self, values || EMPTY_HASH, :raise).expand
      when :ignore    then Expansion.new(self, values || EMPTY_HASH, :ignore).expand
      when :append
        permissive = Expansion.new(self, values || EMPTY_HASH, :ignore)
        given      = values || EMPTY_HASH
        known      = given.select { |key, _| permissive.known_keys.include?(key.to_sym) }
        append_remaining(Expansion.new(self, known, :raise).expand, permissive, values || EMPTY_HASH)
      else raise ArgumentError, "unknown behavior %p" % behavior
      end
    end

    # Partially expands the template: known variables are rendered and unknown
    # variables stay as valid URI template expressions, so the result can be
    # expanded again once more values become available.
    #
    # @example tenant-prefixed links
    #   pattern = Mustermann.new('/t/{tenant}/orders/{id}{?q}', type: :template)
    #   partial = pattern.expand_partial(tenant: 'acme')
    #   partial.to_s                       # => "/t/acme/orders/{id}{?q}"
    #   partial.expand(id: 42, q: 'x')    # => "/t/acme/orders/42?q=x"
    #
    # @overload expand_partial(behavior = nil, **values)
    #   @param [Symbol] behavior +:raise+ (default) or +:ignore+
    #   @param [Hash] values variables known at this stage
    #   @return [Mustermann::Template::PartialExpansion]
    #   @raise [Mustermann::ExpandError] if a supplied value is invalid, a
    #     later variable is given before an earlier missing one, or an unknown
    #     key is supplied
    def expand_partial(behavior = nil, values = EMPTY_HASH)
      behavior, values = nil, behavior unless behavior.nil? || behavior.is_a?(Symbol)
      case behavior
      when nil, :raise then Expansion.new(self, values || EMPTY_HASH, :raise).expand_partial
      when :ignore    then Expansion.new(self, values || EMPTY_HASH, :ignore).expand_partial
      else raise ArgumentError, "unknown behavior %p" % behavior
      end
    end

    def append_remaining(uri, expansion, values)
      extra = values.reject { |key, _| expansion.known_keys.include?(key.to_sym) }
      return uri if extra.empty?
      entries = extra.map { |key, value| "#{expansion.encode(key)}=#{expansion.encode(value)}" }
      "#{uri}#{uri.include?(??) ? ?& : ??}#{entries.join(?&)}"
    end

    private :compile, :map_param, :always_array?, :append_remaining
  end
end
