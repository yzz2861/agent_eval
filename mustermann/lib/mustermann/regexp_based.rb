# frozen_string_literal: true
require 'mustermann/pattern'
require 'forwardable'

module Mustermann
  # Superclass for patterns that internally compile to a regular expression.
  # @see Mustermann::Pattern
  # @abstract
  class RegexpBased < Pattern
    # @return [Regexp] regular expression equivalent to the pattern.
    attr_reader :regexp
    alias_method :to_regexp, :regexp

    # @api private
    supported_options :cache

    # @param (see Mustermann::Pattern#initialize)
    # @return (see Mustermann::Pattern#initialize)
    # @see (see Mustermann::Pattern#initialize)
    def initialize(string, **options)
      cache = options.delete(:cache) { true }

      super
      regexp           = compile(**options)
      @peek_regexp     = Mustermann.dedup(/\A#{regexp}/)
      @regexp          = Mustermann.dedup(/\A#{regexp}\Z/)
      @simple_captures = @regexp.named_captures.none? { |name, positions| positions.size > 1 || always_array?(name) }

      cache_class = ObjectSpace::WeakKeyMap if defined?(ObjectSpace::WeakKeyMap)

      case cache
      when true
        @match_cache = cache_class&.new || false
        @peek_cache  = cache_class&.new || false
      when false
        @match_cache = false
        @peek_cache  = false
      when Hash
        @match_cache = cache[:match] || cache_class&.new || false
        @peek_cache  = cache[:peek]  || cache_class&.new || false
      else
        @match_cache = cache.new
        @peek_cache  = cache.new
      end
    end

    # @param (see Mustermann::Pattern#peek_size)
    # @return (see Mustermann::Pattern#peek_size)
    # @see (see Mustermann::Pattern#peek_size)
    def peek_size(string)
      return unless match = peek_match(string)
      match.to_s.size
    end

    # @param (see Mustermann::Pattern#peek_match)
    # @return (see Mustermann::Pattern#peek_match)
    # @see (see Mustermann::Pattern#peek_match)
    def peek_match(string) = cache_match(@peek_cache, @peek_regexp, string)

    # @param (see Mustermann::Pattern#match)
    # @return (see Mustermann::Pattern#match)
    # @see (see Mustermann::Pattern#match)
    def match(string) = cache_match(@match_cache, @regexp, string)

    # Extracts params directly from the regexp without allocating a Match object or
    # populating the match cache — significant GC savings when called in hot loops.
    # @param (see Mustermann::Pattern#params)
    # @return (see Mustermann::Pattern#params)
    def params(string = nil)
      return unless md = @regexp.match(string)
      return unless valid_match_data?(md)
      build_params(md)
    end

    extend Forwardable
    def_delegators :regexp, :names

    # @return [Boolean] whether the regular expression matches and the +:equal+
    #   duplicate capture strategy is satisfied.
    def ===(string)
      !!@regexp.match(string) && valid_match_data?(($~))
    end

    # @return [Integer, nil] 0 if the pattern matches, nil otherwise.
    def =~(string)
      0 if self === string
    end

    private

    def cache_match(cache, regexp, string)
      if cache
        return cache[string] if cache.key?(string)
        cache[string] = build_match(regexp, string)
      else
        build_match(regexp, string)
      end
    end

    def build_match(regexp, string)
      return unless match = regexp.match(string)
      return unless valid_match_data?(match)
      Match.new(self, match, params: build_params(match))
    end

    def build_params(match)
      if @simple_captures
        params = match.named_captures
        return params if params.empty? || identity_params?(params)
        params.each_with_object({}) { |(k, v), h| h[k] = map_param(k, v) }
      else
        match.regexp.named_captures.to_h do |name, positions|
          present = positions.filter_map { |pos| match[pos] }
          value =
            if positions.size < 2 && !always_array?(name)
              map_param(name, match[name])
            elsif collect_capture?(name)
              present.map { |v| map_param(name, v) }
            elsif equal_capture?(name)
              map_param(name, present.first)
            elsif always_array?(name)
              positions.flat_map { |pos| Array(map_param(name, match[pos])) }
            else
              present.size < 2 ? map_param(name, present.first) : present.map { |v| map_param(name, v) }
            end
          [name, value]
        end
      end
    end

    # Whether a capture name occurs more than once. Overridden by AST patterns.
    # @!visibility private
    def repeated_capture?(_name) = false

    # Whether a repeated name collects all present values into an array.
    # @!visibility private
    def collect_capture?(_name) = false

    # Whether a repeated name requires all occurrences to be equal (scalar result).
    # @!visibility private
    def equal_capture?(_name) = false

    # @!visibility private
    def valid_match_data?(match)
      return true if @simple_captures
      match.regexp.named_captures.all? do |name, positions|
        next true unless repeated_capture?(name) && equal_capture?(name)
        values = positions.filter_map { |pos| map_param(name, match[pos]) }
        values.uniq.size <= 1
      end
    end

    def compile(**options) = raise NotImplementedError, 'subclass responsibility'
  end
end
