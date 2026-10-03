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

      @duplicate_strategy = self.options&.[](:on_duplicate)
      @duplicate_names    = EMPTY_ARRAY
      @check_duplicates   = nil
      unless @simple_captures
        duplicates = @regexp.named_captures.reject { |name, positions| positions.size < 2 || always_array?(name) }
        @duplicate_names  = duplicates.keys.freeze unless duplicates.empty?
        @check_duplicates = duplicates.to_a.freeze if @duplicate_strategy == :check && duplicates.any?
      end

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

    # @api private
    # @return [Symbol, nil] the duplicate capture name strategy (:check or :collect), if any
    attr_reader :duplicate_strategy

    # @api private
    # @return [Array<String>] capture names occurring more than once in the pattern
    attr_reader :duplicate_names

    # Patterns using on_duplicate: :check only match if all occurrences of a
    # repeated capture name decode to the same value, so a plain regexp test is
    # not sufficient for those.
    # @see Mustermann::Pattern#===
    def ===(string)
      return @regexp === string unless @check_duplicates
      !!(match = @regexp.match(string)) && !duplicate_mismatch?(match)
    end

    # @see Mustermann::Pattern#=~
    def =~(string)
      return @regexp =~ string unless @check_duplicates
      self === string ? 0 : nil
    end

    # Extracts params directly from the regexp without allocating a Match object or
    # populating the match cache — significant GC savings when called in hot loops.
    # @param (see Mustermann::Pattern#params)
    # @return (see Mustermann::Pattern#params)
    def params(string = nil)
      return unless md = @regexp.match(string)
      return if duplicate_mismatch?(md)
      build_params(md)
    end

    extend Forwardable
    def_delegators :regexp, :names

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
      return if duplicate_mismatch?(match)
      Match.new(self, match, params: build_params(match))
    end

    # @return [Boolean] true if a duplicate capture name with on_duplicate: :check
    #   has occurrences that decode to different values
    # @!visibility private
    def duplicate_mismatch?(match)
      return false unless @check_duplicates
      @check_duplicates.any? do |name, positions|
        values = positions.filter_map { |pos| match[pos] }
        values.map { |value| map_param(name, value) }.uniq.size > 1
      end
    end

    def build_params(match)
      if @simple_captures
        params = match.named_captures
        return params if params.empty? || identity_params?(params)
        params.each_with_object({}) { |(k, v), h| h[k] = map_param(k, v) }
      else
        match.regexp.named_captures.to_h do |name, positions|
          value = if positions.size < 2 && !always_array?(name)
            map_param(name, match[name])
          else
            multi_param(name, positions.map { |pos| match[pos] })
          end
          [name, value]
        end
      end
    end

    # Resolves the values of a capture occurring multiple times (or always
    # rendered as an Array, like splats) according to the duplicate strategy.
    # Absent occurrences (optional groups that did not participate) are ignored
    # for :check and :collect. Comparison for :check happens on decoded values,
    # while the raw captured ranges remain available via Match#captures.
    # @!visibility private
    def multi_param(name, raw_values)
      case @duplicate_strategy
      when :check   then raw_values.filter_map { |raw| map_param(name, raw) }.first
      when :collect then raw_values.filter_map { |raw| map_param(name, raw) }
      else raw_values.flat_map { |raw| map_param(name, raw) }
      end
    end

    def compile(**options) = raise NotImplementedError, 'subclass responsibility'
  end
end
