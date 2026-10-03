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
      return super if unicode_normalize
      return unless match = peek_match(string)
      match.to_s.size
    end

    # @param (see Mustermann::Pattern#peek_match)
    # @return (see Mustermann::Pattern#peek_match)
    # @see (see Mustermann::Pattern#peek_match)
    def peek_match(string)
      return super if unicode_normalize
      cache_match(@peek_cache, @peek_regexp, string)
    end

    # @param (see Mustermann::Pattern#match)
    # @return (see Mustermann::Pattern#match)
    # @see (see Mustermann::Pattern#match)
    def match(string)
      return cache_match(@match_cache, @regexp, string) unless unicode_normalize

      original, normalized, map = Normalizer.normalize_with_map(string, unicode_normalize)
      if @match_cache
        return @match_cache[string] if @match_cache.key?(string)
        @match_cache[string] = build_normalized_match(original, normalized, map)
      else
        build_normalized_match(original, normalized, map)
      end
    end

    # Extracts params directly from the regexp without allocating a Match object or
    # populating the match cache — significant GC savings when called in hot loops.
    # @param (see Mustermann::Pattern#params)
    # @return (see Mustermann::Pattern#params)
    def params(string = nil)
      if unicode_normalize
        original, normalized, map = Normalizer.normalize_with_map(string, unicode_normalize)
        return unless match = @regexp.match(normalized)
        return map ? build_original_params(match, original, map) : build_params(match)
      end

      return unless md = @regexp.match(string)
      build_params(md)
    end

    extend Forwardable
    def_delegators :regexp, :names

    # @param (see Mustermann::Pattern#===)
    # @return (see Mustermann::Pattern#===)
    # @see (see Mustermann::Pattern#===)
    def ===(string)
      regexp === normalize_string(string)
    end

    # @param (see Mustermann::Pattern#=~)
    # @return (see Mustermann::Pattern#=~)
    # @see (see Mustermann::Pattern#=~)
    def =~(string)
      regexp =~ normalize_string(string)
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
      Match.new(self, match, params: build_params(match))
    end

    # Builds a Match for a normalized input string, translating capture ranges
    # back to the original string so both the original and the normalized
    # params are available on the returned {Match}.
    # @!visibility private
    def build_normalized_match(original, normalized, map)
      return unless match = @regexp.match(normalized)
      normalized_params = build_params(match, normalize_values: true)
      params = map ? build_original_params(match, original, map) : build_params(match)
      Match.new(self, original, params: params, normalized_string: normalized, normalized_params: normalized_params)
    end

    def build_params(match, normalize_values: false)
      if @simple_captures
        params = match.named_captures
        return params if params.empty? || (!normalize_values && identity_params?(params))
        params.each_with_object({}) { |(k, v), h| h[k] = finish_param(k, v, normalize_values) }
      else
        match.regexp.named_captures.to_h do |name, positions|
          value = positions.size < 2 && !always_array?(name) ? finish_param(name, match[name], normalize_values) :
            positions.flat_map { |pos| finish_param(name, match[pos], normalize_values) }
          [name, value]
        end
      end
    end

    # Builds the params hash from capture ranges in the original (unnormalized)
    # string, using the offset map produced by {Normalizer.normalize_with_map}.
    # @!visibility private
    def build_original_params(match, original, map)
      match.regexp.named_captures.to_h do |name, positions|
        value = positions.size < 2 && !always_array?(name) ? map_param(name, slice_capture(match, positions.first, original, map)) :
          positions.flat_map { |pos| map_param(name, slice_capture(match, pos, original, map)) }
        [name, value]
      end
    end

    # @return [String, nil] the capture at the given position, sliced from the
    #   original string via the offset map
    # @!visibility private
    def slice_capture(match, position, original, map)
      start, stop = match.offset(position)
      return nil unless start && stop
      original[map[start]...map[stop]]
    end

    # @!visibility private
    def finish_param(name, value, normalize_values)
      value = map_param(name, value)
      normalize_values && value.is_a?(String) ? normalize_string(value) : value
    end

    def compile(**options) = raise NotImplementedError, 'subclass responsibility'
  end
end
