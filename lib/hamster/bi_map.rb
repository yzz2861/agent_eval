require "hamster/immutable"
require "hamster/trie"
require "hamster/undefined"

module Hamster
  # An immutable bidirectional map. Every key maps to one unique value, and
  # every value maps back to one unique key.
  #
  # The {#inverse} method returns a view with the keys and values exchanged.
  # It does not copy the stored entries; the view and the original map share
  # their underlying tries.
  class BiMap
    include Immutable
    include ::Enumerable

    class DuplicateValueError < ArgumentError; end

    class << self
      def [](pairs = nil)
        pairs.nil? || pairs.empty? ? empty : new(pairs)
      end

      def empty
        @empty ||= pair(EmptyTrie, EmptyTrie).first
      end

      def new(pairs = nil)
        return empty if pairs.nil? || pairs.empty?
        forward, reverse = build_pairs(pairs)
        pair(forward, reverse).first
      end

      def alloc(forward, reverse, inverse = false)
        allocate.tap do |map|
          map.instance_variable_set(:@forward, forward)
          map.instance_variable_set(:@reverse, reverse)
          map.instance_variable_set(:@inverse, inverse)
        end
      end

      private

      def pair(forward, reverse)
        map = alloc(forward, reverse, false)
        inverse_map = alloc(forward, reverse, true)
        map.instance_variable_set(:@counterpart, inverse_map)
        inverse_map.instance_variable_set(:@counterpart, map)
        map.send(:immutable!)
        inverse_map.send(:immutable!)
        [map, inverse_map]
      end

      def build_pairs(pairs)
        forward = Trie.new(0)
        reverse = Trie.new(0)

        normalize_pairs(pairs).each do |key, value|
          ensure_value_available(value, key, reverse)
          forward = forward.put(key, value)
          reverse = reverse.put(value, key)
        end

        [forward, reverse]
      end

      def ensure_value_available(value, key, reverse)
        entry = reverse.get(value)
        return unless entry
        return if entry[1].eql?(key)
        raise DuplicateValueError,
          "value #{value.inspect} is already mapped to #{entry[1].inspect}"
      end

      def immutable_string(object)
        if object.is_a?(::String) && !object.frozen?
          object.dup.freeze
        else
          object
        end
      end

      def normalize_pairs(pairs)
        updates = {}
        pairs.each do |key, value|
          updates[immutable_string(key)] = immutable_string(value)
        end
        updates
      end
    end

    def size
      active_trie.size
    end
    alias :length :size

    def empty?
      active_trie.empty?
    end

    def get(key)
      entry = active_trie.get(key)
      entry ? entry[1] : nil
    end
    alias :[] :get

    def fetch(key, default = Undefined)
      entry = active_trie.get(key)
      return entry[1] if entry
      return yield(key) if block_given?
      return default unless default.equal?(Undefined)
      raise KeyError, "key not found: #{key.inspect}"
    end

    def key?(key)
      !!active_trie.get(key)
    end
    alias :has_key? :key?
    alias :include? :key?
    alias :member? :key?

    def value?(value)
      !!other_trie.get(value)
    end
    alias :has_value? :value?

    def key(value)
      entry = other_trie.get(value)
      entry ? entry[1] : nil
    end

    def inverse
      @counterpart
    end
    alias :invert :inverse
    alias :reverse :inverse

    def put(key, value, force = false)
      put_all([[key, value]], force)
    end
    alias :store :put

    def force_put(key, value)
      put(key, value, true)
    end

    def put_all(pairs, force = false)
      updates = normalize_updates(pairs)
      canonical_updates = orient_pairs(updates)
      changes = canonical_updates.reject do |key, value|
        entry = @forward.get(key)
        entry && entry[1].eql?(value)
      end
      return self if changes.empty?

      ensure_unique_values(changes)
      displaced_keys = displaced_keys(changes, force)
      affected_keys = (changes.keys + displaced_keys).uniq
      old_values = []
      affected_keys.each do |key|
        entry = @forward.get(key)
        old_values << entry[1] if entry
      end

      forward = @forward.bulk_delete(affected_keys).bulk_put(changes)
      reverse = @reverse.bulk_delete(old_values).
        bulk_put(changes.map { |key, value| [value, key] })

      result(forward, reverse)
    end
    alias :merge :put_all

    def delete(key)
      entry = active_trie.get(key)
      return self unless entry

      if @inverse
        old_value = key
        old_key = entry[1]
      else
        old_key = key
        old_value = entry[1]
      end

      forward = @forward.delete(old_key)
      reverse = @reverse.delete(old_value)
      result(forward, reverse)
    end

    def each(&block)
      return to_enum(:each) unless block_given?
      active_trie.each(&block)
      self
    end
    alias :each_pair :each

    def each_key(&block)
      return to_enum(:each_key) unless block_given?
      active_trie.each { |key, _| yield(key) }
      self
    end

    def each_value(&block)
      return to_enum(:each_value) unless block_given?
      active_trie.each { |_, value| yield(value) }
      self
    end

    def keys
      array = []
      each_key { |key| array << key }
      array
    end

    def values
      array = []
      each_value { |value| array << value }
      array
    end

    def clear
      @inverse ? self.class.empty.inverse : self.class.empty
    end

    def eql?(other)
      return true if equal?(other)
      other.is_a?(BiMap) &&
        @inverse == other.instance_variable_get(:@inverse) &&
        active_trie.eql?(other.send(:active_trie))
    end

    def ==(other)
      eql?(other) ||
        (other.respond_to?(:to_hash) && to_hash == other.to_hash)
    end

    def hash
      result = 0
      each { |key, value| result ^= [key.hash, value.hash].hash }
      result
    end

    def inspect
      result = "#{self.class}["
      first = true
      each do |key, value|
        result << ", " unless first
        result << key.inspect << " => " << value.inspect
        first = false
      end
      result << "]"
    end

    def to_hash
      result = {}
      each { |key, value| result[key] = value }
      result
    end
    alias :to_h :to_hash

    def []=(*)
      raise NoMethodError, "Hamster::BiMap doesn't support `[]='; use `put' instead"
    end

    def marshal_dump
      canonical = @inverse ? @counterpart : self
      [canonical.to_hash, @inverse]
    end

    def marshal_load(data)
      pairs = data.is_a?(::Array) ? data.first : data
      inverse = data.is_a?(::Array) ? data.last : false
      forward, reverse = self.class.send(:build_pairs, pairs)
      counterpart = self.class.alloc(forward, reverse, !inverse)

      @forward = forward
      @reverse = reverse
      @inverse = inverse
      @counterpart = counterpart
      counterpart.instance_variable_set(:@counterpart, self)
      counterpart.send(:immutable!)
      immutable!
    end

    private

    def result(forward, reverse)
      return clear if forward.empty?
      result = self.class.send(:pair, forward, reverse)
      @inverse ? result.last : result.first
    end

    def active_trie
      @inverse ? @reverse : @forward
    end

    def other_trie
      @inverse ? @forward : @reverse
    end

    def normalize_updates(pairs)
      self.class.send(:normalize_pairs, pairs)
    end

    def orient_pairs(pairs)
      result = {}
      pairs.each do |left, right|
        key, value = @inverse ? [right, left] : [left, right]
        result[key] = value
      end
      result
    end

    def ensure_unique_values(changes)
      seen = {}
      changes.each do |key, value|
        if seen.key?(value)
          owner = seen[value]
          raise DuplicateValueError,
            "value #{value.inspect} cannot be mapped from both #{owner.inspect} and #{key.inspect}"
        end
        seen[value] = key
      end
    end

    def displaced_keys(changes, force)
      displaced = []

      changes.each do |key, value|
        entry = @reverse.get(value)
        next unless entry
        owner = entry[1]
        next if owner.eql?(key) || changes.key?(owner)

        unless force
          raise DuplicateValueError,
            "value #{value.inspect} is already mapped to #{owner.inspect}; use `force_put' or pass `true' to `put_all' to replace it"
        end
        displaced << owner
      end

      displaced
    end
  end

  EmptyBiMap = Hamster::BiMap.empty
end
