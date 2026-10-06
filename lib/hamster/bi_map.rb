require "hamster/immutable"
require "hamster/enumerable"
require "hamster/trie"
require "hamster/set"
require "hamster/vector"
require "hamster/associable"

module Hamster
  # An immutable bidirectional map. Every key maps to one value and every
  # value maps back to one key. {#inverse} returns the opposite view without
  # copying the stored mappings.
  #
  # By default, storing a value which already belongs to another key raises
  # `ArgumentError`. Existing keys can still be overwritten. Pass `force: true`
  # to {#put} or {#merge} to remove the key which previously owned the value.
  # Batch operations validate all changes before applying them, so values can
  # be exchanged between two existing keys.
  class BiMap
    include Immutable
    include Enumerable
    include Associable

    class << self
      # Create a new `BiMap` populated with the given key/value pairs.
      def [](pairs = nil)
        (pairs.nil? || pairs.empty?) ? empty : new(pairs)
      end

      # Return an empty `BiMap`. If used on a subclass, returns an empty
      # instance of that class.
      def empty
        @empty ||= new
      end

      # @private
      def alloc(forward = EmptyTrie, reverse = EmptyTrie,
                forward_instance = allocate, reverse_instance = allocate)
        forward_instance.instance_variable_set(:@forward, forward)
        forward_instance.instance_variable_set(:@reverse, reverse)
        forward_instance.instance_variable_set(:@inverse, reverse_instance)
        forward_instance.instance_variable_set(:@inverted, false)

        reverse_instance.instance_variable_set(:@forward, reverse)
        reverse_instance.instance_variable_set(:@reverse, forward)
        reverse_instance.instance_variable_set(:@inverse, forward_instance)
        reverse_instance.instance_variable_set(:@inverted, true)

        forward_instance.freeze
        reverse_instance.freeze
        forward_instance
      end

      private

      def normalize_pairs(pairs)
        normalized = {}
        if pairs.respond_to?(:each_pair)
          pairs.each_pair { |key, value| normalized[canonical(key)] = canonical(value) }
        else
          pairs.each do |key, value|
            normalized[canonical(key)] = canonical(value)
          end
        end
        normalized
      end

      def canonical(object)
        (object.is_a?(::String) && !object.frozen?) ? object.dup.freeze : object
      end
    end

    def initialize(pairs = nil)
      if pairs
        replacements = self.class.send(:normalize_pairs, pairs)
        ensure_unique_values!(replacements)
        forward = EmptyTrie.bulk_put(replacements)
        reverse = EmptyTrie.bulk_put(replacements.map { |key, value| [value, key] })
      else
        forward = reverse = EmptyTrie
      end

      @inverse = allocate_inverse
      self.class.alloc(forward, reverse, self, @inverse)
    end

    # Return the number of key/value pairs.
    def size
      @forward.size
    end
    alias :length :size

    # Return `true` if this map contains no pairs.
    def empty?
      @forward.empty?
    end

    # Return the value associated with `key`, or `nil` if it is absent.
    def get(key)
      entry = @forward.get(key)
      entry[1] if entry
    end
    alias :[] :get

    # Retrieve the value associated with `key`, with the same fallback rules
    # as `Hamster::Hash#fetch`.
    def fetch(key, default = Undefined)
      entry = @forward.get(key)
      if entry
        entry[1]
      elsif block_given?
        yield(key)
      elsif default != Undefined
        default
      else
        raise KeyError, "key not found: #{key.inspect}"
      end
    end

    # Return the key associated with `value`, or `nil` if it is absent.
    def key(value)
      entry = @reverse.get(value)
      entry[1] if entry
    end
    alias :get_key :key
    alias :inverse_get :key

    # Return `true` if `key` is present on this side of the map.
    def key?(key)
      @forward.key?(key)
    end
    alias :has_key? :key?
    alias :include? :key?
    alias :member? :key?

    # Return `true` if `value` is present on the opposite side of the map.
    def value?(value)
      @reverse.key?(value)
    end
    alias :has_value? :value?

    # Return a new map containing the given association. Existing keys are
    # replaced. Use `force: true` to displace another key that owns `value`.
    def put(key, value, options = nil)
      merge([[key, value]], force_option(options))
    end

    # Return a new map, replacing both the existing key association and any
    # other key which currently owns `value`.
    def force_put(key, value)
      put(key, value, :force => true)
    end

    # @private
    def []=(*)
      raise NoMethodError, "Hamster::BiMap doesn't support `[]='; use `put' instead"
    end

    # Return a new map containing all given pairs. Pairs are validated as one
    # transaction, so exchanging two values in a batch is supported.
    def merge(other, options = nil)
      if @inverted
        replacements = self.class.send(:normalize_pairs, other)
        ensure_unique_values!(replacements)
        return inverse.merge(swap_pairs(replacements), options).inverse
      end

      force = force_option(options)
      replacements = self.class.send(:normalize_pairs, other)
      return self if replacements.empty?

      ensure_unique_values!(replacements)
      changed_keys = []
      displaced_keys = []

      replacements.each do |key, value|
        current = @forward.get(key)
        next if current && current[1].eql?(value)

        owner = @reverse.get(value)
        if owner && !owner[1].eql?(key)
          owner_key = owner[1]
          if !replacements.key?(owner_key)
            if force
              displaced_keys << owner_key unless displaced_keys.any? { |existing| existing.eql?(owner_key) }
            else
              raise ArgumentError,
                "value #{value.inspect} is already associated with #{owner_key.inspect}"
            end
          end
        end

        changed_keys << key
      end

      return self if changed_keys.empty? && displaced_keys.empty?
      apply_replacements(replacements, changed_keys, displaced_keys)
    end
    alias :put_all :merge

    # Return a new map with `key` and its inverse association removed.
    def delete(key)
      return inverse.delete_value(key).inverse if @inverted

      entry = @forward.get(key)
      return self unless entry

      forward = @forward.delete(key)
      reverse = @reverse.delete(entry[1])
      self.class.alloc(forward, reverse)
    end

    # Return a new map with `value` and its forward association removed.
    def delete_value(value)
      return inverse.delete(value).inverse if @inverted

      entry = @reverse.get(value)
      return self unless entry

      key = entry[1]
      forward = @forward.delete(key)
      reverse = @reverse.delete(value)
      self.class.alloc(forward, reverse)
    end

    # Return an empty map of the same class and orientation as this one.
    def clear
      @inverted ? self.class.empty.inverse : self.class.empty
    end

    # Yield each `[key, value]` pair in this orientation.
    def each(&block)
      return enum_for(:each) unless block_given?
      @forward.each(&block)
      self
    end
    alias :each_pair :each

    # Yield each key in this orientation.
    def each_key
      return enum_for(:each_key) unless block_given?
      @forward.each { |key, _| yield(key) }
      self
    end

    # Yield each unique value.
    def each_value
      return enum_for(:each_value) unless block_given?
      @reverse.each { |value, _| yield(value) }
      self
    end

    # Return all keys as a {Set}.
    def keys
      Set.alloc(@forward)
    end

    # Return all values as a {Set}.
    def values
      Set.alloc(@reverse)
    end

    # Return the opposite view without copying the stored mappings.
    def inverse
      @inverse
    end
    alias :reverse :inverse

    # Convert this orientation to a Ruby `Hash`.
    def to_hash
      result = {}
      each { |key, value| result[key] = value }
      result
    end
    alias :to_h :to_hash

    # Return `true` when `other` is the same type and orientation with equal
    # pairs.
    def eql?(other)
      return true if other.equal?(self)
      other.instance_of?(self.class) &&
        @inverted == other.instance_variable_get(:@inverted) &&
        @forward.eql?(other.instance_variable_get(:@forward))
    end

    def ==(other)
      eql?(other) || (other.respond_to?(:to_hash) && to_hash == other.to_hash)
    end

    def hash
      each.reduce(0) { |result, (key, value)| result ^ key.hash ^ value.hash }
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

    def pretty_print(pp)
      pp.group(1, "#{self.class}[", "]") do
        pp.breakable("")
        pp.seplist(self, nil) do |key, value|
          pp.group do
            key.pretty_print(pp)
            pp.text " => "
            pp.group(1) do
              pp.breakable("")
              value.pretty_print(pp)
            end
          end
        end
      end
    end

    # @private
    def marshal_dump
      to_hash
    end

    # @private
    def marshal_load(pairs)
      pairs = self.class.send(:normalize_pairs, pairs)
      forward = EmptyTrie.bulk_put(pairs)
      reverse = EmptyTrie.bulk_put(pairs.map { |key, value| [value, key] })
      @inverse = allocate_inverse
      self.class.alloc(forward, reverse, self, @inverse)
    end

    private

    def allocate_inverse
      self.class.allocate
    end

    def force_option(options)
      return false if options.nil?
      options.is_a?(::Hash) ? options.fetch(:force, false) : options
    end

    def ensure_unique_values!(replacements)
      seen = {}
      replacements.each do |key, value|
        if seen.key?(value) && !seen[value].eql?(key)
          raise ArgumentError, "duplicate value #{value.inspect} in bidirectional map"
        end
        seen[value] = key
      end
    end

    def apply_replacements(replacements, changed_keys, displaced_keys)
      removed_keys = changed_keys + displaced_keys
      old_values = []

      removed_keys.each do |key|
        entry = @forward.get(key)
        old_values << entry[1] if entry
      end

      forward = @forward.bulk_delete(removed_keys).bulk_put(replacements)
      reverse_pairs = replacements.map { |key, value| [value, key] }
      reverse = @reverse.bulk_delete(old_values).bulk_put(reverse_pairs)
      self.class.alloc(forward, reverse)
    end

    def swap_pairs(pairs)
      Hash[pairs.map { |key, value| [value, key] }]
    end
  end

  EmptyBiMap = Hamster::BiMap.empty
end
