# frozen_string_literal: true

module MessagePack
  class Map
    include Enumerable

    def initialize(pairs = nil)
      @pairs = []

      if pairs
        unless pairs.respond_to?(:each)
          raise ArgumentError, "expected an enumerable collection of key-value pairs"
        end

        if pairs.is_a?(::Hash)
          pairs.each_pair { |key, value| append(key, value) }
        else
          pairs.each do |pair|
            unless pair.is_a?(::Array) && pair.length == 2
              raise ArgumentError, "each map entry must be a 2-element Array"
            end

            append(pair[0], pair[1])
          end
        end
      end
    end

    def self.[](*pairs)
      new(pairs.length == 1 && pairs[0].is_a?(::Array) ? pairs[0] : pairs)
    end

    def pairs
      @pairs.map { |key, value| [key, value] }
    end

    def to_a
      pairs
    end

    def size
      @pairs.size
    end
    alias length size

    def empty?
      @pairs.empty?
    end

    def each
      return to_enum(:each) unless block_given?

      @pairs.each { |key, value| yield(key, value) }
      self
    end
    alias each_pair each

    def each_entry
      return to_enum(:each_entry) unless block_given?

      @pairs.each { |pair| yield(pair) }
      self
    end

    def keys
      @pairs.map(&:first)
    end

    def values
      @pairs.map(&:last)
    end

    def [](key)
      found = nil
      @pairs.reverse_each do |candidate, value|
        if candidate.eql?(key)
          found = value
          break
        end
      end
      found
    end

    def fetch_values(*keys)
      keys.map { |key| fetch(key) }
    end

    def dig(key, *rest)
      value = self[key]
      return value if rest.empty? || value.nil?
      raise TypeError, "#{value.class} does not have #dig method" unless value.respond_to?(:dig)
      value.dig(*rest)
    end

    def fetch(key, *args, &block)
      index = @pairs.rindex { |candidate, _| candidate.eql?(key) }
      return @pairs[index][1] if index

      if block
        block.call(key)
      elsif args.length == 1
        args[0]
      elsif args.empty?
        raise KeyError, "key not found: #{key.inspect}"
      else
        raise ArgumentError, "wrong number of arguments (#{args.length + 1} for 1..2)"
      end
    end

    def add(key, value)
      raise FrozenError, "can't modify frozen MessagePack::Map" if frozen?

      append(key, value)
      self
    end
    alias []= add

    def <<(pair)
      unless pair.is_a?(::Array) && pair.length == 2
        raise ArgumentError, "map entry must be a 2-element Array"
      end

      add(pair[0], pair[1])
    end

    def duplicate_keys?
      seen = {}
      @pairs.any? do |key, _|
        duplicate = seen.key?(key)
        seen[key] = true
        duplicate
      end
    end

    def to_h(strategy = nil, conflict: nil, on_duplicate: nil)
      strategy ||= conflict || on_duplicate
      valid_strategies = [
        :raise, :raise_on_conflict, :raise_on_duplicate,
        :first, :first_wins, :keep_first,
        :last, :last_wins, :keep_last,
      ]
      unless valid_strategies.include?(strategy)
        raise ArgumentError, "conflict must be :raise, :first, or :last"
      end

      result = {}
      @pairs.each do |key, value|
        if result.key?(key)
          if strategy == :raise || strategy == :raise_on_conflict || strategy == :raise_on_duplicate
            raise ArgumentError, "duplicate map key: #{key.inspect}"
          elsif strategy == :last || strategy == :last_wins || strategy == :keep_last
            result[key] = value
          end
        else
          result[key] = value
        end
      end
      result
    end

    def ==(other)
      other.is_a?(Map) && @pairs == other.pairs
    end
    alias eql? ==

    def hash
      @pairs.hash
    end

    def inspect
      "#{self.class}[#{@pairs.map(&:inspect).join(", ")}]"
    end
    alias to_s inspect

    def freeze
      @pairs.each(&:freeze)
      @pairs.freeze
      super
    end

    def initialize_copy(other)
      super
      @pairs = other.__send__(:raw_pairs).map { |key, value| [key, value] }
    end

    def to_msgpack(packer_or_io = nil)
      if packer_or_io.is_a?(Packer)
        packer_or_io.write_map_header(size)
        each do |key, value|
          packer_or_io.write(key)
          packer_or_io.write(value)
        end
        packer_or_io
      else
        MessagePack.pack(self, packer_or_io)
      end
    end

    private

    def append(key, value)
      @pairs << [key, value]
    end

    def raw_pairs
      @pairs
    end
  end

  OrderedMap = Map
end
