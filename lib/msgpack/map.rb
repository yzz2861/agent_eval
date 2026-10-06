# frozen_string_literal: true

module MessagePack
  class Map < Array
    class DuplicateKeyError < ArgumentError
    end

    CONFLICT_STRATEGIES = {
      raise: :raise,
      error: :raise,
      first: :first,
      keep_first: :first,
      last: :last,
      keep_last: :last,
    }.freeze

    DEFAULT_UNDEFINED = Object.new.freeze

    alias array_each each

    def self.[](*pairs)
      new(pairs)
    end

    def self.from_pairs(pairs)
      new(pairs)
    end

    def initialize(pairs = nil)
      if pairs
        pairs.each do |pair|
          pair = Array(pair)
          raise ArgumentError, "expected a key-value pair, got #{pair.inspect}" unless pair.length == 2
          append_pair(pair[0], pair[1])
        end
      end
    end

    def [](key)
      pair = pair_for(key)
      pair && pair[1]
    end

    def pair_for(key)
      find { |entry_key, _| entry_key.eql?(key) }
    end

    def []=(key, value)
      pair = pair_for(key)
      if pair
        pair[1] = value
      else
        append_pair(key, value)
      end
      value
    end

    def fetch(key, *args, &block)
      raise ArgumentError, "wrong number of arguments (given #{args.length + 1}, expected 1..2)" if args.length > 1
      pair = pair_for(key)
      return pair[1] if pair
      return args[0] if args.any?
      return block.call(key) if block
      raise KeyError, "key not found: #{key.inspect}"
    end

    def keys
      map(&:first)
    end

    def values
      map(&:last)
    end

    def values_at_key(key)
      result = []
      array_each do |entry_key, entry_value|
        result << entry_value if entry_key.eql?(key)
      end
      result
    end

    def each_pair
      return to_enum(:each_pair) unless block_given?
      array_each do |pair|
        yield(pair[0], pair[1])
      end
      self
    end
    alias each each_pair
    alias size length

    def empty?
      length.zero?
    end

    alias entries to_a
    alias to_ary to_a

    def to_h(strategy = DEFAULT_UNDEFINED, on_duplicate: nil, &resolver)
      strategy = on_duplicate unless on_duplicate.nil?
      strategy = resolver if resolver

      if strategy.equal?(DEFAULT_UNDEFINED)
        raise ArgumentError, "a conflict strategy is required: :raise, :first, :last, or a callable"
      end

      if strategy.nil? || strategy == :raise
        strategy = CONFLICT_STRATEGIES.fetch(strategy || :raise) do
          raise ArgumentError, "unknown conflict strategy #{strategy.inspect}"
        end
      elsif !strategy.is_a?(Symbol) && !strategy.respond_to?(:call)
        raise TypeError, "expected a conflict strategy Symbol or callable"
      elsif strategy.is_a?(Symbol)
        strategy = CONFLICT_STRATEGIES.fetch(strategy) do
          raise ArgumentError, "unknown conflict strategy #{strategy.inspect}"
        end
      end

      result = {}
      each do |key, value|
        if result.key?(key)
          case strategy
          when :raise
            raise DuplicateKeyError, "duplicate map key #{key.inspect}"
          when :first
            next
          when :last
            result[key] = value
          else
            unless strategy.respond_to?(:call)
              raise ArgumentError, "unknown conflict strategy #{strategy.inspect}"
            end
            value = strategy.call(key, result[key], value)
            result[key] = value
          end
        else
          result[key] = value
        end
      end
      result
    end

    def to_msgpack(packer_or_io = nil)
      if packer_or_io.is_a?(MessagePack::Packer)
        packer_or_io.write(self)
      else
        MessagePack.pack(self, packer_or_io)
      end
    end

    def ==(other)
      other.is_a?(Map) && super
    end
    alias eql? ==

    def hash
      [self.class, to_a].hash
    end

    def inspect
      "MessagePack::Map[#{map { |key, value| "#{key.inspect}=>#{value.inspect}" }.join(', ')}]"
    end
    alias to_s inspect

    private

    def append_pair(key, value)
      push([key, value])
    end
  end

  OrderedMap = Map
end
