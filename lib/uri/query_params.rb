# frozen_string_literal: true

module URI
  # Editable application/x-www-form-urlencoded query component.
  #
  # Integer access selects an item by position. String access selects the
  # first item with that decoded key, so duplicate keys are not all changed.
  class QueryParams
    include Enumerable

    # One item in a QueryParams collection. A query item without '=' has a
    # nil value, while '=' with nothing after it has an empty string value.
    QueryItem = Struct.new(:params, :position) do
      def key
        URI.decode_www_form_component(params.send(:raw_items).fetch(position).first)
      end
      alias name key

      def value
        _, has_equal, raw_value = params.send(:raw_items).fetch(position)
        return nil unless has_equal

        URI.decode_www_form_component(raw_value)
      end

      def key=(key)
        params.send(:set_key_at, position, key)
        key
      end
      alias name= key=

      def value=(value)
        params.send(:set_value_at, position, value)
        value
      end

      def to_a
        [key, value]
      end
      alias to_ary to_a

      def raw_key
        params.send(:raw_items).fetch(position).first.dup
      end

      def raw_value
        _, has_equal, raw_value = params.send(:raw_items).fetch(position)
        return nil unless has_equal

        raw_value.dup
      end

      def ==(other)
        other.respond_to?(:to_ary) && to_a == other.to_ary
      end
    end

    def initialize(uri)
      @uri = uri
    end

    def each
      return to_enum unless block_given?

      size.times do |index|
        yield [self[index].key, self[index].value]
      end
    end

    def [](key_or_index)
      case key_or_index
      when Integer
        item_at(key_or_index)
      else
        key = key_or_index.to_s
        index = index_for_key(key)
        item_at(index).value if index
      end
    end

    def []=(key_or_index, value)
      case key_or_index
      when Integer
        set_value_at(key_or_index, value)
      else
        key = key_or_index.to_s
        index = index_for_key(key)
        if index
          set_value_at(index, value)
        else
          add(key, value)
        end
      end
      value
    end

    def add(key, value = nil)
      item = URI.encode_www_form_component(key.to_s)
      unless value.nil?
        item << '='
        item << URI.encode_www_form_component(value)
      end
      query = @uri.query || ''
      query += '&' unless query.empty?
      update_query(query + item)
      value
    end
    alias append add

    def delete(key)
      items = raw_items
      decoded_key = key.to_s
      index = items.index { |raw_key, _, _| key_matches?(raw_key, decoded_key) }
      return nil unless index

      kept = items.dup
      kept.delete_at(index)

      update_query(kept.map(&method(:serialize_raw_item)).join('&'))
      key
    end

    def delete_at(index)
      items = raw_items
      index += items.size if index < 0
      return nil unless index >= 0 && index < items.size

      raw_key, has_equal, raw_value = items.delete_at(index)
      update_query(items.map(&method(:serialize_raw_item)).join('&'))
      value = has_equal ? URI.decode_www_form_component(raw_value) : nil
      [URI.decode_www_form_component(raw_key), value]
    end

    def fetch(key, *args, &block)
      index = index_for_key(key.to_s)
      return item_at(index).value if index

      if block
        block.call(key)
      elsif args.size == 1
        args.first
      elsif args.empty?
        raise KeyError, "key not found: #{key}"
      else
        raise ArgumentError, "wrong number of arguments (given #{args.size + 1}, expected 1..2)"
      end
    end

    def key?(key)
      !index_for_key(key.to_s).nil?
    end
    alias has_key? key?

    def keys
      raw_items.map { |raw_key, _, _| URI.decode_www_form_component(raw_key) }
    end

    def values
      raw_items.map do |_, has_equal, raw_value|
        has_equal ? URI.decode_www_form_component(raw_value) : nil
      end
    end

    def values_at(*keys)
      keys.map { |key| self[key] }
    end

    def size
      return 0 if @uri.query.nil? || @uri.query.empty?

      @uri.query.count('&') + 1
    end
    alias length size

    def empty?
      size.zero?
    end

    def to_h
      result = {}
      each { |key, value| result[key] = value }
      result
    end

    def inspect
      "#<#{self.class} #{to_a.inspect}>"
    end

    private

    def raw_items
      return [] if @uri.query.nil? || @uri.query.empty?

      @uri.query.split('&', -1).map do |raw_item|
        equal_index = raw_item.index('=')
        if equal_index
          [raw_item[0, equal_index], true, raw_item[(equal_index + 1)..] || '']
        else
          [raw_item, false, '']
        end
      end
    end

    def item_at(index)
      items = raw_items
      index += items.size if index < 0
      raise IndexError, "index #{index} outside of query bounds: #{items.size}" unless index >= 0 && index < items.size

      QueryItem.new(self, index)
    end

    def set_key_at(index, key)
      items = raw_items
      index += items.size if index < 0
      raise IndexError, "index #{index} outside of query bounds: #{items.size}" unless index >= 0 && index < items.size

      _raw_key, has_equal, raw_value = items[index]
      replacement = URI.encode_www_form_component(key)
      replacement << '=' << raw_value if has_equal
      replace_item(index, replacement, items)
      key
    end

    def set_value_at(index, value)
      items = raw_items
      index += items.size if index < 0
      raise IndexError, "index #{index} outside of query bounds: #{items.size}" unless index >= 0 && index < items.size

      raw_key, = items[index]
      if value.nil?
        replacement = raw_key
      else
        replacement = "#{raw_key}=#{URI.encode_www_form_component(value)}"
      end
      replace_item(index, replacement, items)
      value
    end

    def serialize_raw_item(item)
      raw_key, has_equal, raw_value = item
      return raw_key unless has_equal

      "#{raw_key}=#{raw_value}"
    end

    def replace_item(index, replacement, items = raw_items)
      query = @uri.query || ''
      offset = index == 0 ? 0 : items.first(index).sum { |item| serialize_raw_item(item).bytesize + 1 }
      old_item = serialize_raw_item(items[index])
      tail_offset = offset + old_item.bytesize
      raw_query = query.b
      prefix = raw_query.byteslice(0, offset)
      suffix_length = raw_query.bytesize - tail_offset
      suffix = suffix_length.zero? ? +'' : raw_query.byteslice(tail_offset, suffix_length)
      update_query((prefix + replacement + suffix).force_encoding(Encoding::US_ASCII))
    end

    def index_for_key(key)
      raw_items.each_with_index do |(raw_key, _, _), index|
        return index if key_matches?(raw_key, key)
      end
      nil
    end

    def key_matches?(raw_key, key)
      return true if raw_key == key

      URI.decode_www_form_component(raw_key) == key
    rescue ArgumentError
      false
    end

    def update_query(query)
      @uri.query = query
    end
  end

  Ractor.make_shareable(QueryParams::QueryItem) if defined?(Ractor)
  Ractor.make_shareable(QueryParams) if defined?(Ractor)
end
