# frozen_string_literal: false
#--
# = uri/query_params.rb
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# License::
#   You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative "common"
module URI

  # An editable view over the query component of a URI that preserves
  # the original bytes of the query string.
  #
  # Unlike building a query from URI.decode_www_form and URI.encode_www_form,
  # a QueryParams object:
  #
  # - Preserves the order of the query items, including duplicate keys.
  # - Preserves the original percent-encoding of untouched items
  #   (including <tt>+</tt> versus <tt>%20</tt> and lowercase hexadecimal
  #   digits such as <tt>%2f</tt>).
  # - Distinguishes an item without an equals sign
  #   (whose value is +nil+), an item with an empty value, and a trailing
  #   empty parameter produced by a trailing <tt>&</tt>.
  # - Re-encodes only the single item that is modified; every other byte
  #   of the query string is left untouched.
  #
  # The three states of a missing or empty query component are kept apart:
  #
  #   URI('http://example.com/path').query           #=> nil
  #   URI('http://example.com/path?').query          #=> ""
  #   URI('http://example.com/path?a=').query        #=> "a="
  #
  #   URI('http://example.com/path').query_params.present?   #=> false
  #   URI('http://example.com/path?').query_params.present?  #=> true
  #   URI('http://example.com/path?').query_params.empty?    #=> true
  #
  class QueryParams
    include Enumerable

    # Represents a single query item at a fixed position.
    #
    # +key+ and +value+ are decoded, while the original spelling of the
    # item (including its original percent-encoding) is retained by the
    # owning QueryParams object.
    #
    # An item without an equals sign has a +nil+ value:
    #
    #   URI('http://example.com/?a&b=').query_params.items
    #   # => [#<struct URI::QueryParams::Item key="a", value=nil>,
    #   #     #<struct URI::QueryParams::Item key="b", value="">]
    #
    Item = Struct.new(:key, :value)

    # Returns a new QueryParams over the given +target+.
    #
    # +target+ may be a URI, which keeps the view connected to the URI
    # (modifications update its query component), or a query string, which
    # produces a detached view whose result is available through #to_s:
    #
    #   qp = URI::QueryParams.new(URI('http://example.com/?a=1'))
    #   qp[0] = '2'
    #
    def initialize(target)
      if !target.nil? && target.respond_to?(:query) && target.respond_to?(:query=)
        @target = target
      else
        @target = DetachedTarget.new(target.nil? ? nil : String(target))
      end
      reload
    end

    # Returns a new QueryParams parsed from the query string +str+.
    def self.parse(str)
      new(str)
    end

    # Reloads the items from the current query component of the target.
    #
    # This disconnects items previously returned by #items or #at.
    def reload
      @entries = parse_entries(@target.query)
      self
    end

    # Returns whether the URI has a query component at all.
    #
    # A URI without <tt>?</tt> has no query; a URI ending in <tt>?</tt>
    # has a present but empty query.
    def present?
      !@target.query.nil?
    end

    # Returns whether the query component is present and empty.
    #
    # A missing query component is not empty; use #present? to test for it.
    def empty?
      present? && @entries.empty?
    end

    # Returns the number of query items.
    def size
      @entries.size
    end
    alias length size

    # Returns the decoded value of the item at +index+ or of the first
    # item with the given +key+.
    #
    # Lookup by key does not collapse duplicate keys; only the first item
    # with the key is returned. An item without an equals sign has value
    # +nil+, which cannot be distinguished from a missing key here; use
    # #index or #items when that distinction matters.
    def [](index_or_key)
      entry = entry_for(index_or_key)
      entry&.decoded_value
    end

    # Sets the value of a single item and re-encodes only that item.
    #
    # With an Integer index, the item at that position is modified:
    #
    #   qp = URI::QueryParams.parse('a=1&a=2')
    #   qp[1] = '3'
    #   qp.to_s #=> "a=1&a=3"
    #
    # With a String key, only the first item with that key is modified;
    # other items sharing the key are left untouched. If no item has the
    # key, a new item is appended:
    #
    #   qp = URI::QueryParams.parse('a=1&a=2')
    #   qp['a'] = '3'
    #   qp.to_s #=> "a=3&a=2"
    #
    # A +nil+ value removes the equals sign of the item, while an empty
    # string produces an empty value:
    #
    #   qp = URI::QueryParams.parse('a=1')
    #   qp[0] = nil
    #   qp.to_s #=> "a"
    #
    def []=(index_or_key, value)
      if index_or_key.is_a?(Integer)
        set_at(index_or_key, value)
      else
        index = index(index_or_key)
        if index
          set_at(index, value)
        else
          add(index_or_key, value)
        end
      end
    end

    # Returns the Item at +index+, or the first Item whose key equals
    # +key+.
    def at(index_or_key)
      entry = entry_for(index_or_key)
      entry && Item.new(entry.decoded_key, entry.decoded_value)
    end

    # Returns a snapshot array of the query items, preserving order and
    # duplicate keys.
    def items
      @entries.map {|entry| Item.new(entry.decoded_key, entry.decoded_value) }
    end
    alias to_a items

    # Returns the index of the first item with the given decoded +key+,
    # or +nil+ if there is no such item.
    def index(key)
      @entries.index {|entry| entry.decoded_key == key }
    end

    # Returns the indices of all items with the given decoded +key+.
    def indices(key)
      result = []
      @entries.each_with_index {|entry, i| result << i if entry.decoded_key == key }
      result
    end

    # Yields each decoded key/value pair in order.
    #
    # Items without an equals sign are yielded with a +nil+ value.
    def each_pair
      return enum_for(__method__) unless block_given?
      @entries.each do |entry|
        yield entry.decoded_key, entry.decoded_value
      end
      self
    end

    # Yields each Item snapshot in order.
    def each
      return enum_for(__method__) unless block_given?
      items.each {|item| yield item }
      self
    end

    # Appends a new item to the end of the query.
    def add(key, value = nil)
      @entries << Entry.build(key, value)
      write
      self
    end
    alias append add

    # Inserts a new item before the item at +index+.
    def insert(index, key, value = nil)
      @entries.insert(index, Entry.build(key, value))
      write
      self
    end

    # Deletes the item at +index+ and returns its decoded [key, value] pair.
    def delete_at(index)
      removed = @entries.delete_at(index)
      return nil unless removed
      write
      [removed.decoded_key, removed.decoded_value]
    end

    # Deletes the first item with the given +key+ and returns its decoded
    # value. Items with the same key at other positions are preserved.
    def delete(key)
      idx = index(key)
      return nil unless idx
      delete_at(idx).last
    end

    # Drops every item while keeping the query component present but empty.
    #
    # The URI then has a query of <tt>""</tt> (that is, it ends with
    # <tt>?</tt>); use URI::Generic#query= with +nil+ to remove the query
    # component entirely.
    def clear
      @entries = []
      write
      self
    end

    # Returns the current query string with its original spelling for
    # untouched items.
    #
    # Returns +nil+ when the target has no query component, and an empty
    # string when the query component is present but empty.
    def to_s
      @target.query
    end

    # Returns the decoded key/value pairs as an array, like
    # URI.decode_www_form but with +nil+ values for items without an
    # equals sign.
    def pairs
      @entries.map {|entry| [entry.decoded_key, entry.decoded_value] }
    end

    private

    def entry_for(index_or_key)
      if index_or_key.is_a?(Integer)
        @entries[index_or_key]
      else
        idx = index(index_or_key)
        idx && @entries[idx]
      end
    end

    def set_at(index, value)
      entry = @entries.fetch(index)
      @entries[index] = Entry.build(entry.decoded_key, value)
      write
      value
    end

    def parse_entries(query)
      return [] if query.nil? || query.empty?
      query.split('&', -1).map {|part| Entry.new(part) }
    end

    def write
      query = @entries.empty? ? '' : compose(@entries)
      if @target.respond_to?(:set_query_for_query_params)
        @target.set_query_for_query_params(query)
      else
        @target.query = query
      end
      query = @target.query
      @entries = parse_entries(query)
      self
    end

    def compose(entries)
      return '' if entries.empty?
      entries.map(&:segment).join('&')
    end

    # One item backed by its original (possibly modified) segment bytes.
    class Entry # :nodoc: all
      attr_reader :segment

      def self.build(key, value)
        part = URI.encode_www_form_component(key)
        unless value.nil?
          part += '='
          part += URI.encode_www_form_component(value)
        end
        new(part)
      end

      def initialize(segment)
        @segment = segment
      end

      def raw_key
        key, _sep, _value = @segment.partition('=')
        key
      end

      def has_value?
        @segment.include?('=')
      end

      def raw_value
        return nil unless has_value?
        @segment[(@segment.index('=') + 1)..]
      end

      def decoded_key
        URI.decode_www_form_component(raw_key)
      end

      def decoded_value
        return nil unless has_value?
        URI.decode_www_form_component(raw_value)
      end
    end

    # Target adapter for a query string not attached to a URI.
    class DetachedTarget # :nodoc: all
      attr_accessor :query

      def initialize(query)
        @query = query
      end
    end
  end
end
