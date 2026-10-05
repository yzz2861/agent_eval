# encoding: utf-8
# frozen_string_literal: true
require 'date'

module Mail
  class ReceivedHop
    KEYS = [:from, :by, :with, :id, :for].freeze
    MARKER_KEYS = (KEYS + [:via]).freeze

    attr_reader :raw, :raw_field, :info, :from, :by, :with, :id, :for,
                :unrecognized, :date, :date_time,
                :delay_seconds, :error
    alias_method :unknown, :unrecognized
    alias_method :delay, :delay_seconds

    def self.parse(raw, previous_hop = nil, raw_field: nil)
      new(raw, previous_hop, raw_field: raw_field)
    rescue => error
      hop = allocate
      hop.send(:initialize_failure, raw.to_s, error, raw_field)
      hop
    end

    def initialize(raw, previous_hop = nil, raw_field: nil)
      @raw = raw.to_s
      @raw_field = raw_field || "Received: #{@raw}"
      @unrecognized = []
      parse_value(unfold(@raw))
      calculate_delay(previous_hop)
    end

    def to_h
      {
        raw: raw,
        raw_field: raw_field,
        info: info,
        from: from,
        by: by,
        with: with,
        id: id,
        for: self.for,
        unrecognized: unrecognized.dup,
        unknown: unrecognized.dup,
        date: date,
        date_time: date_time,
        delay: delay_seconds,
        delay_seconds: delay_seconds,
        delay_missing: delay_missing?,
        negative_delay: negative_delay?,
        error: error
      }
    end

    def delay_missing?
      delay_seconds.nil?
    end
    alias_method :missing_delay?, :delay_missing?

    def negative_delay?
      !delay_seconds.nil? && delay_seconds < 0
    end

    def to_s(index = nil, total = nil)
      text = +''
      text << "#{index + 1}/#{total}: " if index && total
      text << (from || '(unknown sender)')
      text << " -> #{by}" if by
      text << " via #{with}" if with
      text << " for #{self.for}" if self.for
      text << " [#{unrecognized.join(' ')}]" unless unrecognized.empty?
      text << " at #{date}" if date
      text << " (#{delay_label})"
      text
    end

    private

    def initialize_failure(raw, error, raw_field = nil)
      @raw = raw
      @raw_field = raw_field || "Received: #{raw}"
      @info = nil
      @from = @by = @with = @id = @for = nil
      @unrecognized = []
      @date = nil
      @date_time = nil
      @delay_seconds = nil
      @error = error
    end

    def unfold(string)
      string.gsub(/\r?\n([ \t]+)/, '\1')
    end

    def parse_value(value)
      info, date_text = split_date(value)
      @info = info
      parse_info(info)
      parse_date(date_text)
    end

    def split_date(value)
      position = top_level_semicolon(value)
      return [value, nil] unless position

      [value[0...position].strip, value[(position + 1)..-1].to_s.strip]
    end

    def top_level_semicolon(value)
      stack = []
      escaped = false
      quoted = false

      value.each_char.with_index do |character, index|
        if escaped
          escaped = false
        elsif quoted
          escaped = character == '\\'
          quoted = false if character == '"' && !escaped
        elsif stack.last == :comment
          case character
          when '\\' then escaped = true
          when '(' then stack << :comment
          when ')' then stack.pop
          end
        else
          case character
          when '(' then stack << :comment
          when '"' then quoted = true
          when '<' then stack << :angle unless stack.include?(:angle)
          when '>' then stack.delete(:angle)
          when '[' then stack << :literal unless stack.include?(:literal)
          when ']' then stack.delete(:literal)
          when ';' then return index if stack.empty?
          end
        end
      end

      nil
    end

    def parse_info(info)
      KEYS.each { |key| instance_variable_set("@#{key}", nil) }

      segment = +''
      active_key = nil
      stack = []
      escaped = false
      quoted = false
      index = 0

      while index < info.length
        character = info[index]

        if escaped
          segment << character
          escaped = false
          index += 1
        elsif quoted
          segment << character
          escaped = character == '\\'
          quoted = false if character == '"' && !escaped
          index += 1
        elsif stack.last == :comment
          segment << character
          case character
          when '\\' then escaped = true
          when '(' then stack << :comment
          when ')' then stack.pop
          end
          index += 1
        else
          case character
          when '(' then stack << :comment; segment << character; index += 1
          when '"' then quoted = true; segment << character; index += 1
          when '<' then stack << :angle unless stack.include?(:angle); segment << character; index += 1
          when '>' then stack.delete(:angle); segment << character; index += 1
          when '[' then stack << :literal unless stack.include?(:literal); segment << character; index += 1
          when ']' then stack.delete(:literal); segment << character; index += 1
          else
            marker = marker_at(info, index)
            if marker
              store_segment(active_key, segment)
              active_key = marker
              segment = +''
              index += marker.length
            else
              segment << character
              index += 1
            end
          end
        end
      end

      unless stack.empty? && !quoted
        raise Mail::Field::ParseError.new(self.class, @raw, 'unbalanced comment or quoted string')
      end

      store_segment(active_key, segment)
    end

    def marker_at(info, index)
      return nil unless index.zero? || whitespace?(info[index - 1])

      MARKER_KEYS.find do |key|
        word = key.to_s
        next_position = index + word.length
        next if info[index, word.length].downcase != word
        next if next_position < info.length && info[next_position] =~ /\A[A-Za-z0-9!#\$%&'*+\/=?^_`{|}~-]\z/

        word.to_sym
      end
    end

    def store_segment(key, segment)
      value = clean_segment(segment)
      return if value.empty?

      if key && KEYS.include?(key)
        instance_variable_set("@#{key}", value)
      else
        @unrecognized << (key ? "#{key} #{value}" : value)
      end
    end

    def clean_segment(segment)
      segment.gsub(/[\t ]+/, ' ').strip
    end

    def parse_date(date_text)
      @date = date_text
      @date_time = DateTime.parse(date_text) unless date_text.nil? || date_text.empty?
    rescue ArgumentError => error
      raise unless error.message == 'invalid date'

      @date_time = nil
      @error = error
    end

    def calculate_delay(previous_hop)
      if previous_hop&.date_time && date_time
        seconds = (previous_hop.date_time - date_time) * 86400
        @delay_seconds = seconds == seconds.to_i ? seconds.to_i : seconds.to_f
      else
        @delay_seconds = nil
      end
    end

    def delay_label
      delay_seconds ? "#{delay_seconds}s" : 'delay unknown'
    end

    def whitespace?(character)
      character == ' ' || character == "\t"
    end
  end
end
