# frozen_string_literal: true
require 'http/cookie'
require 'strscan'
require 'time'

class HTTP::Cookie::Scanner < StringScanner
  # Whitespace.
  RE_WSP = /[ \t]+/

  # A pattern that matches a cookie name or attribute name which may
  # be empty, capturing trailing whitespace.
  RE_NAME = /(?!#{RE_WSP})[^,;\\"=]*/

  RE_BAD_CHAR = /([\x00-\x20\x7F",;\\])/

  # A pattern that matches the comma in a (typically date) value.
  RE_COOKIE_COMMA = /,(?=#{RE_WSP}?#{RE_NAME}=)/

  def initialize(string, logger = nil, strict_categories: [])
    @logger = logger
    @issues = []
    @strict_categories = strict_categories
    super(string)
  end

  class << self
    def quote(s)
      return s unless s.match(RE_BAD_CHAR)
      (+'"') << s.gsub(/([\\"])/, "\\\\\\1") << '"'
    end
  end

  def skip_wsp
    skip(RE_WSP)
  end

  def scan_dquoted
    value, = scan_dquoted_with_diagnostics(false, pos - 1)
    value
  end

  def scan_name
    name, = scan_name_with_range
    name
  end

  def scan_value(comma_as_separator = false)
    value, = scan_value_with_diagnostics(comma_as_separator)
    value
  end

  def scan_name_value(comma_as_separator = false)
    name, = scan_name_with_range
    if skip(/=/)
      value, = scan_value_with_diagnostics(comma_as_separator)
    else
      scan_value_with_diagnostics(comma_as_separator)
      value = nil
    end
    [name, value]
  end

  if Time.respond_to?(:strptime)
    def tuple_to_time(day_of_month, month, year, time)
      Time.strptime(
        '%02d %s %04d %02d:%02d:%02d UTC' % [day_of_month, month, year, *time],
        '%d %b %Y %T %Z'
      ).tap { |date|
        date.day == day_of_month or return nil
      }
    end
  else
    def tuple_to_time(day_of_month, month, year, time)
      Time.parse(
        '%02d %s %04d %02d:%02d:%02d UTC' % [day_of_month, month, year, *time]
      ).tap { |date|
        date.day == day_of_month or return nil
      }
    end
  end
  private :tuple_to_time

  def parse_cookie_date(s, value_start = nil)
    # RFC 6265 5.1.1
    time = day_of_month = month = year = nil

    date_scanner = StringScanner.new(s)
    until date_scanner.eos?
      date_scanner.skip(/[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]+/)
      break if date_scanner.eos?

      token_start = date_scanner.pos
      token = date_scanner.scan(/[^\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]+/)
      case
      when time.nil? && token.match(/\A(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?(?=\D|\z)/)
        sec =
          if $3
            $3.to_i
          else
            # violation of the RFC
            @logger.warn("Time lacks the second part") if @logger
            issue_start = value_start || 0
            add_issue(:expires_missing_seconds, :default_seconds,
                      issue_start + token_start,
                      issue_start + token_start + token.length)
            0
          end
        time = [$1.to_i, $2.to_i, sec]
      when day_of_month.nil? && token.match(/\A(\d{1,2})(?=\D|\z)/)
        day_of_month = $1.to_i
      when month.nil? && token.match(/\A(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/i)
        month = $1.capitalize
      when year.nil? && token.match(/\A(\d{2,4})(?=\D|\z)/)
        year = $1.to_i
      end
    end

    if day_of_month.nil? || month.nil? || year.nil? || time.nil?
      return nil
    end

    case day_of_month
    when 1..31
    else
      return nil
    end

    case year
    when 100..1600
      return nil
    when 70..99
      year += 1900
    when 0..69
      year += 2000
    end

    hh, mm, ss = time
    if hh > 23 || mm > 59 || ss > 59
      return nil
    end

    tuple_to_time(day_of_month, month, year, time)
  rescue ArgumentError
    nil
  end

  def scan_set_cookie(&block)
    each_set_cookie_record { |record|
      next if record[:issues].any? { |issue| issue[:action] == :reject }

      attrs = {}
      record[:attrs].each { |attr|
        attrs[attr[:name]] = attr[:value]
      }
      yield record[:name], record[:value], attrs
    }
  end

  def scan_cookie
    # RFC 6265 4.1.1 & 5.4
    until eos?
      skip_wsp

      # Do not treat comma in a Cookie header value as separator; see CVE-2016-7401
      name, value = scan_name_value(false)

      yield name, value if value

      skip(/;/)
    end
  end

  def each_set_cookie_record
    return enum_for(__method__) unless block_given?

    until eos?
      @issues = []
      record_start = pos
      skip_wsp
      pair_start = pos

      name, name_start, name_end = scan_name_with_range
      has_equals = skip(/=/)
      if has_equals
        value, value_meta = scan_value_with_diagnostics(true)
      else
        _, value_meta = scan_value_with_diagnostics(true)
        value = nil
      end

      if name.empty? && !has_equals
        add_issue(:missing_name_value_pair, :reject, pair_start, pos)
      elsif name.empty?
        add_issue(:empty_cookie_name, :reject, name_start, name_end)
      elsif value.nil?
        add_issue(:missing_name_value_pair, :reject, pair_start, pos)
      elsif name.match?(/[\x00-\x20\x7F,;\\"=]/)
        add_issue(:invalid_cookie_name, :reject, name_start, name_end)
      elsif value.match?(/[\x00-\x1F\x7F]/)
        add_issue(:invalid_cookie_value, :reject,
                  value_meta[:start], value_meta[:end])
      end

      attrs = scan_attributes
      record_end = pos
      range = byte_range(record_start, record_end)

      if range.last > HTTP::Cookie::MAX_LENGTH
        add_issue(:cookie_too_long, :reject, record_start, record_end)
      end

      yield({
        :name => name,
        value: value,
        attrs: attrs,
        issues: @issues,
        range: range,
      })
    end
  end

  private

  def byte_range(start_pos, end_pos)
    offset = string.byteslice(0...start_pos).bytesize
    length = string.byteslice(start_pos...end_pos).bytesize
    [offset, length]
  end

  def add_issue(category, action, start_pos, end_pos = start_pos, attribute: nil)
    @issues << {
      category: category,
      action: @strict_categories.include?(category) ? :reject : action,
      byte_range: byte_range(start_pos, end_pos),
      attribute: attribute,
    }
  end

  def closing_quote_position(string)
    index = 0

    while (quote_pos = string.index('"', index))
      backslashes = 0
      check_pos = quote_pos - 1
      while check_pos >= 0 && string[check_pos] == '\\'
        backslashes += 1
        check_pos -= 1
      end
      return quote_pos if backslashes.even?

      index = quote_pos + 1
    end

    nil
  end

  def quoted_value_boundary_position(string, comma_as_separator)
    quote_pos = closing_quote_position(string)
    semicolon_pos = string.index(';')
    positions = []

    if quote_pos.nil?
      positions = [semicolon_pos].compact
      if comma_as_separator && (match = string.match(RE_COOKIE_COMMA))
        positions << match.begin(0)
      end
    elsif semicolon_pos && semicolon_pos < quote_pos
      between = string.byteslice((semicolon_pos + 1)...quote_pos)
      return semicolon_pos if between&.match?(RE_COOKIE_COMMA)
    end

    positions.min
  end

  def scan_name_with_range
    start_pos = pos
    raw_name = scan(RE_NAME) || +''
    name = raw_name.rstrip
    [name, start_pos, start_pos + name.length]
  end

  def scan_dquoted_with_diagnostics(comma_as_separator, quote_start)
    value = +''
    closed = false
    quote_pos = closing_quote_position(rest)
    boundary_pos = quoted_value_boundary_position(rest, comma_as_separator)
    close_pos =
      if quote_pos && (boundary_pos.nil? || quote_pos < boundary_pos)
        quote_pos
      end

    if close_pos
      until close_pos.zero? || check(/"/)
        case
        when scan(/[^"\\]+/)
          value << matched
        when skip(/\\/)
          value << getch
        end
      end
      skip(/"/)
      closed = true
    else
      until eos?
        case
        when scan(/[^"\\,;]+/)
          value << matched
        when skip(/\\/)
          value << '\\'
          if eos?
            add_issue(:invalid_escape, :ignore, pos - 1, pos)
          else
            value << getch
          end
        when check(/;/)
          break
        when comma_as_separator && check(RE_COOKIE_COMMA)
          break
        else
          value << getch
        end
      end
    end

    unless closed
      add_issue(:unterminated_quote, :accept_partial, quote_start, pos)
    end

    [value, closed]
  end

  def scan_value_with_diagnostics(comma_as_separator = false)
    start_pos = pos
    value = +''
    quoted = false
    closed = true

    until eos?
      case
      when scan(/[^,;"]+/)
        value << matched
      when skip(/"/)
        quoted = true
        part, part_closed = scan_dquoted_with_diagnostics(
          comma_as_separator, pos - 1
        )
        closed &&= part_closed
        value << part
      when check(/;/)
        break
      when comma_as_separator && check(RE_COOKIE_COMMA)
        break
      else
        value << getch
      end
    end

    value.rstrip!
    [value, quoted: quoted, closed: closed, start: start_pos, end: pos]
  end

  def scan_attributes
    attrs = []

    until eos?
      skip_wsp

      if skip(/;/)
        skip_wsp
        while check(/;/)
          empty_start = pos
          getch
          add_issue(:empty_attribute, :ignore, empty_start, empty_start + 1)
          skip_wsp
        end

        break if eos? || check(/,/)

        attr = scan_attribute(attrs)
        attrs << attr if attr
      elsif skip(/,/)
        # A comma separates concatenated Set-Cookie values. Values stop
        # at commas that look like another cookie, so this is a trailing
        # or separator comma here.
        break
      else
        bad_start = pos
        getch
        add_issue(:malformed_header, :ignore, bad_start, pos)
      end
    end

    attrs
  end

  def scan_attribute(accepted_attrs)
    attr_start = pos
    name, name_start, name_end = scan_name_with_range
    has_equals = skip(/=/)
    if has_equals
      value, value_meta = scan_value_with_diagnostics(true)
    else
      _, value_meta = scan_value_with_diagnostics(true)
      value = nil
    end
    value_end = value_meta[:end]

    if name.empty?
      add_issue(:empty_attribute, :ignore, attr_start, value_end)
      return nil
    end

    canonical_name = name.downcase
    if accepted_attrs.any? { |attr| attr[:name] == canonical_name }
      action =
        case canonical_name
        when 'secure', 'httponly'
          :ignore_duplicate
        else
          :overwrite
        end
      add_issue(:duplicate_attribute, action, name_start, name_end,
                attribute: canonical_name)
    end

    parsed_value = value
    valid = true

    case canonical_name
    when 'expires'
      if value.nil? || value.empty?
        valid = false
        add_issue(:invalid_expires, :ignore,
                  value_meta[:start], value_end, attribute: canonical_name)
      else
        parsed_value = parse_cookie_date(value, value_meta[:start])
        unless parsed_value
          valid = false
          add_issue(:invalid_expires, :ignore,
                    value_meta[:start], value_end, attribute: canonical_name)
        end
      end
    when 'max-age'
      unless value && /\A-?\d+\z/.match?(value)
        valid = false
        add_issue(:invalid_max_age, :ignore,
                  value_meta[:start], value_end, attribute: canonical_name)
      end
    when 'domain'
      if value.nil? || value.empty?
        valid = false
        add_issue(:invalid_domain, :ignore,
                  value_meta[:start], value_end, attribute: canonical_name)
      end
    when 'path'
      unless value && /\A\//.match?(value)
        valid = false
        add_issue(:invalid_path, :ignore,
                  value_meta[:start], value_end, attribute: canonical_name)
      end
    when 'secure', 'httponly'
      parsed_value = true
    else
      add_issue(:unknown_attribute, :ignore,
                name_start, name_end, attribute: canonical_name)
    end

    return unless valid

    {
      name: canonical_name,
      value: parsed_value,
      name_range: byte_range(name_start, name_end),
      value_range: byte_range(value_meta[:start], value_end),
    }
  end
end
