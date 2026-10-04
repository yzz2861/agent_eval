# frozen_string_literal: true

require 'date'

module Fugit

  class CronConversionError < ArgumentError
    attr_reader :result
    def initialize(result); @result = result; super(result[:errors].map { |e| e[:message] }.join('; ')); end
  end

  module_function

  def convert_cron(
    expression, from: nil, dialect: nil, source: nil,
    base_position: 0, verify: true)

    d = from || dialect || source
    fail ArgumentError.new('missing keyword: :from') if d.nil?

    id = d.to_s.downcase.tr('-', '_').to_sym
    unless [ :unix, :quartz ].include?(id)
      fail ArgumentError.new("unsupported source dialect #{d.inspect}")
    end

    klass = id == :unix ? CronConverter::Unix : CronConverter::Quartz
    klass.new(expression, base_position, verify).convert
  end

  def do_convert_cron(expression, **opts)
    result = convert_cron(expression, **opts)
    fail CronConversionError.new(result) unless result[:ok]
    result[:cron]
  end

  module CronConverter

    VERIFY_START = Date.new(2024, 1, 1)
    VERIFY_DAYS = 366 + 365 * 3
    MONTHS = [ nil, *%w[ JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC ] ].freeze
    WEEKDAYS = %w[ SUN MON TUE WED THU FRI SAT ].freeze
    FIELDS = %i[second minute hour day_of_month month day_of_week year].freeze

    def self.issue(code, message, field, field_index, position, length, base)
      h = { code: code, message: message, field: field, field_index: field_index }
      h[:position] = base + position if position
      h[:column] = h[:position] + 1 if position
      h[:length] = length if length
      h
    end

    class Common
      def initialize(expression, base_position, verify)
        @expression = expression
        @base_position = base_position.to_i
        @verify = verify
        @issues = []
      end

      def convert
        return invalid_input unless @expression.is_a?(String)
        parse_and_build
        verify! if @issues.empty? && @verify
        result
      end

      private

      def invalid_input
        @issues << CronConverter.issue(:invalid_input, 'source must be a String', nil, nil, 0, @expression.to_s.length, 0)
        result
      end

      def result
        if @issues.empty?
          { ok: true, source_dialect: dialect, source: @expression,
            original: @expression,
            expression: @target, cron: @cron, errors: [] }
        else
          { ok: false, source_dialect: dialect, source: @expression,
            original: @expression,
            expression: nil, cron: nil, errors: @issues }
        end
      end

      def issue(code, message, field: nil, position: nil, length: nil)
        @issues << CronConverter.issue(
          code, message, field, field && FIELDS.index(field), position, length, @base_position)
      end

      def split(expected)
        pos = 0
        fields = []
        while (m = /\S+/.match(@expression, pos))
          fields << { text: m[0], start: m.begin(0), end: m.end(0) }
          pos = m.end(0)
        end
        if fields.length != expected
          issue(:invalid_field_count,
            "#{dialect_name} source must contain #{expected} fields, found #{fields.length}",
            position: 0, length: [ @expression.strip.length, 1 ].max)
        end
        fields.length == expected ? fields : nil
      end

      def field_for(fields, position)
        fields.each_with_index { |f, i| return i if position >= f[:start] && position < f[:end] }
        nil
      end

      def target_parse(s)
        c = Fugit::Cron.parse(s)
        unless c
          issue(:unrepresentable_schedule,
            'converted schedule is not executable by Fugit',
            position: 0, length: [ @expression.length, 1 ].max)
        end
        c
      end

      def verify!
        verify_time_arrays!
        verify_days! unless @issues.any?
      end

      def verify_time_arrays!
      end

      def verify_days!
        date = VERIFY_START
        mismatches = []
        VERIFY_DAYS.times do
          expected = source_day?(date)
          actual = cron_day?(@cron, date)
          mismatches << date.to_s if expected != actual
          break if mismatches.length >= 3
          date = date.next_day
        end
        return if mismatches.empty?
        issue(:verification_failed,
          "converted schedule differs from source in verification window, first mismatch #{mismatches.first}",
          position: 0, length: @expression.length)
      end

      def target_day?(cron, date)
        return false unless (cron.months || (1..12).to_a).include?(date.month)
        doms = cron.monthdays
        dows = cron.weekdays
        dom = doms.nil? || doms.any? { |d| target_dom?(d, date) }
        dow = dows.nil? || dows.any? { |w, nth| target_dow?(w, nth, date) }
        if doms && dows
          cron.instance_variable_get(:@day_and) ? dom && dow : dom || dow
        else
          dom && dow
        end
      end

      def target_dom?(value, date)
        value < 1 ? date.day == Date.new(date.year, date.month, -1).day + value + 1 : date.day == value
      end

      def target_dow?(wday, nth, date)
        return false unless wday == date.wday
        return true unless nth.is_a?(Integer)
        if nth > 0
          (date.day - 1) / 7 + 1 == nth
        else
          (Date.new(date.year, date.month, -1).day - date.day) / 7 + 1 == -nth
        end
      end

      alias cron_day? target_day?
    end

    class Unix < Common
      def dialect; :unix; end
      def dialect_name; 'Unix cron'; end
      private
      def parse_and_build
        fields = split(5)
        return unless fields
        if (p = @expression.index('?'))
          issue(:unsupported_question_mark, "'?' is not valid in Unix cron",
            field: FIELDS[field_for(fields, p) || 0], position: p, length: 1)
          return
        end
        @source_cron = Fugit::Cron.parse(@expression)
        unless @source_cron
          issue(:unrepresentable_schedule,
            'Unix source is not an executable Fugit cron expression',
            position: 0, length: [ @expression.length, 1 ].max)
          return
        end
        @target = @source_cron.to_cron_s
        @cron = target_parse(@target)
      end
      def source_day?(date)

        return false unless (@source_cron.months || (1..12).to_a).include?(date.month)
        doms = @source_cron.monthdays
        dows = @source_cron.weekdays
        dom = doms.nil? || doms.any? { |d| unix_dom?(d, date) }
        dow = dows.nil? || dows.any? { |w, nth| unix_dow?(w, nth, date) }
        if doms && dows
          @source_cron.instance_variable_get(:@day_and) ? dom && dow : dom || dow
        else
          dom && dow
        end
      end

      def unix_dom?(value, date)

        value < 1 ?
          date.day == Date.new(date.year, date.month, -1).day + value + 1 :
          date.day == value
      end

      def unix_dow?(wday, nth, date)

        return false unless wday == date.wday
        return true unless nth.is_a?(Integer)
        if nth > 0
          (date.day - 1) / 7 + 1 == nth
        else
          (Date.new(date.year, date.month, -1).day - date.day) / 7 + 1 == -nth
        end
      end
    end

    class Quartz < Common
      def dialect; :quartz; end
      def dialect_name; 'Quartz cron'; end
      private
      def parse_and_build
        count = @expression.strip.split(/\s+/).length
        fields = split(count == 7 ? 7 : 6)
        return unless fields
        @sec = parse_numeric_values(fields[0], 0, 0, 59)
        @min = parse_numeric_values(fields[1], 1, 0, 59)
        @hour = parse_numeric_values(fields[2], 2, 0, 23)
        @dom = parse_dom(fields[3])
        @month = parse_month(fields[4])
        @dow = parse_dow(fields[5])
        parse_year(fields[6])
        validate_day_combination(fields) if @dom && @dow
        return unless @issues.empty? && @sec && @min && @hour && @month
        @target = render_target
        @cron = target_parse(@target)
      end

      def parse_numeric_field(field, index, min, max)

        nodes, _ = parse_generic(field, index, min, max)
        if nodes.nil? && field[:text] == '?'
          unsupported(field, index, field[:start], 1, "'?' in #{FIELDS[index]}")
        end
        nodes
      end

      def parse_numeric_values(field, index, min, max)

        nodes = parse_numeric_field(field, index, min, max)
        nodes && expand(nodes)
      end

      def parse_generic(field, index, min, max, names=nil)

        return [ nil, :question ] if field[:text] == '?'
        return [ nil, :wild ] if field[:text] == '*'

        nodes = []

        scan_tokens(field) do |token, start, length|
          add_generic_node(nodes, token, start, length, field, index, min, max, names)
        end

        [ nodes, nodes ]
      end

      def scan_tokens(field)

        pos = 0
        text = field[:text]
        text.split(',', -1).each do |raw|
          token = raw.strip
          start = field[:start] + pos + (raw.length - raw.lstrip.length)
          pos += raw.length + 1
          yield(token, start, [ token.length, 1 ].max)
        end
      end

      def add_generic_node(nodes, token, start, length, field, index, min, max, names)

        if token.empty?
          invalid(field, index, start, length)
          return
        end

        range_part, step_part = token.split('/', 2)

        calendar =
          names.nil? &&
          (token =~ /(?:\A|[^A-Z])\d*C\d*(?:\z|[^0-9])/i ||
           step_part&.include?('C'))

        if calendar
          unsupported(field, index, start, length, "'C' calendar offsets")
          return
        end

        if step_part&.include?('/')
          invalid(field, index, start, length)
          return
        end

        step = 1
        if step_part
          unless step_part.match?(/\A[1-9][0-9]*\z/)
            invalid(field, index, start, length)
            return
          end
          step = step_part.to_i
        end

        if range_part == '*'
          nodes << [ min, max, step ] unless step_part.nil? && min == 0
          return
        end

        left, right = range_part.split('-', 2)
        if right.nil? && range_part.include?('-')
          invalid(field, index, start, length)
          return
        end

        a = numeric_name(left, names, field, index, start, length)
        b = right && numeric_name(right, names, field, index, start, length)
        return if a.nil? || (right && b.nil?)
        return unless in_range?(a, min, max, field, index, start, length)
        return if b && !in_range?(b, min, max, field, index, start, length)
        if b && b < a
          invalid(field, index, start, length)
          return
        end

        nodes << [ a, b || (step_part ? max : a), step ]
      end

      def numeric_name(token, names, field, index, start, length)

        if names
          n = names.index(token.upcase)
          return n if n
        end

        unless token&.match?(/\A[0-9]+\z/)
          invalid(field, index, start, length)
          return nil
        end

        token.to_i
      end

      def in_range?(value, min, max, field, index, start, length)

        return true if value >= min && value <= max
        invalid(field, index, start, length)
        false
      end

      def invalid(field, index, start, length)

        issue(:unsupported_syntax, "unsupported #{FIELDS[index]} field #{field[:text].inspect}",
          field: FIELDS[index], position: start, length: length)
      end

      def unsupported(field, index, start, length, what)

        issue(:unsupported_feature, "the supported Quartz subset does not include #{what}",
          field: FIELDS[index], position: start, length: length)
      end

      def parse_dom(field)

        return { type: :question } if field[:text] == '?'
        return { type: :wild } if field[:text] == '*'

        if /[WCc]/i.match?(field[:text])
          unsupported(field, 3, field[:start], field[:text].length, "nearest-weekday 'W' and calendar 'C' day fields")
          return nil
        end

        if field[:text].upcase == 'L'
          return { type: :last, values: [ -1 ] }
        end

        if field[:text].upcase.start_with?('L')
          unsupported(field, 3, field[:start], field[:text].length, "last-day offsets such as #{field[:text].inspect}")
          return nil
        end

        nodes, _ = parse_generic(field, 3, 1, 31)
        return nil unless nodes
        { type: :restricted, values: expand(nodes), nodes: nodes }
      end

      def parse_month(field)

        nodes, kind = parse_generic(field, 4, 1, 12, MONTHS)
        return { wild: true, values: nil } if kind == :wild
        return nil unless nodes
        { wild: false, values: expand(nodes) }
      end

      def parse_dow(field)

        return { type: :question } if field[:text] == '?'
        return { type: :wild } if field[:text] == '*'

        if field[:text].upcase == 'L'
          unsupported(field, 5, field[:start], 1, "bare 'L' in the day-of-week field")
          return nil
        end

        entries = []
        scan_tokens(field) do |token, start, length|
          parse_dow_token(token, field, start, length, entries)
        end
        { type: :restricted, entries: entries }
      end

      def parse_dow_token(token, field, start, length, entries)

        if token.empty?
          invalid(field, 5, start, length)
          return
        end

        if /[WCc]/.match?(token)
          unsupported(field, 5, start, length, "'C' calendar offsets")
          return
        end

        if (m = /\A([1-7]|SUN|MON|TUE|WED|THU|FRI|SAT)L\z/i.match(token))
          q = quartz_wday(m[1])
          entries << { type: :last, wday: q, render: "#{fugit_wday(q)}#-1" }
          return
        end

        if (m = /\A([1-7]|SUN|MON|TUE|WED|THU|FRI|SAT)#([1-5])\z/i.match(token))
          q = quartz_wday(m[1])
          entries << { type: :nth, wday: q, nth: m[2].to_i, render: "#{fugit_wday(q)}##{m[2]}" }
          return
        end

        range_part, step_part = token.split('/', 2)
        step = step_part ? step_part.to_i : 1
        unless step_part.nil? || step_part.match?(/\A[1-9][0-9]*\z/)
          invalid(field, 5, start, length)
          return
        end

        left, right = range_part.split('-', 2)
        aq = quartz_wday(left)
        bq = right ? quartz_wday(right) : aq
        raw_wrap = left == '7' && right
        full_numeric = left == '1' && right == '7'
        full_named = aq == 1 && bq == 0 && left.match?(/\A[A-Z]{3}\z/i)
        full_range = full_numeric || full_named
        wrap = right && bq <= aq
        if aq.nil? || right && bq.nil? || raw_wrap ||
             (!full_range && wrap)
          invalid(field, 5, start, length)
          return
        end

        values =
          if full_range
            if full_numeric
              (1..7).step(step).collect { |v| v == 7 ? 0 : v - 1 }.sort
            else
              [ aq, *((aq + 1)..6).to_a, 0 ].each_slice(step).collect(&:first)
            end
          elsif aq == 0 && right.nil?
            [ 0 ]
          else
            (aq..bq).step(step).to_a
          end
        entries.concat(values.collect { |v| { type: :normal, wday: v, render: fugit_wday(v).to_s } })
      end

      def quartz_wday(token)

        n = WEEKDAYS.index(token&.upcase)
        return n if n
        return nil unless token&.match?(/\A[1-7]\z/)
        v = token.to_i
        v == 7 ? 0 : v - 1
      end

      def fugit_wday(quartz_value); quartz_value; end

      def parse_year(field)

        return if field.nil?
        return if field[:text] == '*'

        issue(:unsupported_year,
          "Fugit cron has no finite year field; only an omitted year or '*' is convertible",
          field: :year, position: field[:start], length: field[:text].length)
      end

      def validate_day_combination(fields)

        dom_q = @dom && @dom[:type] == :question
        dow_q = @dow && @dow[:type] == :question
        dom_r = @dom && (@dom[:type] == :restricted || @dom[:type] == :last)
        dow_r = @dow && @dow[:type] == :restricted

        return if dom_q ^ dow_q
        return if !dom_q && !dow_q && dom_r && dow_r

        issue(:unsupported_day_combination,
          "the supported Quartz subset requires '?' in exactly one day " +
          "field, or concrete values in both fields for AND semantics",
          field: :day_of_week, position: fields[5][:start],
          length: fields[5][:text].length)
      end

      def expand(nodes)

        nodes.flat_map { |a, b, step| (a..b).step(step).to_a }.uniq.sort
      end

      def render_target

        [
          render_numeric(@sec),
          render_numeric(@min),
          render_numeric(@hour),
          render_dom,
          render_month,
          render_dow
        ].join(' ')
      end

      def render_numeric(info); info.nil? ? '*' : info.join(','); end
      def render_month; @month[:wild] ? '*' : @month[:values].join(','); end

      def render_dom

        return '*' unless @dom[:type] == :restricted || @dom[:type] == :last
        @dom[:values].collect(&:to_s).join(',')
      end

      def render_dow

        return '*' unless @dow[:type] == :restricted
        s = @dow[:entries]
          .uniq { |e| [ e[:type], e[:wday], e[:nth], e[:render] ] }
          .sort_by { |e| [ e[:render].start_with?(?-) ? 1 : 0, e[:wday], e[:nth].to_i ] }
          .collect { |e| e[:render] }
          .join(',')
        both_day_fields_restricted? ? s + '&' : s
      end

      def both_day_fields_restricted?

        (@dom[:type] == :restricted || @dom[:type] == :last) &&
          @dow[:type] == :restricted
      end

      def verify_time_arrays!

        expected = [
          @sec,
          @min,
          @hour,
          @month[:wild] ? nil : @month[:values]
        ]
        actual = [
          @cron.seconds,
          @cron.minutes,
          @cron.hours,
          @cron.months
        ]

        return if expected == actual

        issue(:verification_failed,
          'converted second/minute/hour/month fields do not match the Quartz source',
          position: 0, length: [ @expression.length, 1 ].max)
      end

      def source_day?(date)

        return false unless @month[:wild] || @month[:values].include?(date.month)
        dom = source_dom?(date)
        dow = source_dow?(date)
        if both_day_fields_restricted?
          dom && dow
        elsif @dom[:type] == :question
          dow
        else
          dom
        end
      end

      def source_dom?(date)

        case @dom[:type]
        when :question, :wild then true
        when :last
          date.day == Date.new(date.year, date.month, -1).day
        else
          @dom[:values].include?(date.day)
        end
      end

      def source_dow?(date)

        case @dow[:type]
        when :question, :wild then true
        else
          @dow[:entries].any? do |e|
            next false unless e[:wday] == date.wday
            case e[:type]
            when :normal then true
            when :nth then (date.day - 1) / 7 + 1 == e[:nth]
            when :last then (Date.new(date.year, date.month, -1).day - date.day) / 7 + 1 == 1
            end
          end
        end
      end
    end
  end
end
