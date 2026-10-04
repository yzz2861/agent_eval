# frozen_string_literal: true

require 'date'

module Fugit

  # Converts cron expressions from a declared source dialect into
  # executable Fugit::Cron instances.
  #
  # The entry points are
  #
  #   Fugit.convert_cron(s, from: :unix)    # 5 fields
  #   Fugit.convert_cron(s, from: :quartz)  # 6 or 7 fields
  #
  # and their raising variant Fugit.do_convert_cron(s, from: ...).
  #
  # The source dialect MUST be declared, this conversion entry point does
  # not guess. Fugit.parse and Fugit.parse_cron are left untouched, they
  # keep interpreting strings the way they always did.
  #
  # == unix dialect
  #
  # Five fields "minute hour day-of-month month day-of-week". Supported:
  # numbers, three-letter month and weekday names, '*', lists ',',
  # ranges '-', steps '/'. When both day-of-month and day-of-week are
  # restricted, the classical unix "either matches" (OR) rule applies,
  # which is what Fugit::Cron already implements.
  #
  # == quartz dialect (supported subset)
  #
  # Six or seven fields "second minute hour day-of-month month
  # day-of-week [year]". Supported:
  #
  #   * seconds, minutes, hours, months: numbers (and JAN-DEC for
  #     months), '*', lists, ranges, steps ('*/15' and '0/15' included)
  #   * day-of-month: numbers, lists, ranges, steps, 'L' (last day of
  #     the month) and 'L-n' (nth-to-last day of the month), or '?'
  #   * day-of-week: 1-7 or SUN-SAT (1 and SUN both mean Sunday), lists,
  #     ranges, steps, 'L' alone (Saturday), 'xL' (last x-day of the
  #     month), 'x#n' (nth x-day of the month, n in 1..5), or '?'
  #   * year: only '*' (or absent); a bounded year cannot be expressed
  #     in a fugit cron and yields a structured error
  #   * '?' is accepted in the day-of-month and day-of-week fields only,
  #     where it means "no specific value"
  #
  # Not supported (each yields a structured error pointing at the
  # original position of the offending field):
  #
  #   * bounded years ('2025', '2020-2030', '2025,2027', '*/2', ...)
  #   * 'W', 'LW' and 'C' forms
  #   * expressions restricting BOTH day-of-month and day-of-week
  #     (Quartz itself requires '?' in one of the two fields)
  #   * wrap-around ranges ('FRI-MON', '5-1', ...)
  #
  # == verification
  #
  # Every convertible expression is checked before being returned: the
  # occurrences of the converted Fugit::Cron are compared one by one
  # against an independent implementation of the source dialect
  # semantics over a finite time window (2024-01-01 to 2029-01-01 UTC,
  # up to 256 occurrences, overridable via the :window and :count
  # options). A divergence yields a structured error, never a silently
  # wrong schedule.
  #
  module Convert

    DIALECTS = %i[ unix quartz ].freeze

    MONTHS = %w[ - jan feb mar apr may jun jul aug sep oct nov dec ].freeze
    WEEKDS = %w[ sun mon tue wed thu fri sat ].freeze

    VERIFICATION_WINDOW = [
      '2024-01-01 00:00:00 UTC', '2029-01-01 00:00:00 UTC' ].freeze
    VERIFICATION_COUNT = 256

    UNIX_FIELDS = [
      { name: :minutes, min: 0, max: 59 },
      { name: :hours, min: 0, max: 23 },
      { name: :day_of_month, min: 1, max: 31 },
      { name: :months, min: 1, max: 12, names: MONTHS },
      { name: :day_of_week, min: 0, max: 7, names: WEEKDS,
        remap: lambda { |v| v == 7 ? 0 : v } } ].freeze

    QUARTZ_SIMPLE_FIELDS = [
      { name: :seconds, min: 0, max: 59 },
      { name: :minutes, min: 0, max: 59 },
      { name: :hours, min: 0, max: 23 } ].freeze
    QUARTZ_DOM_FIELD =
      { name: :day_of_month, min: 1, max: 31 }.freeze
    QUARTZ_MON_FIELD =
      { name: :months, min: 1, max: 12, names: MONTHS }.freeze
    QUARTZ_DOW_FIELD =
      { name: :day_of_week, min: 1, max: 7, names: WEEKDS, names_base: 1,
        remap: lambda { |v| v - 1 } }.freeze

    # A structured conversion error. Returned (not raised) by
    # Fugit.convert_cron, raised by Fugit.do_convert_cron.
    #
    # Each issue is a Hash:
    #   { field: :day_of_week, # nil for whole-expression issues
    #     index: 5,            # 0-based field index, nil if n/a
    #     offset: 12,          # character offset in the original string
    #     value: 'MON',        # the original field text
    #     reason: '...' }
    #
    class Error < StandardError

      attr_reader :input, :dialect, :issues

      def initialize(input, dialect, issues)

        @input = input
        @dialect = dialect
        @issues = issues

        super(
          "cannot convert #{dialect} cron #{input.inspect}: " +
          issues
            .collect { |i|
              if i[:index]
                "field #{i[:index]} (#{i[:field]}) #{i[:value].inspect}: " +
                  i[:reason]
              else
                i[:reason]
              end }
            .join('; '))
      end

      def to_h

        { input: input, dialect: dialect, issues: issues }
      end
    end

    # An independent, brute-force implementation of the source dialect
    # semantics, used to verify converted expressions occurrence by
    # occurrence over a finite time window.
    #
    class Reference

      # sec, min, hou: sorted arrays of integers (fully materialized)
      # mon: nil (any) or sorted array of 1..12
      # dom: nil (any) or array of integers, negatives count back from
      #      the last day of the month (-1 == last day)
      # dow: nil (any) or array of [ :each, w ], [ :nth, w, n ] or
      #      [ :last, w ] with w in 0..6 (0 is Sunday)
      # day_mode: :and (both must match) or :or (unix rule when both
      #           day-of-month and day-of-week are restricted)
      #
      def initialize(sec, min, hou, mon, dom, dow, day_mode)

        @sec = sec
        @min = min
        @hou = hou
        @mon = mon
        @dom = dom
        @dow = dow
        @day_mode = day_mode
      end

      # Returns the occurrence times (UTC) strictly after +from+ and
      # strictly before +to+, at most +limit+ of them.
      #
      def occurrences(from, to, limit)

        r = []

        date = from.to_date
        last = to.to_date

        while date <= last

          if month_match?(date) && day_match?(date)
            each_time_of_day(date, from, to) do |t|
              r << t
              return r if r.length >= limit
            end
          end

          date += 1
        end

        r
      end

      protected

      def each_time_of_day(date, from, to)

        @hou.each do |h|
          @min.each do |mi|
            @sec.each do |se|
              t = Time.utc(date.year, date.month, date.day, h, mi, se)
              next if t <= from
              return if t >= to
              yield t
            end
          end
        end
      end

      def month_match?(date)

        ( ! @mon) || @mon.include?(date.month)
      end

      def day_match?(date)

        if @day_mode == :or
          dom_match?(date) || dow_match?(date)
        else
          dom_match?(date) && dow_match?(date)
        end
      end

      def dom_match?(date)

        return true unless @dom

        dim = ::Date.new(date.year, date.month, -1).day

        @dom.any? { |d| (d < 1 ? dim + 1 + d : d) == date.day }
      end

      def dow_match?(date)

        return true unless @dow

        dim = ::Date.new(date.year, date.month, -1).day

        @dow.any? do |kind, w, n|
          next false unless date.wday == w
          case kind
          when :each then true
          when :nth then (date.day - 1) / 7 + 1 == n
          when :last then date.day + 7 > dim
          end
        end
      end
    end

    class << self

      # Returns a Fugit::Cron on success, a Fugit::Convert::Error
      # instance (not raised) on failure.
      #
      def convert(s, from:, **opts)

        dialect = from.to_sym if from.respond_to?(:to_sym)

        unless DIALECTS.include?(dialect)
          fail ArgumentError.new(
            "unknown cron dialect #{from.inspect}, " +
            "declare one of #{DIALECTS.collect(&:inspect).join(', ')}")
        end

        unless s.is_a?(String)
          return Error.new(s, dialect, [
            issue(nil, nil, nil, nil, "not a String") ])
        end

        fields = split_fields(s)
        issues = []

        r =
          if dialect == :unix
            convert_unix(fields, issues)
          else
            convert_quartz(fields, issues)
          end

        return Error.new(s, dialect, issues) unless r

        cron_s, ref = r

        cron =
          begin
            Fugit::Cron.do_parse(cron_s)
          rescue => err
            return Error.new(s, dialect, [
              issue(nil, nil, nil, nil,
                "converted expression #{cron_s.inspect} " +
                "is not a valid fugit cron: #{err.message}") ])
          end

        verr = verify(ref, cron, opts)

        return Error.new(s, dialect, [ verr ]) if verr

        cron
      end

      protected

      def issue(field, index, offset, value, reason)

        { field: field, index: index, offset: offset,
          value: value, reason: reason }
      end

      def split_fields(s)

        r = []
        s.scan(/\S+/) { r << [ $~[0], $~.begin(0) ] }
        r
      end

      def convert_unix(fields, issues)

        if fields.length != 5
          msg =
            "expected 5 fields (minute hour day-of-month month " +
            "day-of-week) for the unix dialect, got #{fields.length}"
          msg +=
            "; a seconds (and maybe year) field suggests the quartz " +
            "dialect (from: :quartz)" if fields.length.between?(6, 7)
          issues << issue(nil, nil, nil, nil, msg)
          return nil
        end

        vals = []
        toks = []

        fields.each_with_index do |(token, off), i|
          r = parse_simple_field(token, i, off, UNIX_FIELDS[i], issues)
          return nil unless r
          vals << r[0]
          toks << r[1]
        end

        min, hou, dom, mon, dow = vals

        ref = Reference.new(
          [ 0 ],
          min || (0..59).to_a,
          hou || (0..23).to_a,
          mon,
          dom,
          dow && dow.collect { |w| [ :each, w ] },
          (dom && dow) ? :or : :and)

        [ toks.join(' '), ref ]
      end

      def convert_quartz(fields, issues)

        unless fields.length.between?(6, 7)
          issues << issue(nil, nil, nil, nil,
            "expected 6 or 7 fields (second minute hour day-of-month " +
            "month day-of-week [year]) for the quartz dialect, " +
            "got #{fields.length}")
          return nil
        end

        if fields.length == 7
          ytok, yoff = fields[6]
          unless ytok == '*'
            issues << issue(:year, 6, yoff, ytok,
              "year #{ytok.inspect} cannot be expressed in a fugit " +
              "cron expression, only '*' is supported; " +
              "filter by year outside of the schedule")
          end
        end

        vals = []
        toks = []

        QUARTZ_SIMPLE_FIELDS.each_with_index do |spec, i|
          token, off = fields[i]
          r = parse_simple_field(token, i, off, spec, issues)
          return nil unless r
          vals << r[0]
          toks << r[1]
        end

        dom_token, dom_off = fields[3]
        dom = parse_quartz_dom(dom_token, 3, dom_off, issues)
        return nil unless dom

        mon_token, mon_off = fields[4]
        mon = parse_simple_field(mon_token, 4, mon_off, QUARTZ_MON_FIELD, issues)
        return nil unless mon

        dow_token, dow_off = fields[5]
        dow = parse_quartz_dow(dow_token, 5, dow_off, issues)
        return nil unless dow

        return nil if issues.any? # bounded year collected above

        dom_vals, dom_tok = dom
        mon_vals, mon_tok = mon
        dow_restricted, dow_tok, dow_specs = dow

        if dom_vals && dow_restricted
          issues << issue(:day_of_month, 3, dom_off, dom_token,
            "day-of-month and day-of-week are both restricted; " +
            "quartz requires '?' in one of the two fields and fugit " +
            "cannot express their combination")
          issues << issue(:day_of_week, 5, dow_off, dow_token,
            "restricted together with day-of-month (see field 3)")
          return nil
        end

        sec, min, hou = vals

        ref = Reference.new(
          sec || (0..59).to_a,
          min || (0..59).to_a,
          hou || (0..23).to_a,
          mon_vals,
          dom_vals,
          dow_specs,
          :and)

        [ (toks + [ dom_tok, mon_tok, dow_tok ]).join(' '), ref ]
      end

      def parse_quartz_dom(token, idx, off, issues)

        return [ nil, '*' ] if token == '*' || token == '?'

        m = token.match(/\AL(?:-(\d{1,2}))?\z/i)

        if m
          n = m[1] && m[1].to_i
          if n.nil?
            return [ [ -1 ], 'L' ]
          elsif n.between?(1, 30)
            return [ [ -n ], "-#{n}" ]
          else
            issues << issue(:day_of_month, idx, off, token,
              "quartz L-n offset #{n} is out of range 1..30")
            return nil
          end
        end

        if token.match(/[wc]/i)
          issues << issue(:day_of_month, idx, off, token,
            "quartz 'W', 'LW' and 'C' forms have no fugit equivalent")
          return nil
        end

        parse_simple_field(token, idx, off, QUARTZ_DOM_FIELD, issues)
      end

      # Returns [ restricted, fugit_token, reference_specs ] or nil
      # (after appending to +issues+).
      #
      def parse_quartz_dow(token, idx, off, issues)

        return [ false, '*', nil ] if token == '*' || token == '?'

        specs = []
        fparts = []
        simple = []

        token.split(',').each do |part|

          case part
          when /\AL\z/i
            specs << [ :each, 6 ] # L alone is Saturday
            fparts << '6'
          when /\A([a-z]{3}|\d)L\z/i
            w = quartz_dow_bound($1)
            unless w
              issues << issue(:day_of_week, idx, off, token,
                "invalid weekday in #{part.inspect}")
              return nil
            end
            specs << [ :last, w ]
            fparts << "#{w}#L"
          when /\A([a-z]{3}|\d)#(\d{1,2})\z/i
            w = quartz_dow_bound($1)
            n = $2.to_i
            if w.nil? || ( ! n.between?(1, 5))
              issues << issue(:day_of_week, idx, off, token,
                "invalid nth-weekday #{part.inspect} (n must be in 1..5)")
              return nil
            end
            specs << [ :nth, w, n ]
            fparts << "#{w}##{n}"
          when /\A(?:\d{1,2}W|LW|W|\d{1,2}C|C)\z/i
            issues << issue(:day_of_week, idx, off, token,
              "quartz 'W' and 'C' forms have no fugit equivalent")
            return nil
          else
            simple << part
          end
        end

        unless simple.empty?
          r = parse_simple_field(
            simple.join(','), idx, off, QUARTZ_DOW_FIELD, issues)
          return nil unless r
          vals, ftok = r
          if vals
            specs.concat(vals.collect { |w| [ :each, w ] })
            fparts << ftok
          end
        end

        return [ false, '*', nil ] if specs.empty?

        [ true, fparts.join(','), specs ]
      end

      # Quartz day-of-week bound to fugit 0..6 (0 is Sunday);
      # returns nil when invalid.
      #
      def quartz_dow_bound(s)

        if s =~ /\A\d+\z/
          v = s.to_i
          v.between?(1, 7) ? v - 1 : nil
        else
          WEEKDS.index(s.downcase)
        end
      end

      # Parses a "simple" field (numbers, names, '*', lists, ranges,
      # steps) into [ values, fugit_token ], where values is nil when
      # the field covers its whole range. Returns nil after appending
      # to +issues+ when the field cannot be parsed.
      #
      def parse_simple_field(token, idx, off, spec, issues)

        values = []
        fparts = []

        token.split(',').each do |part|

          m = part.match(%r{\A([^/]+)(?:/(\d+))?\z})

          unless m
            issues << issue(spec[:name], idx, off, token,
              "cannot parse #{part.inspect} in the #{spec[:name]} field")
            return nil
          end

          core = m[1]
          step = m[2] && m[2].to_i

          if step && step < 1
            issues << issue(spec[:name], idx, off, token,
              "invalid step in #{part.inspect}")
            return nil
          end

          sta = nil
          edn = nil
          fcore = nil

          if core == '*'
            fcore = '*'
          else
            cm = core.match(/\A([a-z0-9]+)(?:-([a-z0-9]+))?\z/i)
            a = cm && bound_value(cm[1], spec)
            z = cm && cm[2] ? bound_value(cm[2], spec) : nil

            if a.nil? || (cm && cm[2] && z.nil?)
              issues << issue(spec[:name], idx, off, token,
                "invalid value #{core.inspect} " +
                "in the #{spec[:name]} field")
              return nil
            end

            lo = spec[:min]
            hi = spec[:max]

            unless a.between?(lo, hi) && (z.nil? || z.between?(lo, hi))
              issues << issue(spec[:name], idx, off, token,
                "value #{core.inspect} out of range #{lo}..#{hi} " +
                "in the #{spec[:name]} field")
              return nil
            end

            if z && z < a
              issues << issue(spec[:name], idx, off, token,
                "range #{core.inspect} wraps around, not supported")
              return nil
            end

            sta = a
            edn = z
            fcore = remap_bound(cm[1], spec)
            fcore += "-#{remap_bound(cm[2], spec)}" if z
          end

          fcore += "/#{step}" if step
          fparts << fcore

          sta = spec[:min] if sta.nil?
          edn = spec[:max] if edn.nil? && (step || core == '*')

          vs = edn ? (sta..edn).step(step || 1).to_a : [ sta ]
          values.concat(vs.collect { |v| remap(v, spec) })
        end

        values.uniq!
        values.sort!

        full = (spec[:min]..spec[:max]).to_a.collect { |v| remap(v, spec) }
        full.uniq!
        full.sort!

        values == full ? [ nil, '*' ] : [ values, fparts.join(',') ]
      end

      def bound_value(s, spec)

        if s =~ /\A\d+\z/
          s.to_i
        elsif spec[:names]
          i = spec[:names].index(s.downcase)
          i && i + (spec[:names_base] || 0)
        else
          nil
        end
      end

      def remap(v, spec)

        spec[:remap] ? spec[:remap].call(v) : v
      end

      def remap_bound(s, spec)

        return s unless s =~ /\A\d+\z/
        remap(s.to_i, spec).to_s
      end

      # Compares the converted Fugit::Cron against the reference
      # implementation of the source semantics, occurrence by
      # occurrence, over a finite time window. Returns nil when they
      # agree, an issue Hash when they diverge.
      #
      def verify(ref, cron, opts)

        win = opts[:window] || VERIFICATION_WINDOW
        limit = opts[:count] || VERIFICATION_COUNT

        from = win[0].is_a?(String) ? Time.parse(win[0]).utc : win[0].utc
        to = win[1].is_a?(String) ? Time.parse(win[1]).utc : win[1].utc
        to_i = to.to_i

        expected = ref.occurrences(from, to, limit).collect(&:to_i)

        zcron = # pin the verification in UTC, a zone-less fugit cron
          Fugit::Cron.do_parse(cron.to_cron_s + ' UTC')
            # would fire in the local timezone

        got =
          begin
            zcron.next(from).lazy
              .take_while { |t| t.to_i < to_i }
              .first(limit)
              .collect(&:to_i)
          rescue => err
            return issue(nil, nil, nil, nil,
              "verification of the converted expression failed: " +
              err.message)
          end

        return nil if got == expected

        i = 0
        i += 1 while expected[i] && got[i] && expected[i] == got[i]

        issue(nil, nil, nil, nil,
          "converted expression #{cron.to_cron_s.inspect} diverges " +
          "from the source semantics at occurrence #{i}: expected " +
          "#{expected[i] ? Time.at(expected[i]).utc : 'none'}, got " +
          "#{got[i] ? Time.at(got[i]).utc : 'none'}")
      end
    end
  end

  class << self

    # Converts a cron string from a declared dialect (:unix or :quartz)
    # into an executable Fugit::Cron.
    #
    # Returns the Fugit::Cron on success, or a Fugit::Convert::Error
    # instance (not raised) describing the parts of the expression that
    # cannot be expressed.
    #
    def convert_cron(s, from:, **opts)

      Convert.convert(s, from: from, **opts)
    end

    # Like .convert_cron but raises the Fugit::Convert::Error instead
    # of returning it.
    #
    def do_convert_cron(s, from:, **opts)

      r = convert_cron(s, from: from, **opts)
      r.is_a?(Convert::Error) ? raise(r) : r
    end
  end
end
