# frozen_string_literal: true

module Fugit

  class Cron

    SPECIALS = {
      '@reboot' => :reboot,
      '@yearly' => '0 0 1 1 *',
      '@annually' => '0 0 1 1 *',
      '@monthly' => '0 0 1 * *',
      '@weekly' => '0 0 * * 0',
      '@daily' => '0 0 * * *',
      '@midnight' => '0 0 * * *',
      '@noon' => '0 12 * * *',
      '@hourly' => '0 * * * *' }.freeze
    MAXDAYS = [
      nil, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 ].freeze

    # Policies for local times that occur twice (DST "fall back")
    #
    FOLD_POLICIES = [ :earlier, :later, :twice ].freeze
      #
      # :earlier only triggers on the first occurrence (current behaviour)
      # :later only triggers on the second occurrence
      # :twice triggers on both occurrences

    # Policies for local times that never occur (DST "spring forward")
    #
    GAP_POLICIES = [ :skip, :shift ].freeze
      #
      # :skip does not trigger at all (current behaviour)
      # :shift triggers after shifting the local time by the gap size

    # How far (in seconds, wall-clock) to keep collecting candidates
    # after an ambiguous (fold) or shifted (gap) candidate, since their
    # UTC instants may interleave with the ones of neighbour candidates
    #
    DST_LOOKAHEAD_S = 2 * DAY_S

    attr_reader(
      :original, :zone, :fold, :gap)
    attr_reader(
      :seconds, :minutes, :hours, :monthdays, :months, :weekdays, :timezone)

    class << self

      def new(original, opts={})

        parse(original, opts)
      end

      def parse(s, opts={})

        return s if s.is_a?(self)
        return nil unless s.is_a?(String)

        s0 = s
        s = s.strip

        if s.length > ::Fugit::MAX_INPUT_LENGTH

          fail ArgumentError.new(
            'input too long for a cron string, ' +
            "#{s.length} > #{MAX_INPUT_LENGTH}"
          ) if opts[:do_parse]

          return nil
        end

        s =
          if s[0, 1] == '@'
            ss = s.split(/\s+/, 2)
            [ SPECIALS[ss[0]] || ss, *ss[1..-1] ].join(' ')
          else
            s
          end

#p s; Raabro.pp(Parser.parse(s, debug: 3), colors: true)
        h = Parser.parse(s)

        self.allocate.send(:init, s0, h, opts)
      end

      def do_parse(s, opts={})

        parse(s, opts.merge(do_parse: true)) ||
        fail(ArgumentError.new("invalid cron string #{trunc(s)}"))
      end

      protected

      def trunc(s)

        if s.is_a?(String)
          r = s.length > 28 ? s[0, 28] + "... len #{s.length}" : s
          r.inspect
        else
          r = s.inspect
          r.length > 35 ? s[0, 35] + '...' : r
        end
      end
    end

    def to_cron_s

      @cron_s ||= [
        @seconds == [ 0 ] ? nil : (@seconds || [ '*' ]).join(','),
        (@minutes || [ '*' ]).join(','),
        (@hours || [ '*' ]).join(','),
        (@monthdays || [ '*' ]).join(','),
        (@months || [ '*' ]).join(','),
        weekdays_to_cron_s,
        @timezone ? @timezone.name : nil
          ].compact.join(' ')
    end

    class TimeCursor

      def initialize(cron, t)
        @cron = cron
        @t = t.is_a?(TimeCursor) ? t.time : t
        @t.seconds = @t.seconds.to_i
      end

      def time; @t; end
      def to_t; @t; end
        #
      def to_i; @t.to_i; end

      %w[ year month day wday hour min sec wday_in_month rweek rday ]
        .collect(&:to_sym).each { |k| define_method(k) { @t.send(k) } }

      def inc(i); @t = @t + i; self; end
      def dec(i); inc(-i); end

      def inc_month

        y = @t.year
        m = @t.month + 1
        if m == 13; m = 1; y += 1; end

        @t = ::EtOrbi.make(y, m, @t.zone)

        self
      end

      def inc_day

        inc((24 - @t.hour) * 3600 - @t.min * 60 - @t.sec)

        return if @t.hour == 0

        if @t.hour < 12
          begin
            @t = ::EtOrbi.make(@t.year, @t.month, @t.day, @t.zone)
          rescue ::TZInfo::PeriodNotFound
            inc((24 - @t.hour) * 3600)
          end
        else
          inc((24 - @t.hour) * 3600)
        end
      end

      def inc_hour
        inc((60 - @t.min) * 60 - @t.sec)
      end
      def inc_min
        inc(60 - @t.sec)
      end

      def inc_sec
        if sec = @cron.seconds.find { |s| s > @t.sec }
          inc(sec - @t.sec)
        else
          inc(60 - @t.sec + @cron.seconds.first)
        end
      end

      def dec_month
        dec((@t.day - 1) * DAY_S + @t.hour * 3600 + @t.min * 60 + @t.sec + 1)
      end

      def dec_day
        dec(@t.hour * 3600 + @t.min * 60 + @t.sec + 1)
      end
      def dec_hour
        dec(@t.min * 60 + @t.sec + 1)
      end
      def dec_min
        dec(@t.sec + 1)
      end

      def dec_sec
        target =
          @cron.seconds.reverse.find { |s| s < @t.sec } ||
          @cron.seconds.last
        inc(target - @t.sec - (@t.sec > target ? 0 : 60))
      end
    end

    def month_match?(nt); ( ! @months) || @months.include?(nt.month); end
    def hour_match?(nt); ( ! @hours) || @hours.include?(nt.hour); end
    def min_match?(nt); ( ! @minutes) || @minutes.include?(nt.min); end
    def sec_match?(nt); ( ! @seconds) || @seconds.include?(nt.sec); end

    def weekday_hash_match?(nt, hsh)

      return false unless hsh.is_a?(Integer)

      phsh, nhsh = nt.wday_in_month
        #
        # positive wday, from the beginning of the month
        # negative wday, from the end of the month, -1 == last

      (hsh == phsh) || (hsh == nhsh)
    end

    def weekday_modulo_match?(nt, mod)

      mod.is_a?(Array) &&
      ((nt.rweek % mod[0]) == (mod[1] % mod[0]))
    end

    def weekday_match?(nt)

      @weekdays.nil? ||
      @weekdays.find { |wd, hom|
        (nt.wday == wd) &&
        (hom.nil? ||
         weekday_modulo_match?(nt, hom) ||
         weekday_hash_match?(nt, hom)) }
    end

    def monthday_match?(nt)

      return true if @monthdays.nil?

      last = (TimeCursor.new(self, nt).inc_month.time - 24 * 3600).day + 1

      @monthdays
        .collect { |d| d < 1 ? last + d : d }
        .include?(nt.day)
    end

    def day_match?(nt)

      if @weekdays && @monthdays

        return weekday_match?(nt) && monthday_match?(nt) \
          if @day_and
            #
            # extension for fugit, gh-78

        return weekday_match?(nt) || monthday_match?(nt)
          #
          # From `man 5 crontab`
          #
          # Note: The day of a command's execution can be specified
          # by two fields -- day of month, and day of week.
          # If both fields are restricted (ie, are not *), the command will be
          # run when either field matches the current time.
          # For example, ``30 4 1,15 * 5'' would cause a command to be run
          # at 4:30 am on the 1st and 15th of each month, plus every Friday.
          #
          # as seen in gh-5 and gh-35
      end


      return false unless weekday_match?(nt)
      return false unless monthday_match?(nt)

      true
    end

    def match?(t)

      t = Fugit.do_parse_at(t).translate(@timezone)

      month_match?(t) && day_match?(t) &&
      hour_match?(t) && min_match?(t) && sec_match?(t)
    end

    MAX_ITERATION_COUNT = 2048
      #
      # See gh-15 and tst/iteration_count.rb
      #
      # Initially set to 1024 after seeing the worst case for #next_time
      # at 167 iterations, I placed it at 2048 after experimenting with
      # gh-18 and noticing some > 1024 for some experiments. 2048 should
      # be ok.

    DST_MAX_ITERATION_COUNT = 64 * MAX_ITERATION_COUNT
      #
      # For the fold/gap policy aware #next_time and #previous_time,
      # a per-second cron expression scanning a DST fold or gap
      # iterates once per second of the transition window

    def next_time(from=::EtOrbi::EoTime.now)

      return next_time_with_dst_policies(from) if dst_policies?

      from = ::EtOrbi.make_time(from)
      sfrom = from.strftime('%F|%T')
      ifrom = from.to_i

      i = 0
      t = TimeCursor.new(self, from.translate(@timezone))
        #
        # the translation occurs in the timezone of
        # this Fugit::Cron instance

      zfrom = t.time.strftime('%z|%Z')

      loop do

        fail RuntimeError.new(
          "too many loops for #{@original.inspect} #next_time, breaking, " +
          "cron expression most likely invalid (Feb 30th like?), " +
          "please fill an issue at https://git.io/fjJC9"
        ) if (i += 1) > MAX_ITERATION_COUNT

#tt = t.time;
#puts "  #{tt.strftime('%F %T %:z %A')} #{tt.rweek} #{tt.rweek % 2}"
        (ifrom == t.to_i) && (t.inc(1); next)
        month_match?(t) || (t.inc_month; next)
        day_match?(t) || (t.inc_day; next)
        hour_match?(t) || (t.inc_hour; next)
        min_match?(t) || (t.inc_min; next)
        sec_match?(t) || (t.inc_sec; next)

        tt = t.time
        st = tt.strftime('%F|%T')
        zt = tt.strftime('%z|%Z')
          #
        if st == sfrom && zt != zfrom
          from, sfrom, zfrom, ifrom = tt, st, zt, t.to_i
          next
        end
          #
          # when transitioning out of DST, this prevents #next_time from
          # yielding the same literal time twice in a row, see gh-6

        break
      end

      t.time.translate(from.zone)
        #
        # the answer time is in the same timezone as the `from`
        # starting point
    end

    def previous_time(from=::EtOrbi::EoTime.now)

      return previous_time_with_dst_policies(from) if dst_policies?

      from = ::EtOrbi.make_time(from)

      i = 0
      t = TimeCursor.new(self, (from - 1).translate(@timezone))

      loop do

        fail RuntimeError.new(
          "too many loops for #{@original.inspect} #previous_time, breaking, " +
          "cron expression most likely invalid (Feb 30th like?), " +
          "please fill an issue at https://git.io/fjJCQ"
        ) if (i += 1) > MAX_ITERATION_COUNT

#tt = t.time;
#puts "  #{tt.strftime('%F %T %:z %A')} #{tt.rweek} #{tt.rweek % 4}"
        month_match?(t) || (t.dec_month; next)
        day_match?(t) || (t.dec_day; next)
        hour_match?(t) || (t.dec_hour; next)
        min_match?(t) || (t.dec_min; next)
        sec_match?(t) || (t.dec_sec; next)
        break
      end

      t.time.translate(from.zone)
    end

    # Returns true when this cron instance was given explicit
    # DST fold/gap policies
    #
    def dst_policies?

      @dst_policies
    end

    # A copy of this cron instance, in the UTC timezone, used to
    # enumerate wall-clock (local time) candidates, which are then
    # resolved to UTC instants according to the fold/gap policies
    #
    def wall_cron

      @wall_cron ||=
        begin
          s = to_cron_s
          s = s.sub(/ +#{Regexp.escape(@timezone.name)}\z/, '') if @timezone
          self.class.do_parse("#{s} UTC")
        end
    end

    def next_time_with_dst_policies(from)

      from = ::EtOrbi.make_time(from)
      zone = @timezone || from.zone
      ifrom = from.to_i

      w = ::EtOrbi::EoTime.new(
        ifrom + from.translate(zone).utc_offset - 1, 'UTC')
      w = ::EtOrbi::EoTime.new(
        fold_rewind_wall(zone, ifrom, w.to_i), 'UTC')

      i = 0
      min = nil
      horizon = nil

      loop do

        fail RuntimeError.new(
          "too many loops for #{@original.inspect} #next_time, breaking, " +
          "cron expression most likely invalid (Feb 30th like?) or " +
          "only matching non-existent local times, " +
          "please fill an issue at https://git.io/fjJC9"
        ) if (i += 1) > DST_MAX_ITERATION_COUNT

        w = wall_cron.next_time(w)

        instants, complex = resolve_wall_time(zone, w)

        if complex
          h = instants.max
          horizon = h if horizon.nil? || h > horizon
        end

        t = instants.select { |ts| ts > ifrom }.min
        min = t if t && (min.nil? || t < min)

        # a trivial (unambiguous, unshifted) candidate whose instant
        # is past the horizon cannot be beaten by later candidates
        #
        return ::EtOrbi::EoTime.new(min, from.zone) \
          if min && ! complex &&
          (horizon.nil? || (instants.first && instants.first >= horizon))
      end
    end

    def previous_time_with_dst_policies(from)

      from = ::EtOrbi.make_time(from)
      zone = @timezone || from.zone
      ifrom = from.to_i

      w = ::EtOrbi::EoTime.new(
        ifrom + from.translate(zone).utc_offset + 1, 'UTC')
      w = ::EtOrbi::EoTime.new(
        fold_forward_wall(zone, ifrom, w.to_i), 'UTC')

      i = 0
      max = nil
      horizon = nil

      loop do

        fail RuntimeError.new(
          "too many loops for #{@original.inspect} #previous_time, breaking, " +
          "cron expression most likely invalid (Feb 30th like?) or " +
          "only matching non-existent local times, " +
          "please fill an issue at https://git.io/fjJCQ"
        ) if (i += 1) > DST_MAX_ITERATION_COUNT

        w = wall_cron.previous_time(w)

        instants, complex = resolve_wall_time(zone, w)

        if complex
          h = instants.min
          horizon = h if horizon.nil? || h < horizon
        else
          complex = shift_conflict?(zone, w.to_i, max)
        end

        t = instants.select { |ts| ts < ifrom }.max
        max = t if t && (max.nil? || t > max)

        return ::EtOrbi::EoTime.new(max, from.zone) \
          if max && ! complex &&
          (horizon.nil? || (instants.last && instants.last <= horizon))
      end
    end

    # Returns true when a DST gap transition is still ahead of the
    # backward wall-clock walk and its gap-shifted occurrences may
    # beat the current maximum (only relevant with gap: :shift)
    #
    def shift_conflict?(zone, w, max)

      return false unless @gap == :shift && max

      zone
        .transitions_up_to(
          ::Time.at(w + DST_LOOKAHEAD_S).utc,
          ::Time.at(w - DST_LOOKAHEAD_S).utc)
        .any? { |tr|
          pre = tr.previous_offset.utc_total_offset
          post = tr.offset.utc_total_offset
          gap = post - pre
          gap > 0 &&
          w > tr.timestamp_value + post &&
          tr.timestamp_value + gap > max }
    end

    # When `from` sits within (or just ahead of) a DST fold, wall-clock
    # candidates located before the wall time of `from` may still yield
    # second pass UTC instants after `from`; rewinds the wall starting
    # point past the beginning of the fold
    #
    def fold_rewind_wall(zone, ifrom, wfrom)

      each_fold_transition(zone, ifrom) { |ts, pre, post|
        wfrom = ts + post - 1 \
          if ts + pre - post > ifrom && ts + post - 1 < wfrom }

      wfrom
    end

    # Symmetric of #fold_rewind_wall for #previous_time; extends the
    # wall starting point past the end of the fold, so that first pass
    # UTC instants before `from` are not missed
    #
    def fold_forward_wall(zone, ifrom, wfrom)

      each_fold_transition(zone, ifrom) { |ts, pre, post|
        wfrom = ts + pre + 1 \
          if ts < ifrom + pre - post && ts + pre + 1 > wfrom }

      wfrom
    end

    # Yields [ timestamp, offset_before, offset_after ] for each DST
    # fold (clock turned back) transition around the given UTC instant
    #
    def each_fold_transition(zone, ifrom)

      zone
        .transitions_up_to(
          ::Time.at(ifrom + DST_LOOKAHEAD_S).utc,
          ::Time.at(ifrom - DST_LOOKAHEAD_S).utc)
        .each { |tr|
          pre = tr.previous_offset.utc_total_offset
          post = tr.offset.utc_total_offset
          yield(tr.timestamp_value, pre, post) if pre > post }

      zone
    end

    # Resolves a wall-clock time (an EoTime in UTC standing for local
    # time fields) in the given timezone to a list of UTC epoch seconds,
    # according to this cron instance's fold and gap policies.
    # The second element of the returned pair is true when the
    # resolution was ambiguous (fold) or shifted (gap), in which case
    # neighbour candidates may yield interleaving UTC instants
    #
    def resolve_wall_time(zone, w)

      local = ::Time.utc(w.year, w.month, w.day, w.hour, w.min, w.sec)

      periods = zone.periods_for_local(local)

      return resolve_gap_wall_time(zone, local) if periods.empty?

      utcs = periods
        .collect { |p| local.to_i - p.utc_total_offset }
        .sort

      case @fold
      when :later then [ [ utcs.last ], false ]
      when :twice then [ utcs, utcs.length > 1 ]
      else [ [ utcs.first ], false ]
      end
    end

    # The local time does not exist (DST gap); either skip it or
    # shift it by the gap size (which is equivalent to reading it
    # with the UTC offset in effect before the gap)
    #
    def resolve_gap_wall_time(zone, local)

      return [ [], false ] if @gap == :skip

      li = local.to_i

      tr = zone
        .transitions_up_to(
          ::Time.at(li + 2 * DAY_S).utc, ::Time.at(li - 2 * DAY_S).utc)
        .find { |t|
          t.timestamp_value + t.previous_offset.utc_total_offset <= li &&
          li < t.timestamp_value + t.offset.utc_total_offset }

      return [ [], false ] unless tr

      [ [ li - tr.previous_offset.utc_total_offset ], true ]
    end

    # Used by Fugit::Cron#next and Fugit::Cron#prev
    #
    class CronIterator
      include ::Enumerable

      attr_reader :cron, :start, :current, :direction

      def initialize(cron, direction, start)

        @cron = cron
        @start = start
        @current = start.dup
        @direction = direction
      end

      def each

        loop do

          yield(@current = @cron.send(@direction, @current))
        end
      end
    end

    # Returns an ::Enumerable instance that yields each "next time" in
    # succession
    #
    def next(from=::EtOrbi::EoTime.now)

      CronIterator.new(self, :next_time, from)
    end

    # Returns an ::Enumerable instance that yields each "previous time" in
    # succession
    #
    def prev(from=::EtOrbi::EoTime.now)

      CronIterator.new(self, :previous_time, from)
    end

    # Returns an array of EtOrbi::EoTime instances that correspond to
    # the occurrences of the cron within the given time range
    #
    def within(time_range, time_end=nil)

      sta, ned =
        time_range.is_a?(::Range) ? [ time_range.begin, time_range.end ] :
        [ ::EtOrbi.make_time(time_range), ::EtOrbi.make_time(time_end) ]

      CronIterator
        .new(self, :next_time, sta)
        .take_while { |eot| eot.to_t < ned }
    end

    # Mostly used as a #next_time sanity check.
    # Avoid for "business" use, it's slow.
    #
    # 2017 is a non leap year (though it is preceded by
    # a leap second on 2016-12-31)
    #
    # Nota bene: cron with seconds are not supported.
    #
    def brute_frequency(year=2017)

      FREQUENCY_CACHE["#{to_cron_s}|#{year}"] ||=
        begin

          deltas = []

          t = EtOrbi.make_time("#{year}-01-01") - 1
          t0 = nil
          t1 = nil

          loop do
            t1 = next_time(t)
            deltas << (t1 - t).to_i if t0
            t0 ||= t1
            break if deltas.any? && t1.year > year
            break if t1.year - t0.year > 7
            t = t1
          end

          Frequency.new(deltas, t1 - t0)
        end
    end

    SLOTS = [
      [ :seconds, 1, 60 ],
      [ :minutes, 60, 60 ],
      [ :hours, 3600, 24 ],
      [ :days, DAY_S, 365 ] ].freeze

    def rough_frequency

      slots = SLOTS
        .collect { |k, v0, v1|
          a = (k == :days) ? rough_days : instance_variable_get("@#{k}")
          [ k, v0, v1, a ] }

      slots.each do |k, v0, _, a|
        next if a == [ 0 ]
        break if a != nil
        return v0 if a == nil
      end

      slots.each do |k, v0, v1, a|
        next unless a && a.length > 1
        return (a + [ a.first + v1 ])
          .each_cons(2)
          .collect { |a0, a1| a1 - a0 }
          .select { |d| d > 0 } # weed out zero deltas
          .min * v0
      end

      slots.reverse.each do |k, v0, v1, a|
        return v0 * v1 if a && a.length == 1
      end

      1 # second
    end

    class Frequency

      attr_reader :span, :delta_min, :delta_max, :occurrences
      attr_reader :span_years, :yearly_occurrences

      def initialize(deltas, span)

        @span = span

        @delta_min = deltas.min; @delta_max = deltas.max
        @occurrences = deltas.size
        @span_years = span / YEAR_S
        @yearly_occurrences = @occurrences.to_f / @span_years
      end

      def to_debug_s

        {
          dmin: Fugit::Duration.new(delta_min).deflate.to_plain_s,
          dmax: Fugit::Duration.new(delta_max).deflate.to_plain_s,
          ocs: occurrences,
          spn: Fugit::Duration.new(span.to_i).deflate.to_plain_s,
          spnys: span_years.to_i,
          yocs: yearly_occurrences.to_i
        }.collect { |k, v| "#{k}: #{v}" }.join(', ')
      end
    end

    def to_a

      [ @seconds, @minutes, @hours, @monthdays, @months, @weekdays ]
    end

    def to_h

      { seconds: @seconds,
        minutes: @minutes,
        hours: @hours,
        monthdays: @monthdays,
        months: @months,
        weekdays: @weekdays }
    end

    def ==(o)

      o.is_a?(::Fugit::Cron) && o.to_a == to_a
    end
    alias eql? ==

    def hash

      to_a.hash
    end

    protected

    def compact_month_days

      return true if @months == nil || @monthdays == nil

      ms, ds =
        @months.inject([ [], [] ]) { |a, m|
          @monthdays.each { |d|
            next if d > MAXDAYS[m]
            a[0] << m; a[1] << d }
          a }
      @months = ms.uniq
      @monthdays = ds.uniq

      @months.any? && @monthdays.any?
    end

    def rough_days

      return nil if @weekdays == nil && @monthdays == nil

      months = (@months || (1..12).to_a)

      monthdays = months
        .product(@monthdays || [])
        .collect { |m, d|
          d = 31 + d if d < 0
          (m - 1) * 30 + d } # rough

      weekdays = (@weekdays || [])
        .collect { |d, w|
          w ?
          d + (w - 1) * 7 :
          (0..3).collect { |ww| d + ww * 7 } }
        .flatten
      weekdays = months
        .product(weekdays)
        .collect { |m, d| (m - 1) * 30 + d } # rough

      (monthdays + weekdays).sort
    end

    FREQUENCY_CACHE = {}

    def init(original, h, opts)

      return nil unless h

      @original = original
      @cron_s = nil # just to be sure
      @day_and = h[:&]

      valid =
        determine_seconds(h[:sec], opts) &&
        determine_minutes(h[:min], opts) &&
        determine_hours(h[:hou], opts) &&
        determine_monthdays(h[:dom], opts) &&
        determine_months(h[:mon], opts) &&
        determine_weekdays(h[:dow], opts) &&
        determine_timezone(h[:tz])

      return nil unless valid
      return nil unless compact_month_days

      @fold = determine_dst_policy(:fold, opts, FOLD_POLICIES, :earlier)
      @gap = determine_dst_policy(:gap, opts, GAP_POLICIES, :skip)

      @dst_policies = opts.key?(:fold) || opts.key?(:gap)
        #
        # the fold/gap policy aware #next_time and #previous_time
        # are only used when the policies were explicitly set,
        # the default behaviour is left untouched

      self
    end

    def determine_dst_policy(key, opts, policies, default)

      v = opts[key]

      return default if v.nil?

      v = v.to_sym if v.respond_to?(:to_sym)

      return v if policies.include?(v)

      fail ArgumentError.new(
        "invalid #{key} policy #{opts[key].inspect}, " +
        "expected one of #{policies.collect(&:inspect).join(', ')}"
      )
    end

    def expand(min, max, opts, r)

      sta, edn, sep, sla = r

      #return false if sla && sla > max
        #
        # let it go, "* */24 * * *" and "* */27 * * *" are okay
        # gh-86 and gh-103

      return false if sla && sla < 1

      if sep == :tilde
        sta = random(min, max, sta, edn, sla, opts)
        edn = nil unless sla
      end

      edn = max if sla && edn.nil?

      return nil if sta.nil? && edn.nil? && sla.nil?
      return sta if sta && edn.nil?

      sla = 1 if sla == nil
      sta = min if sta == nil
      edn = max if edn == nil || edn < 0 && sta > 0

      range(min, max, sta, edn, sla)
    end

    def random(min, max, sta, edn, sla, opts)

      sta = min if sta.nil?
      edn = max if edn.nil?

      random = opts.fetch(:random, true)
      random = Random if random == true
      return sta unless random

      n = edn - sta + 1
      n = max - min + 1 + n if n <= 0
      n = sla if sla && sla < n

      r = sta + random.rand(n)
      r = r + min - max - 1 if r > max
      r
    end

    def range(min, max, sta, edn, sla)

      return [ nil ] if sta == min && edn == max && sla == 1

      fail ArgumentError.new(
        'both start and end must be negative in ' +
        { min: min, max: max, sta: sta, edn: edn, sla: sla }.inspect
      ) if (sta < 0 && edn > 0) || (edn < 0 && sta > 0)

      a = []

      omin, omax = min, max
      min, max = -max, -1 if sta < 0

      cur = sta

      loop do

        a << cur
        break if cur == edn

        cur += 1
        if cur > max
          cur = min
          edn = edn - max - 1 if edn > max
        end

        fail RuntimeError.new(
          "too many loops for " +
          { min: omin, max: omax, sta: sta, edn: edn, sla: sla }.inspect +
          " #range, breaking, " +
          "please fill an issue at https://git.io/fjJC9"
        ) if a.length > 2 * omax
          # there is a #uniq afterwards, hence the 2* for 0-24 and friends
      end

      a.each_with_index
        .select { |e, i| i % sla == 0 }
        .collect(&:first)
        .uniq
    end

    def do_determine(key, arr, min, max, opts)

      null = false

      r = arr
        .collect { |v|
          expand(min, max, opts, v) }
        .flatten(1)
        .collect { |e|
          return false if e == false
          null = null || e == nil
          (key == :hours && e == 24) ? 0 : e }

      return nil if null
      r.uniq.sort
    end

    def determine_seconds(arr, opts)
      (@seconds = do_determine(:seconds, arr || [ 0 ], 0, 59, opts)) != false
    end

    def determine_minutes(arr, opts)
      (@minutes = do_determine(:minutes, arr, 0, 59, opts)) != false
    end

    def determine_hours(arr, opts)
      (@hours = do_determine(:hours, arr, 0, 23, opts)) != false
    end

    def determine_monthdays(arr, opts)
      (@monthdays = do_determine(:monthdays, arr, 1, 31, opts)) != false
    end

    def determine_months(arr, opts)
      (@months = do_determine(:months, arr, 1, 12, opts)) != false
    end

    def determine_weekdays(arr, opts)

      @weekdays = []

      arr.each do |a, z, sp, sl, ha, mo| # a to z, seperator, slash, hash, and mod
        if sp == :tilde
          a = random(0, 6, a, z, sl, opts)
          z = nil unless sl
        end

        if ha || mo
          @weekdays << [ a, ha || mo ]
        elsif sl
          z ||= (a ? a : 6)
          a ||= 0
          z = z + 7 if a > z
          (a..z).step(sl < 1 ? 1 : sl)
            .each { |i| @weekdays << [ (i > 6) ? i - 7 : i ] }
        elsif z
          z = z + 7 if a > z
          (a..z).each { |i| @weekdays << [ (i > 6) ? i - 7 : i ] }
        elsif a
          @weekdays << [ a ]
        #else
        end
      end

      @weekdays.each { |wd| wd[0] = 0 if wd[0] == 7 } # turn sun7 into sun0
      @weekdays.uniq!
      @weekdays.sort!
      @weekdays = nil if @weekdays.empty?

      true
    end

    def determine_timezone(z)

      @zone, @timezone = z

      true
    end

    def weekdays_to_cron_s

      return '*' unless @weekdays

      @weekdays
        .collect { |a|
          if a.length == 1
            a[0].to_s
          elsif a[1].is_a?(Array)
            a11 = a[1][1]
            off = (a11 < 0) ? a11.to_s : (a11 > 0) ? "+#{a11}" : ''
            "#{a[0]}%#{a[1][0]}" + off
          else
            a.collect(&:to_s).join('#')
          end }
        .join(',') +
      (@day_and ? '&' : '')
    end

    module Parser include Raabro

      WEEKDAYS =
        %w[ sunday monday tuesday wednesday thursday friday saturday ].freeze

      WEEKDS =
        WEEKDAYS.collect { |d| d[0, 3] }.freeze
      DOW_REX =
        /([0-7]|#{WEEKDS.join('|')})/i.freeze

      MONTHS =
        %w[ - jan feb mar apr may jun jul aug sep oct nov dec ].freeze
      MONTH_REX =
        /(1[0-2]|0?[1-9]|#{MONTHS[1..-1].join('|')})/i.freeze

      # piece parsers bottom to top

      def s(i); rex(nil, i, /[ \t]+/); end
      def star(i); str(nil, i, '*'); end
      def hyphen(i); str(:hyphen, i, '-'); end
      def tilde(i); str(:tilde, i, '~'); end
      def comma(i); rex(nil, i, /,([ \t]*,)*/); end
      def comma?(i); rex(nil, i, /([ \t]*,)*/); end
      def and?(i); rex(nil, i, /&?/); end

      def slash(i); rex(:slash, i, /\/\d\d?/); end

      def mos(i); rex(:mos, i, /[0-5]?\d/); end # min or sec
      def hou(i); rex(:hou, i, /(2[0-4]|[01]?[0-9])/); end
      def dom(i); rex(:dom, i, /(-?(3[01]|[12][0-9]|0?[1-9])|last|l)/i); end
      def mon(i); rex(:mon, i, MONTH_REX); end
      def dow(i); rex(:dow, i, DOW_REX); end

      def dow_hash(i); rex(:hash, i, /#(-?[1-5]|last|l)/i); end

      def _mos(i); seq(nil, i, :hyphen, :mos); end
      def _hou(i); seq(nil, i, :hyphen, :hou); end
      def _dom(i); seq(nil, i, :hyphen, :dom); end
      def _mon(i); seq(nil, i, :hyphen, :mon); end
      def _dow(i); seq(nil, i, :hyphen, :dow); end

      # r: range
      def r_mos(i); seq(nil, i, :mos, :_mos, '?'); end
      def r_hou(i); seq(nil, i, :hou, :_hou, '?'); end
      def r_dom(i); seq(nil, i, :dom, :_dom, '?'); end
      def r_mon(i); seq(nil, i, :mon, :_mon, '?'); end
      def r_dow(i); seq(nil, i, :dow, :_dow, '?'); end

      # t: tilde range
      def t_mos(i); seq(nil, i, :mos, '?', :tilde, :mos, '?'); end
      def t_hou(i); seq(nil, i, :hou, '?', :tilde, :hou, '?'); end
      def t_dom(i); seq(nil, i, :dom, '?', :tilde, :dom, '?'); end
      def t_mon(i); seq(nil, i, :mon, '?', :tilde, :mon, '?'); end
      def t_dow(i); seq(nil, i, :dow, '?', :tilde, :dow, '?'); end

      # sor: star or range
      def sor_mos(i); alt(nil, i, :star, :t_mos, :r_mos); end
      def sor_hou(i); alt(nil, i, :star, :t_hou, :r_hou); end
      def sor_dom(i); alt(nil, i, :star, :t_dom, :r_dom); end
      def sor_mon(i); alt(nil, i, :star, :t_mon, :r_mon); end
      def sor_dow(i); alt(nil, i, :star, :t_dow, :r_dow); end

      # sorws: star or range with[out] slash
      def sorws_mos(i); seq(nil, i, :sor_mos, :slash, '?'); end
      def sorws_hou(i); seq(nil, i, :sor_hou, :slash, '?'); end
      def sorws_dom(i); seq(nil, i, :sor_dom, :slash, '?'); end
      def sorws_mon(i); seq(nil, i, :sor_mon, :slash, '?'); end
      def sorws_dow(i); seq(nil, i, :sor_dow, :slash, '?'); end

      # ssws: slash or sorws
      def mos_elt(i); alt(:elt, i, :slash, :sorws_mos); end
      def hou_elt(i); alt(:elt, i, :slash, :sorws_hou); end
      def dom_elt(i); alt(:elt, i, :slash, :sorws_dom); end
      def mon_elt(i); alt(:elt, i, :slash, :sorws_mon); end
      def dow_elt(i); alt(:elt, i, :slash, :sorws_dow); end

      def mod(i); rex(:mod, i, /%\d+(\+\d+)?/); end

      def mod_dow(i); seq(:elt, i, :dow, :mod); end
      def h_dow(i); seq(:elt, i, :dow, :dow_hash); end

      def dow_elt_(i); alt(nil, i, :h_dow, :mod_dow, :dow_elt); end

      def list_sec(i); jseq(:sec, i, :mos_elt, :comma); end
      def list_min(i); jseq(:min, i, :mos_elt, :comma); end
      def list_hou(i); jseq(:hou, i, :hou_elt, :comma); end
      def list_dom(i); jseq(:dom, i, :dom_elt, :comma); end
      def list_mon(i); jseq(:mon, i, :mon_elt, :comma); end
      def list_dow(i); jseq(:dow, i, :dow_elt_, :comma); end

      def lsec_(i); seq(nil, i, :comma?, :list_sec, :comma?, :s); end
      def lmin_(i); seq(nil, i, :comma?, :list_min, :comma?, :s); end
      def lhou_(i); seq(nil, i, :comma?, :list_hou, :comma?, :s); end
      def ldom_(i); seq(nil, i, :comma?, :list_dom, :comma?, :and?, :s); end
      def lmon_(i); seq(nil, i, :comma?, :list_mon, :comma?, :s); end
      def ldow(i); seq(nil, i, :comma?, :list_dow, :comma?, :and?); end

      def _tz_name(i)
        rex(nil, i, / +[A-Z][a-zA-Z0-9+\-]+(\/[A-Z][a-zA-Z0-9+\-_]+){0,2}/)
      end
      def _tz_delta(i)
        rex(nil, i, / +[-+]([01][0-9]|2[0-4]):?(00|15|30|45)/)
      end
      def _tz(i); alt(:tz, i, :_tz_delta, :_tz_name); end

      def classic_cron(i)
        seq(:ccron, i,
          :lmin_, :lhou_, :ldom_, :lmon_, :ldow, :_tz, '?')
      end
      def second_cron(i)
        seq(:scron, i,
          :lsec_, :lmin_, :lhou_, :ldom_, :lmon_, :ldow, :_tz, '?')
      end

      def cron(i)
        alt(:cron, i, :second_cron, :classic_cron)
      end

      # rewriting the parsed tree

      def rewrite_bound(k, t)

        s = t.string.downcase

        (k == :mon && MONTHS.index(s)) ||
        (k == :dow && WEEKDS.index(s)) ||
        ((k == :dom) && s[0, 1] == 'l' && -1) || # L, l, last
        s.to_i
      end

      def rewrite_mod(k, t)

        mod, plus = t.string
          .split(/[%+]/).reject(&:empty?).collect(&:to_i)

        [ mod, plus || 0 ]
      end

      def rewrite_elt(k, t)

        at, zt, spt, slt, hat, mot = nil

        t.subgather(nil).each do |tt|
          case tt.name
          when :slash then slt = tt
          when :hash then hat = tt
          when :mod then mot = tt
          when :hyphen then spt = tt
          when :tilde then spt = tt
          else if spt; zt ||= tt; else; at = tt; end
          end
        end

        sl = slt ? slt.string[1..-1].to_i : nil

        ha = hat ? hat.string[1..-1] : nil
        ha = -1 if ha && ha.upcase[0, 1] == 'L'
        ha = ha.to_i if ha

        mo = mot ? rewrite_mod(k, mot) : nil

        a = at ? rewrite_bound(k, at) : nil
        z = zt ? rewrite_bound(k, zt) : nil
        sp = spt ? spt.name : nil

        #a, z = z, a if a && z && a > z
          # handled downstream since gh-27

        [ a, z, sp, sl, ha, mo ]
      end

      def rewrite_entry(t)

        t
          .subgather(:elt)
          .collect { |et| rewrite_elt(t.name, et) }
      end

      def rewrite_tz(t)

        s = t.strim
        z = EtOrbi.get_tzone(s)

        [ s, z ]
      end

      def rewrite_cron(t)

        st = t
          .sublookup(nil) # go to :ccron or :scron

        return nil unless st

        hcron = st
          .subgather(nil) # list min, hou, mon, ...
          .inject({}) { |h, tt|
            h[tt.name] = tt.name == :tz ? rewrite_tz(tt) : rewrite_entry(tt)
            h }
        hcron[:&] = true if t.string.index('&')

        z, tz = hcron[:tz]; return nil if z && ! tz

        hcron
      end
    end
  end
end

