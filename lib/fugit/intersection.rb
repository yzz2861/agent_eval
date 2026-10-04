# frozen_string_literal: true

module Fugit

  class Cron

    # Given another cron and a finite time window, enumerates the
    # trigger instants the two crons have in common.
    #
    # See Fugit.cron_intersection for details.
    #
    def intersection(other, window, end_time=nil, max_advances: nil)

      ::Fugit::Cron::Intersection.new(
        self, other, window, end_time, max_advances: max_advances)
    end

    # Lazily enumerates the instants at which two crons trigger
    # together.
    #
    # The two crons may live in different timezones, comparison is
    # always done on the real (UTC) instant.
    #
    # Enumeration is bound to a finite window and to a maximum number
    # of candidate advancements, so it cannot degenerate into a
    # second-by-second (or infinite) scan. When the budget is reached
    # before the end of the window, #incomplete? (aliased #unfinished?)
    # returns true.
    #
    class Intersection

      include ::Enumerable

      DEFAULT_SPAN_FACTOR = 2
      MIN_DEFAULT_MAX_ADVANCES = 4096

      attr_reader :crons
      attr_reader :from, :to
      attr_reader :max_advances, :advances
      attr_reader :status

      def initialize(cron0, cron1, window, end_time=nil, max_advances: nil)

        @cron0 = to_cron(cron0, 0)
        @cron1 = to_cron(cron1, 1)
        @crons = [ @cron0, @cron1 ].freeze

        @from, @to, @exclude_end =
          determine_window(window, end_time)

        determine_max_advances(max_advances)

        @advances = 0
        @status = nil
      end

      def window

        @exclude_end ? (@from...@to) : (@from..@to)
      end

      def exclude_end?

        @exclude_end
      end

      def complete?

        @status == :complete
      end

      def incomplete?

        @status == :incomplete
      end
      alias unfinished? incomplete?

      # Returns the common trigger instants as EtOrbi::EoTime instances
      # expressed in the zone of the window start time.
      #
      def each

        unless block_given?
          return enum_for(:each)
        end

        reset!

        c0, c1 = @cron0, @cron1
        t0 = place(c0, @from)
        t1 = place(c1, @from)

        to_i = @to.to_i

        loop do

          i0 = t0.to_i
          i1 = t1.to_i

          if [ i0, i1 ].min > to_i
            @status = :complete
            break
          end

          if i0 == i1

            inside =
              i0 < to_i || (i0 == to_i && ! @exclude_end)

            yield t0.translate(@from.zone) if inside

            if i0 >= to_i
              @status = :complete
              break
            end
          end

          if i0 < i1
            t0 = advance(c0, t0)
          else
            t1 = advance(c1, t1)
          end

          unless t0 && t1
            @status = :incomplete
            break
          end
        end

        self
      end

      protected

      def reset!

        @advances = 0
        @status = nil
      end

      # First trigger instant of the cron at or after the start of
      # the window. Relies on Cron#match?/Cron#next_time, so DST gaps
      # and overlaps are handled by the cron itself.
      #
      def place(cron, from)

        cron.match?(from) ? from : cron.next_time(from - 1)
      end

      def advance(cron, t)

        return nil if @advances >= @max_advances

        @advances += 1

        cron.next_time(t)
      end

      def to_cron(c, index)

        r =
          case c
          when ::Fugit::Cron then c
          when ::String then ::Fugit::Cron.parse(c)
          else nil
          end

        r ||
          fail(
            ArgumentError.new(
              "not a cron (argument #{index}): #{c.inspect}"))
      end

      def determine_window(window, end_time)

        if window.is_a?(::Range)

          if window.begin.nil? || window.end.nil?
            fail(
              ArgumentError.new(
                'intersection window must be finite, ' +
                'a beginless or endless range is not allowed'))
          end

          sta, edn = window.begin, window.end
          exclude = window.exclude_end?
        else

          if end_time.nil?
            fail(
              ArgumentError.new(
                'intersection window must be finite, ' +
                'missing window end time'))
          end

          sta, edn = window, end_time
          exclude = false
        end

        sta = ::EtOrbi.make_time(sta)
        edn = ::EtOrbi.make_time(edn)

        unless sta.respond_to?(:to_i) && edn.respond_to?(:to_i)
          fail(ArgumentError.new('intersection window bounds must be times'))
        end

        # The bounds keep the zone given by the caller (local when
        # plain). Instants still compare on their real time thanks to
        # EtOrbi::EoTime, so crons with different timezones interleave
        # on a single timeline.
        #
        [ sta, edn, exclude ]
      end

      def determine_max_advances(max)

        if max.nil?

          span = [ @to.to_i - @from.to_i, 0 ].max

          @max_advances =
            [
              DEFAULT_SPAN_FACTOR * span + 16,
              MIN_DEFAULT_MAX_ADVANCES
            ].max
        else

          unless max.is_a?(::Integer) && max >= 1
            fail(
              ArgumentError.new(
                "max_advances must be a positive Integer, not #{max.inspect}"))
          end

          @max_advances = max
        end
      end
    end
  end

  class << self

    # Returns a Fugit::Cron::Intersection, an Enumerable that lazily
    # yields the instants (EtOrbi::EoTime, in the zone of the window
    # start) at which the two given crons trigger together within the
    # given finite window.
    #
    # The window is a Range (its #exclude_end? is honoured) or a start
    # time followed by an end time, as for Fugit::Cron#within.
    #
    # The two crons may carry different timezones; they are compared on
    # their real (UTC) instant.
    #
    # max_advances bounds the work (candidate advancements) the
    # enumeration may perform. When the bound is hit before the end of
    # the window, the resulting intersection is #incomplete?.
    #
    def cron_intersection(cron0, cron1, window, end_time=nil, max_advances: nil)

      ::Fugit::Cron::Intersection.new(
        cron0, cron1, window, end_time, max_advances: max_advances)
    end
    alias intersect_crons cron_intersection
  end
end
