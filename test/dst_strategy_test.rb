#
# Specifying fugit DST fold/gap strategies
#

class Probatio::Context

  # Asserts the UTC instants produced by a sweep of next_time/previous_time.
  #
  def assert_utc_points(expected, cron_s, opts, from, count, meth=:next_time)

    c = Fugit::Cron.parse(cron_s, opts)
    t = EtOrbi.make_time(from)

    actual =
      count.times.collect do
        t = c.send(meth, t)
        t.dup.utc.strftime('%Y-%m-%d %H:%M:%S')
      end

    assert(actual.join("\n"), expected.join("\n"))
  end
end

group Fugit::Cron do

  group 'DST fold and gap strategies' do

    # America/New_York 2021:
    #   spring forward: Sun 2021-03-14 02:00 EST -> 03:00 EDT (gap)
    #   fall back:     Sun 2021-11-07 02:00 EDT -> 01:00 EST (fold)

    group 'gap (spring forward)' do

      test 'skips the missing local time by default (5 fields)' do

        assert_utc_points(
          [
            "2021-03-15 06:30:00",
            "2021-03-16 06:30:00",
            "2021-03-17 06:30:00",
          ],
          '30 2 * * * America/New_York', {},
          '2021-03-13 07:30:00 UTC', 3)
      end

      test 'skips the missing local time with gap: :skip' do

        assert_utc_points(
          [
            "2021-03-15 06:30:00",
            "2021-03-16 06:30:00",
            "2021-03-17 06:30:00",
          ],
          '30 2 * * * America/New_York', { gap: :skip },
          '2021-03-13 07:30:00 UTC', 3)
      end

      test 'adjusts forward by the gap size with gap: :adjust' do

        assert_utc_points(
          [
            "2021-03-14 08:30:00",
            "2021-03-15 06:30:00",
            "2021-03-16 06:30:00",
          ],
          '30 2 * * * America/New_York', { gap: :adjust },
          '2021-03-13 07:30:00 UTC', 3)
      end

      test 'adjusts forward with a seconds field' do

        assert_utc_points(
          [
            "2021-03-14 08:30:15",
            "2021-03-15 06:30:15",
            "2021-03-16 06:30:15",
          ],
          '15 30 2 * * * America/New_York', { gap: :adjust },
          '2021-03-13 07:30:16 UTC', 3)
      end

      test 'adjust works for previous_time without repeating' do

        assert_utc_points(
          [
            "2021-03-14 08:30:00",
            "2021-03-13 07:30:00",
            "2021-03-12 07:30:00",
            "2021-03-11 07:30:00",
          ],
          '30 2 * * * America/New_York', { gap: :adjust },
          '2021-03-15 06:30:00 UTC', 4, :previous_time)
      end

      test 'gap :skip works for previous_time' do

        assert_utc_points(
          [
            "2021-03-15 06:30:00",
            "2021-03-13 07:30:00",
            "2021-03-12 07:30:00",
          ],
          '30 2 * * * America/New_York', { gap: :skip },
          '2021-03-16 06:30:00 UTC', 3, :previous_time)
      end
    end

    group 'fold (fall back)' do

      test 'returns both occurrences by default' do

        assert_utc_points(
          [
            "2021-11-07 05:30:00",
            "2021-11-07 06:30:00",
            "2021-11-08 06:30:00",
            "2021-11-09 06:30:00",
          ],
          '30 1 * * * America/New_York', {},
          '2021-11-06 05:30:00 UTC', 4)
      end

      test 'returns both with fold: :both and a seconds field' do

        assert_utc_points(
          [
            "2021-11-07 05:30:00",
            "2021-11-07 06:30:00",
            "2021-11-08 06:30:00",
          ],
          '0 30 1 * * * America/New_York', { fold: :both },
          '2021-11-06 05:30:00 UTC', 3)
      end

      test 'fold: :early yields only the earlier occurrence' do

        assert_utc_points(
          [
            "2021-11-07 05:30:00",
            "2021-11-08 06:30:00",
            "2021-11-09 06:30:00",
          ],
          '30 1 * * * America/New_York', { fold: :early },
          '2021-11-06 05:30:00 UTC', 3)
      end

      test 'fold: :late yields only the later occurrence' do

        assert_utc_points(
          [
            "2021-11-07 06:30:00",
            "2021-11-08 06:30:00",
            "2021-11-09 06:30:00",
          ],
          '30 1 * * * America/New_York', { fold: :late },
          '2021-11-06 05:30:00 UTC', 3)
      end

      test 'next_time does not miss the second fold for 59 past' do

        assert_utc_points(
          [
            "2021-11-07 05:59:00",
            "2021-11-07 06:59:00",
            "2021-11-08 06:59:00",
          ],
          '59 1 * * * America/New_York', { fold: :both },
          '2021-11-06 05:59:00 UTC', 3)
      end

      test 'previous_time obeys fold: :both symmetrically' do

        assert_utc_points(
          [
            "2021-11-07 06:30:00",
            "2021-11-07 05:30:00",
            "2021-11-06 05:30:00",
            "2021-11-05 05:30:00",
          ],
          '30 1 * * * America/New_York', { fold: :both },
          '2021-11-08 06:30:00 UTC', 4, :previous_time)
      end

      test 'previous_time obeys fold: :early' do

        assert_utc_points(
          [
            "2021-11-07 05:30:00",
            "2021-11-06 05:30:00",
            "2021-11-05 05:30:00",
          ],
          '30 1 * * * America/New_York', { fold: :early },
          '2021-11-08 06:30:00 UTC', 3, :previous_time)
      end

      test 'previous_time obeys fold: :late with a seconds field' do

        assert_utc_points(
          [
            "2021-11-07 06:30:45",
            "2021-11-06 05:30:45",
            "2021-11-05 05:30:45",
          ],
          '45 30 1 * * * America/New_York', { fold: :late },
          '2021-11-08 06:30:45 UTC', 3, :previous_time)
      end

      test 'previous_time does not miss the second fold for 59 past' do

        assert_utc_points(
          [
            "2021-11-07 06:59:00",
            "2021-11-07 05:59:00",
            "2021-11-06 05:59:00",
          ],
          '59 1 * * * America/New_York', { fold: :both },
          '2021-11-08 06:59:00 UTC', 3, :previous_time)
      end
    end

    group 'fixed offset zones' do

      test 'are unaffected by the strategies (next_time)' do

        assert_utc_points(
          [
            "2021-03-14 18:30:00",
            "2021-03-15 18:30:00",
            "2021-03-16 18:30:00",
          ],
          '30 2 * * * +08:00', { gap: :adjust, fold: :late },
          '2021-03-13 18:30:00 UTC', 3)
      end

      test 'are unaffected by the strategies (previous_time)' do

        assert_utc_points(
          [
            "2021-03-14 02:30:00",
            "2021-03-13 02:30:00",
            "2021-03-12 02:30:00",
          ],
          '30 2 * * * UTC', { gap: :adjust, fold: :early },
          '2021-03-15 02:30:00 UTC', 3, :previous_time)
      end
    end

    group 'option validation' do

      test 'rejects unknown fold strategies' do

      assert_error(
        -> { Fugit::Cron.parse('* * * * *', fold: :nope) },
        ArgumentError,
        /unknown fold strategy :nope/)
      end

      test 'rejects unknown gap strategies' do

      assert_error(
        -> { Fugit::Cron.parse('* * * * *', gap: 'nope') },
        ArgumentError,
        /unknown gap strategy :nope/)
      end

      test 'accepts string strategy names and exposes readers' do

      c = Fugit::Cron.parse('30 1 * * * America/New_York', fold: 'late')

      assert(c.fold, :late)
      assert(c.gap, :skip)
      end
    end
  end
end
