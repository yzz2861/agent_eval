
#
# Specifying fugit
#


class Probatio::Context

  def verify_min(cron_s, from, to, min_interval=30, budget=100_000)

    Fugit::Cron
      .parse(cron_s)
      .verify_min_interval(from, to, min_interval, budget: budget)
  end

  def brute_triggers(cron, from, to)

    # reference implementation: plain #next_time enumeration
    # over the same left-closed, right-open window [from, to)

    r = []
    t = from - 1

    loop do
      t = cron.next_time(t)
      break if t.to_i >= to.to_i
      r << t.to_i
    end

    r
  end
end


group Fugit::Cron do

  group '#verify_min_interval' do

    group 'dense crons' do

      test 'flags an every-second cron' do

        v = verify_min(
          '* * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 1, 1))

        assert_equal :violation, v.status
        assert_equal 1, v.delta
        assert_equal 2, v.checked
        assert_equal Time.utc(2017, 1, 1, 0, 0, 0).to_i, v.pair[0].to_i
        assert_equal Time.utc(2017, 1, 1, 0, 0, 1).to_i, v.pair[1].to_i
      end

      test 'flags a */10 seconds cron' do

        v = verify_min(
          '*/10 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 1, 1))

        assert_equal :violation, v.status
        assert_equal 10, v.delta
      end

      test 'flags a */31 seconds cron (wraparound, not average frequency)' do

        # */31 fires at :00 and :31 of every minute; the gap from :31
        # to the next minute's :00 is 29s, which an average-frequency
        # argument (3600s / 120 = 30s) would miss

        v = verify_min(
          '*/31 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2))

        assert_equal :violation, v.status
        assert_equal 29, v.delta
      end

      test 'flags a 0,10 seconds cron' do

        v = verify_min(
          '0,10 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2))

        assert_equal :violation, v.status
        assert_equal 10, v.delta
      end
    end

    group 'passing crons' do

      test 'passes a */30 seconds cron (30s is not < 30s)' do

        v = verify_min(
          '*/30 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2))

        assert_equal :ok, v.status
        assert_equal 2880, v.checked
        assert_true v.ok?
      end

      test 'passes a per-minute cron over a full year' do

        v = verify_min(
          '* * * * *', Time.utc(2017, 1, 1), Time.utc(2018, 1, 1), 30, 1_000_000)

        assert_equal :ok, v.status
        assert_equal 525600, v.checked
      end

      test 'accepts a Fugit::Duration as min_interval' do

        v = verify_min(
          '*/30 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 1, 1),
          Fugit::Duration.parse('30s'))

        assert_equal :ok, v.status
      end
    end

    group 'sparse crons' do

      test 'passes a Feb 29 cron over a year without Feb 29' do

        v = verify_min(
          '0 0 29 2 *', Time.utc(2017, 1, 1), Time.utc(2018, 1, 1))

        assert_equal :ok, v.status
        assert_equal 0, v.checked
      end

      test 'passes a Feb 29 cron over a window containing a leap day' do

        v = verify_min(
          '0 0 29 2 *', Time.utc(2019, 1, 1), Time.utc(2021, 1, 1))

        assert_equal :ok, v.status
        assert_equal 1, v.checked
      end

      test 'passes a 31st-of-the-month cron over a year' do

        v = verify_min(
          '0 0 31 * *', Time.utc(2017, 1, 1), Time.utc(2018, 1, 1))

        assert_equal :ok, v.status
        assert_equal 7, v.checked
      end
    end

    group 'window boundaries' do

      test 'includes a trigger falling exactly on from (left-closed)' do

        v = verify_min(
          '50,0 * * * * *',
          Time.utc(2017, 1, 2, 12, 0, 50), Time.utc(2017, 1, 2, 12, 1, 1))

        assert_equal :violation, v.status
        assert_equal 10, v.delta
        assert_equal Time.utc(2017, 1, 2, 12, 0, 50).to_i, v.pair[0].to_i
      end

      test 'excludes a trigger falling exactly on to (right-open)' do

        v = verify_min(
          '0 * * * * *',
          Time.utc(2017, 1, 2, 12, 0, 0), Time.utc(2017, 1, 2, 12, 2, 0))

        assert_equal :ok, v.status
        assert_equal 2, v.checked # 12:00:00 and 12:01:00, not 12:02:00
      end
    end

    group 'budget' do

      test 'returns :budget_exceeded when the budget runs out' do

        v = verify_min(
          '*/30 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2), 30, 10)

        assert_equal :budget_exceeded, v.status
        assert_equal 10, v.checked
      end

      test ':budget_exceeded is not a pass' do

        v = verify_min(
          '*/30 * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2), 30, 10)

        assert_false v.ok?
        assert_true v.budget_exceeded?
      end

      test 'a small budget does not hide a dense-cron violation' do

        v = verify_min(
          '* * * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2), 30, 5)

        assert_equal :violation, v.status
      end
    end

    group 'DST' do

      NY = 'America/New_York'

      test 'keeps 60s gaps for a per-minute cron across the fall-back fold' do

        c = Fugit::Cron.parse("* * * * * #{NY}")

        v = c.verify_min_interval(
          EtOrbi.parse("2017-11-05 00:00:00 #{NY}"),
          EtOrbi.parse("2017-11-06 00:00:00 #{NY}"),
          60)

        assert_equal :ok, v.status
        assert_equal 1500, v.checked # 25h, the 01:00 hour happens twice
      end

      test 'passes a per-minute cron across the spring-forward gap' do

        c = Fugit::Cron.parse("* * * * * #{NY}")

        v = c.verify_min_interval(
          EtOrbi.parse("2017-03-12 00:00:00 #{NY}"),
          EtOrbi.parse("2017-03-13 00:00:00 #{NY}"),
          30)

        assert_equal :ok, v.status
        assert_equal 1380, v.checked # 23h
      end

      test 'matches a plain #next_time enumeration across the fold' do

        c = Fugit::Cron.parse("0,30 * * * * * #{NY}")
        from = EtOrbi.parse("2017-11-05 00:00:00 #{NY}")
        to = EtOrbi.parse("2017-11-05 04:00:00 #{NY}")

        v = c.verify_min_interval(from, to, 30)

        times = brute_triggers(c, from, to)
        min_gap = times.each_cons(2).collect { |a, b| b - a }.min

        assert_equal :ok, v.status
        assert_equal times.length, v.checked
        assert_equal 30, min_gap
      end


      test 'matches a plain #next_time enumeration across fold and next day' do

        c = Fugit::Cron.parse("* * * * * #{NY}")
        from = EtOrbi.parse("2017-11-05 00:00:00 #{NY}")
        to = EtOrbi.parse("2017-11-07 00:00:00 #{NY}")

        v = c.verify_min_interval(from, to, 60)

        assert_equal :ok, v.status
        assert_equal brute_triggers(c, from, to).length, v.checked
        assert_equal 2940, v.checked # 49h, fold day + regular day
      end
      test 'matches a plain #next_time enumeration across the spring-forward' do

        c = Fugit::Cron.parse("0,30 * * * * * #{NY}")
        from = EtOrbi.parse("2017-03-12 00:00:00 #{NY}")
        to = EtOrbi.parse("2017-03-12 04:00:00 #{NY}")

        v = c.verify_min_interval(from, to, 30)

        times = brute_triggers(c, from, to)
        min_gap = times.each_cons(2).collect { |a, b| b - a }.min

        assert_equal :ok, v.status
        assert_equal times.length, v.checked
        assert_equal 30, min_gap
      end
    end

    group 'invalid arguments' do

      test 'rejects to <= from' do

        assert_error ArgumentError do
          verify_min('* * * * *', Time.utc(2017, 1, 2), Time.utc(2017, 1, 1))
        end
      end

      test 'rejects a non-positive min_interval' do

        assert_error ArgumentError do
          verify_min('* * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2), 0)
        end
      end

      test 'rejects a non-positive budget' do

        assert_error ArgumentError do
          verify_min('* * * * *', Time.utc(2017, 1, 1), Time.utc(2017, 1, 2), 30, 0)
        end
      end
    end
  end
end
