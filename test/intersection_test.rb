#
# Specifying Fugit.cron_intersection
#
# Fri Oct  3 10:00:00 UTC 2026
#

group Fugit::Cron::Intersection do

  test 'is an Enumerable built from two crons and a finite window' do

    c0 = Fugit.parse_cron('0 0 * * * UTC')
    c1 = Fugit.parse_cron('0 0 * * * UTC')

    i = Fugit.cron_intersection(
      c0, c1, Time.utc(2024, 1, 1)..Time.utc(2024, 1, 3))

    assert i.is_a?(::Enumerable), true
    assert i.crons, [ c0, c1 ]
    assert i.is_a?(Fugit::Cron::Intersection), true
    assert i.status, nil

    # Cron#intersection as well

    j = c0.intersection(c1, Time.utc(2024, 1, 1), Time.utc(2024, 1, 3))

    assert j.count, 3
  end

  test 'also accepts cron strings and the two-args window form' do

    i = Fugit.intersect_crons(
      '0 0 * * * UTC', '0 0 * * * UTC',
      Time.utc(2024, 1, 1), Time.utc(2024, 1, 3))

    assert i.crons.collect(&:class).uniq, [ Fugit::Cron ]
    assert i.map { |t| t.utc.to_s }, [
      '2024-01-01 00:00:00 UTC', '2024-01-02 00:00:00 UTC',
      '2024-01-03 00:00:00 UTC' ]
  end

  group 'enumeration' do

    test 'intersects two different-frequency crons on shared instants' do

      i = Fugit.cron_intersection(
        '0 9 * * mon UTC', '0 9 13 * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2025, 1, 1))

      hits = i.to_a

      assert hits.collect { |t| t.utc.strftime('%F %a %T') }, [
        '2024-05-13 Mon 09:00:00' ]
      assert i.complete?, true
      assert i.incomplete?, false
    end

    test 'intersects the cron with itself' do

      i = Fugit.cron_intersection(
        '0 0 13 * * UTC', '0 0 13 * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2024, 4, 1))

      assert i.map { |t| t.utc.strftime('%F') }, %w[
        2024-01-13 2024-02-13 2024-03-13 ]
    end

    test 'compares crons on the real instant across timezones' do

      # 06:00 New York is 11:00 London while both are in winter time

      i = Fugit.cron_intersection(
        '0 6 * * * America/New_York',
        '0 11 * * * Europe/London',
        Time.utc(2024, 1, 1)..Time.utc(2024, 1, 8))

      assert i.map { |t| t.utc.strftime('%F %T') }, [
        '2024-01-01 11:00:00', '2024-01-02 11:00:00',
        '2024-01-03 11:00:00', '2024-01-04 11:00:00',
        '2024-01-05 11:00:00', '2024-01-06 11:00:00',
        '2024-01-07 11:00:00' ]
    end

    test 'does not match same wall-clock labels at different instants' do

      # 06:00 New York is 11:00 UTC, never 06:00 UTC in January

      i = Fugit.cron_intersection(
        '0 6 * * * America/New_York',
        '0 6 * * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2024, 2, 1))

      assert i.to_a, []
      assert i.complete?, true
    end
  end

  group 'window boundaries' do

    test 'includes a trigger exactly at the inclusive window start/end' do

      i = Fugit.cron_intersection(
        '0 0 * * * UTC', '0 0 * * * UTC',
        Time.utc(2024, 1, 1)..Time.utc(2024, 1, 3))

      assert i.map { |t| t.utc.strftime('%F') }, %w[
        2024-01-01 2024-01-02 2024-01-03 ]
    end

    test 'excludes a trigger exactly at an exclusive window end' do

      i = Fugit.cron_intersection(
        '0 0 * * * UTC', '0 0 * * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2024, 1, 3))

      assert i.exclude_end?, true
      assert i.map { |t| t.utc.strftime('%F') }, %w[
        2024-01-01 2024-01-02 ]
    end

    test 'includes a trigger exactly at the window start but not before' do

      i = Fugit.cron_intersection(
        '0 9 * * * UTC', '0 9 * * * UTC',
        Time.utc(2024, 1, 1, 12)..Time.utc(2024, 1, 4))

      assert i.map { |t| t.utc.strftime('%F %T') }, [
        '2024-01-02 09:00:00', '2024-01-03 09:00:00' ]
    end
  end

  group 'DST' do

    test 'places a gap-day trigger at the first valid instant' do

      # On 2024-03-10, 02:00->03:00 New York does not exist; fugit
      # places the 03:00 trigger at 07:00 UTC, which meets the UTC
      # cron exactly.

      i = Fugit.cron_intersection(
        '0 3 * * * America/New_York',
        '0 7 * * * UTC',
        Time.utc(2024, 3, 9)...Time.utc(2024, 3, 14))

      assert i.map { |t| t.utc.strftime('%F %T') }, [
        '2024-03-10 07:00:00', '2024-03-11 07:00:00',
        '2024-03-12 07:00:00',
        '2024-03-13 07:00:00' ]
    end

    test 'handles the fall-back repeated local hour' do

      # From 2024-11-03 on, 01:00 NY is 06:00 UTC. The 01:00 that
      # occurs twice that day (EDT 05:00Z, then EST 06:00Z) yields
      # exactly one common instant, the EST one.

      i = Fugit.cron_intersection(
        '0 1 * * * America/New_York',
        '0 6 * * * UTC',
        Time.utc(2024, 11, 1)...Time.utc(2024, 11, 10))

      assert i.map { |t| t.utc.strftime('%F %T') }, [
        '2024-11-03 06:00:00', '2024-11-04 06:00:00',
        '2024-11-05 06:00:00', '2024-11-06 06:00:00',
        '2024-11-07 06:00:00', '2024-11-08 06:00:00',
        '2024-11-09 06:00:00' ]
    end
  end

  group 'work bound (no per-second scan)' do

    test 'cross-year monthly rules with no intersection use few advances' do

      # Day 31 and day 30 of the month never coincide. Both rules
      # trigger at most once per month, the leapfrog must stay monthly.

      i = Fugit.cron_intersection(
        '0 0 31 * * UTC', '0 0 30 * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2030, 1, 1))

      hits = i.to_a

      assert hits, []
      assert i.complete?, true
      assert i.advances <= 2 * 12 * 6 + 4, true
      assert i.advances, 108 # exact for 2024..2029
    end

    test 'stops as incomplete when max_advances is reached' do

      i = Fugit.cron_intersection(
        '0 0 31 * * UTC', '0 0 30 * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2025, 1, 1),
        max_advances: 5)

      assert i.to_a, []
      assert i.advances, 5
      assert i.max_advances, 5
      assert i.incomplete?, true
      assert i.unfinished?, true
      assert i.complete?, false
      assert i.status, :incomplete
    end

    test 'does not mark complete runs incomplete with the default budget' do

      i = Fugit.cron_intersection(
        '0 * * * * UTC', '0 * * * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2024, 2, 1))

      assert i.count, 744
      assert i.advances, 1488
      assert i.complete?, true
      assert i.incomplete?, false
    end

    test 'rejects a non positive max_advances' do

      err = nil
      begin
        Fugit.cron_intersection(
          '0 0 * * *', '0 0 * * *',
          Time.utc(2024, 1, 1)..Time.utc(2024, 1, 2),
          max_advances: 0)
      rescue ArgumentError => err
      end

      assert err.class, ArgumentError
      assert err.message, 'max_advances must be a positive Integer, not 0'
    end
  end

  group 'laziness' do

    test 'returns an Enumerator and advances only as needed' do

      i = Fugit.cron_intersection(
        '0 0 31 * * UTC', '0 0 31 * * UTC',
        Time.utc(2024, 1, 1)...Time.utc(2030, 1, 1))

      assert i.each.class, Enumerator

      first = i.first

      assert first.utc.strftime('%F'), '2024-01-31'
      assert i.advances, 0 # already at a trigger, no advancement

      taken = i.lazy.drop(1).take(1).to_a

      assert taken.first.utc.strftime('%F'), '2024-03-31'
    end
  end

  group 'inputs and options' do

    test 'does not modify the given cron strings' do

      s0 = '0  0  1 * 1  UTC'
      s1 = s0.dup

      i = Fugit.cron_intersection(
        s0, '0 0 * * 0 UTC',
        Time.utc(2024, 1, 1)..Time.utc(2024, 3, 1))
      i.to_a

      assert s0, s1
      assert i.crons.first.original, s0
    end

    test 'fails on a non cron argument' do

      err = nil
      begin
        Fugit.cron_intersection(
          'nope', '0 0 * * *',
          Time.utc(2024, 1, 1)..Time.utc(2024, 1, 2))
      rescue ArgumentError => err
      end

      assert err.class, ArgumentError
      assert err.message, 'not a cron (argument 0): "nope"'
    end

    test 'requires a finite window range' do

      err = nil
      begin
        Fugit.cron_intersection(
          '0 0 * * *', '0 0 * * *', Time.utc(2024, 1, 1)..)
      rescue ArgumentError => err
      end

      assert err.class, ArgumentError
      assert err.message,
        'intersection window must be finite, ' +
        'a beginless or endless range is not allowed'
    end

    test 'requires a window end when not given a range' do

      err = nil
      begin
        Fugit.cron_intersection(
          '0 0 * * *', '0 0 * * *', Time.utc(2024, 1, 1))
      rescue ArgumentError => err
      end

      assert err.class, ArgumentError
      assert err.message,
        'intersection window must be finite, missing window end time'
    end
  end
end
