
#
# Specifying fugit
#
# Tue Jan  3 11:31:29 JST 2017  Ishinomaki
#


group Fugit::Duration do

  group '.parse' do

    test 'returns nil when test cannot parse' do

      assert_nil Fugit::Duration.parse('NADA')
    end

    test 'returns nil if the input is too long' do

      assert_nil Fugit::Duration.parse('NADA ' * 100)
    end

    [
      [ 0, '0s' ],
      [ 7, '7s' ],
      [ 0.3, '0.3s' ],
      [ 1000, '1000s' ],
      [ 1001.05, '1001.05s' ],
    ].each do |source, target|

      test "turns numeric #{source.inspect} into #{target.inspect}" do

        assert Fugit::Duration.parse(source).to_plain_s, target
      end
    end

    [
      [ 0, 'PT0S' ],
      [ 1000, 'PT1000S' ],
      [ 1001.05, 'PT1001.05S' ],
    ].each do |source, target|

      test "turns numeric #{source.inspect} into ISO #{target.inspect}" do

        assert Fugit::Duration.parse(source).to_iso_s, target
      end
    end

    test "returns the input immediately if it's a duration" do

      d = Fugit::Duration.parse('1s')

      assert d.class, Fugit::Duration

      d1 = Fugit::Duration.parse(d)

      assert d1.class, Fugit::Duration
      assert d1.object_id, d.object_id
    end

    test 'returns nil if test cannot parse' do

      assert_nil Fugit::Duration.parse(true)
      assert_nil Fugit::Duration.parse('nada')
    end

    DAY_S = 24 * 3600

    [

      [ '1y2M', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ '1M1y1M', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ '10d10h', '10D10h', '10d10h', 'P10DT10H', 10 * DAY_S + 10 * 3600 ],
      [ '100s', '100s', '100s', 'PT100S', 100 ],

      [ '-1y-2M', '-1Y2M', '-1y2M', 'P-1Y-2M', - 365 * DAY_S - 60 * DAY_S ],
      [ '1M-1y-1M', '-1Y', '-1y', 'P-1Y', - 365 * DAY_S ],

      [ '-1y+2M', '-1Y+2M', '-1y+2M', 'P-1Y2M', - 365 * DAY_S + 60 * DAY_S ],
      [ '1M+1y-1M', '1Y', '1y', 'P1Y', 365 * DAY_S ],

      [ '1y 2M', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ '1M 1y  1M', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ ' 1M1y1M ', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],

      [ '1 year and 2 months', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ '1 y, 2 M, and 2 months', '1Y4M', '1y4M', 'P1Y4M', 41904000 ],
      [ '1 y, 2 M and 2 m', '1Y2M2m', '1y2M2m', 'P1Y2MT2M', 36720120 ],

      [ 'P1Y2M', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ 'P1Y2M', '1Y2M', '1y2M', 'P1Y2M', 365 * DAY_S + 60 * DAY_S ],
      [ 'P10DT10H', '10D10h', '10d10h', 'P10DT10H', 10 * DAY_S + 10 * 3600 ],
      [ 'PT100S', '100s', '100s', 'PT100S', 100 ],

      [ 'P-1Y-2M', '-1Y2M', '-1y2M', 'P-1Y-2M', - 365 * DAY_S - 60 * DAY_S ],
      [ 'p1M-1y-1Mt-1M', '-1Y1m', '-1y1m', 'P-1YT-1M', -31536060 ],

      [ '1min', '1m', '1m', 'PT1M', 60 ],
      [ '1 min', '1m', '1m', 'PT1M', 60 ],
      [ '1m', '1m', '1m', 'PT1M', 60 ],
      [ '1 m', '1m', '1m', 'PT1M', 60 ],
      [ '1minute', '1m', '1m', 'PT1M', 60 ],
      [ '1 minute', '1m', '1m', 'PT1M', 60 ],

      [ '3mins', '3m', '3m', 'PT3M', 180 ],
      [ '3 mins', '3m', '3m', 'PT3M', 180 ],
      [ '3m', '3m', '3m', 'PT3M', 180 ],
      [ '3 m', '3m', '3m', 'PT3M', 180 ],
      [ '3minutes', '3m', '3m', 'PT3M', 180 ],
      [ '3 minutes', '3m', '3m', 'PT3M', 180 ],

      [ '3secs', '3s', '3s', 'PT3S', 3 ],
      [ '3 secs', '3s', '3s', 'PT3S', 3 ],
      [ '3s', '3s', '3s', 'PT3S', 3 ],
      [ '3 s', '3s', '3s', 'PT3S', 3 ],
      [ '3seconds', '3s', '3s', 'PT3S', 3 ],
      [ '3 seconds', '3s', '3s', 'PT3S', 3 ],

      [ '1.4s', '1.4s', '1.4s', 'PT1.4S', 1.4 ],
      [ 'PT1.5S', '1.5s', '1.5s', 'PT1.5S', 1.5 ],
      [ '.4s', '0.4s', '0.4s', 'PT0.4S', 0.4 ],
      [ 'PT.5S', '0.5s', '0.5s', 'PT0.5S', 0.5 ],

      [ '1.0d1.0w1.0d', '1.0W2.0D', '1.0w2.0d', 'P1.0W2.0D', 777_600.0 ],

      [ '-5.s', '-5.0s', '-5.0s', 'PT-5.0S', -5.0 ],

      [ '7d7', '7D7s', '7d7s', 'P7DT7S', 7 * 24 * 3600 + 7 ],
      [ '7', '7s', '7s', 'PT7S', 7 ],
      [ '0.3', '0.3s', '0.3s', 'PT0.3S', 0.3 ],
      [ '0.1s0.3', '0.4s', '0.4s', 'PT0.4S', 0.4 ],

    ].each do |source, target, rufus_target, iso_target, sec|

      test "parses #{source.inspect}" do

        d = Fugit::Duration.parse(source)

        assert d.class, ::Fugit::Duration
        assert d.to_plain_s, target
        assert d.to_rufus_s, rufus_target
        assert d.to_iso_s, iso_target
        assert d.to_sec, sec
      end
    end

    [

      [ "7d7", 7 * 24 * 3600 + 7 ],
      [ " 7d7\n \n", 7 * 24 * 3600 + 7 ],
      [ " 7d 7\n \n", 7 * 24 * 3600 + 7 ],

    ].each do |src, sec|

      test "strips and parses #{src.inspect}" do

        d = Fugit::Duration.parse(src)

        assert d.original, src
        assert d.to_sec, sec
      end
    end

    test 'rejects lower case when ISO and :stricter' do

      assert_nil Fugit::Duration.parse('p1y', stricter: true)
    end

    test 'rejects when :iso and not ISO' do

      assert_nil Fugit::Duration.parse('1y', iso: true)
    end
  end

  group '.do_parse' do

    test 'raises an ArgumentError when test cannot parse' do

      assert_error(
        lambda { Fugit::Duration.do_parse('NADA') },
        ArgumentError, 'not a duration "NADA"')
    end

    test 'raises an ArgumentError when the input is too long' do

      assert_error(
        lambda { Fugit::Duration.do_parse('NADA ' * 100) },
        ArgumentError, 'input too long for a duration string, 499 > 256')
    end
  end

  group '#deflate' do

    [ %w[ 3600s    3600s     1h     ],
      %w[ 1y3600s  1Y3600s   1Y1h   ],
      %w[ 1d60s    86460s    1D1m   ],

      %w[ 3d-3h    248400s   2D21h  ],

      %w[ 0s       0s        0s     ],

      %w[ 0.1s     0.1s      0.1s   ],
      %w[ 1.1s     1.1s      1.1s   ],

      [ 61.127, '61.127s', '1m1.127s' ],

    ].each do |source, step, target|

      test(
        "deflates #{source.inspect} via #{step.inspect} into #{target.inspect}"
      ) do

        d = Fugit::Duration.new(source)

        id = d.inflate

        assert id.class, ::Fugit::Duration
        assert id.to_plain_s, step

        cd = d.deflate

        assert cd.class, ::Fugit::Duration
        assert cd.to_plain_s, target
      end
    end

    group 'month: true' do

      [
        [ '1M4W3s', { mon: 1, wee: 4, sec: 3 }, { mon: 1, wee: 4, sec: 3 } ],
        [ '5w3s', { wee: 5, sec: 3 }, { mon: 1, day: 5, sec: 3 } ],
        [ '40d', { day: 40 }, { mon: 1, wee: 1, day: 3 } ],
        [ 40 * 24 * 3600, { sec: 40 * 24 * 3600 }, { mon: 1, wee: 1, day: 3 } ],
      ].each do |src, h0, h1|

        test "returns a copy of the duration without its seconds (#{src})" do

          d = Fugit::Duration.parse(src)
          d1 = d.deflate(:month => true)

          assert d.h, h0
          assert d1.h, h1
        end
      end
    end

    group 'month: 30' do

      [

        %w[ 3600s 1h ],
        [ "#{30 * 24 * 3600}s", '1M' ],
        [ "#{1 + 30 * 24 * 3600}s", '1M1s' ],

      ].each do |source, target|

        test "deflates #{source.inspect} into #{target.inspect}" do

          d = Fugit::Duration.new(source).deflate(month: 30)

          assert d.to_plain_s, target
        end
      end
    end

    group 'month: "29d"' do

      [

        %w[ 3600s 1h ],
        [ "#{30 * 24 * 3600}s", '1M1D' ],
        [ "#{1 + 30 * 24 * 3600}s", '1M1D1s' ],

      ].each do |source, target|

        test "deflates #{source.inspect} into #{target.inspect}" do

          d = Fugit::Duration.new(source).deflate(month: '29d')

          assert d.to_plain_s, target
        end
      end
    end

    group 'year: 365' do

      [

        %w[ 3600s 1h ],
        [ '366d', '1Y1D' ],
        [ '53w', '1Y6D' ],

      ].each do |source, target|

        test "deflates #{source.inspect} into #{target.inspect}" do

          d = Fugit::Duration.new(source).deflate(year: 365)

          assert d.to_plain_s, target
        end
      end
    end

    group 'year: "52w"' do

      [

        %w[ 3600s 1h ],
        [ '366d', '1Y2D' ],
        [ '53w', '1Y1W' ],

      ].each do |source, target|

        test "deflates #{source.inspect} into #{target.inspect}" do

          d = Fugit::Duration.new(source).deflate(year: '52w')

          assert d.to_plain_s, target
        end
      end
    end
  end

  group '#opposite' do

    test 'returns the additive inverse' do

      d = Fugit::Duration.new('1y2m-3h')
      od = d.opposite

      assert od.to_plain_s, '-1Y+3h-2m'
      assert od.to_iso_s, 'P-1YT3H-2M'
    end
  end

  group '#-@' do

    test 'returns the additive inverse' do

      d = Fugit::Duration.new('1y2m-3h')
      od = - d

      assert od.to_plain_s, '-1Y+3h-2m'
      assert od.to_iso_s, 'P-1YT3H-2M'
    end
  end

  group '#add' do

    test 'adds Numeric instances' do

      d = Fugit.parse('1Y2h')

      assert d.add(1).to_plain_s, '1Y2h1s'
      assert (d + 1).to_plain_s, '1Y2h1s'
    end

    test 'adds Duration instances' do

      d0 = Fugit.parse('1Y2h')
      d1 = Fugit.parse('1Y2h1s')

      assert d0.add(d1).to_plain_s, '2Y4h1s'
      assert (d0 + d1).to_plain_s, '2Y4h1s'
    end

    test 'adds String instances (parses them as Duration)' do

      d = Fugit.parse('1Y2h')
      s = '1Y-1h1s'

      assert d.add(s).to_plain_s, '2Y1h-1s'
      assert (d + s).to_plain_s, '2Y1h-1s'
    end

    test 'yields a Time instance when adding a Time instance' do

      d = Fugit.parse('1Y1m17s')
      t = Time.parse('2017-01-03 17:02:00')

      t1 = d.add(t)
      assert Fugit.time_to_plain_s(t1, false), '2018-01-03 17:03:17'

      t1 = d + t
      assert Fugit.time_to_plain_s(t1, false), '2018-01-03 17:03:17'
    end

    [

      [ '1Y1m17s', '2016-12-30 17:00:00', '2017-12-30 17:01:17' ],
      [ '1Y1M17s', '2016-12-30 17:00:00', '2018-01-30 17:00:17' ],
      [ '1M', '2016-02-02', '2016-03-02' ],

      [ '-2M', '2016-02-02', '2015-12-02' ],
      [ '-15M', '2016-02-02', '2014-11-02' ],

      [ '-1Y1m17s', '2016-12-30 17:00:00', '2015-12-30 16:58:43' ],
      [ '10M11m12s', '2016-03-01 16:48:48', '2017-01-01 17:00:00' ],
      [ '-10M0m0s', '2016-12-30 17:00:00', '2016-03-01 17:00:00' ],
      [ '-10M11m12s', '2016-12-30 17:00:00', '2016-03-01 16:48:48' ],
        #
        # 2016 is a bissextile year ;-)
        # still "December 30" minus 10 months equals "March 1", ponder...

    ].each do |d, t, tt|

      test "adding #{t.inspect} to #{d.inspect} yields #{tt.inspect}" do

        d = Fugit.parse(d)
        t = Fugit.parse(t)

        t1 = d.add(t)

        assert(
          Fugit.time_to_plain_s(t1, false),
          Fugit.time_to_plain_s(Time.parse(tt), false))
      end
    end

    test 'fails else' do

      d = Fugit.parse('1Y2h')
      x = false

      assert_error(
        lambda { d.add(x) },
        ArgumentError, 'cannot add FalseClass instance to a Fugit::Duration')
      assert_error(
        lambda { d + x },
        ArgumentError,
        'cannot add FalseClass instance to a Fugit::Duration')
    end

    group 'end of month policy' do

      [
        [ '1M', '2020-01-31 12:00:00 UTC', :clamp,
          '2020-02-29 12:00:00 Z' ],
        [ '-1M', '2020-03-31 12:00:00 UTC', :clamp,
          '2020-02-29 12:00:00 Z' ],
        [ '1y', '2020-02-29 12:00:00 UTC', :clamp,
          '2021-02-28 12:00:00 Z' ],
        [ '-1y', '2020-02-29 12:00:00 UTC', :clamp,
          '2019-02-28 12:00:00 Z' ],
        [ '1M', '2020-01-31 12:00:00 UTC', :roll,
          '2020-03-02 12:00:00 Z' ],
        [ '-1M', '2020-03-31 12:00:00 UTC', :roll,
          '2020-03-02 12:00:00 Z' ],
        [ '1y', '2020-02-29 12:00:00 UTC', :roll,
          '2021-03-01 12:00:00 Z' ],
        [ '-1y', '2020-02-29 12:00:00 UTC', :roll,
          '2019-03-01 12:00:00 Z' ],
        [ '1M-1d', '2020-01-31 12:00:00 UTC', :clamp,
          '2020-02-29 12:00:00 Z' ],
        [ '1d1M', '2020-01-31 12:00:00 UTC', :clamp,
          '2020-03-01 12:00:00 Z' ],
        [ '1M-1d', '2020-01-31 12:00:00 UTC', :roll,
          '2020-03-01 12:00:00 Z' ],
        [ '1y1d', '2020-02-29 12:00:00 UTC', :roll,
          '2021-03-01 12:00:00 Z' ],
        [ '1y1M', '2020-02-29 12:00:00 UTC', :roll,
          '2021-04-01 12:00:00 Z' ],
        [ '1y1M', '2020-02-29 12:00:00 UTC', :clamp,
          '2021-03-28 12:00:00 Z' ],
        [ '1y1M1d', '2020-02-29 12:00:00 UTC', :clamp,
          '2021-04-01 12:00:00 Z' ],
        [ '13M', '2020-02-29 12:00:00 UTC', :clamp,
          '2021-03-29 12:00:00 Z' ],
        [ '13M', '2020-02-29 12:00:00 UTC', :reject,
          '2021-03-29 12:00:00 Z' ],
      ].each do |ds, ts, policy, target|

        test "applies #{policy} to #{ds} from #{ts}" do

          t = Fugit.parse(ds).add(
            ::EtOrbi::EoTime.parse(ts), end_of_month: policy)

          assert t.to_s, target
        end
      end

    test 'rolls by default to preserve historical arithmetic' do

      t = Fugit.parse('1M').add(::EtOrbi::EoTime.parse('2020-01-31 12:00 UTC'))

      assert t.to_s, '2020-03-02 12:00:00 Z'
    end

    test 'applies the policy when subtracting a time' do

      t = Fugit.parse('1M').subtract(
        ::EtOrbi::EoTime.parse('2020-03-31 12:00 UTC'),
        end_of_month: :clamp)

      assert t.to_s, '2020-02-29 12:00:00 Z'
    end

    test 'rejects an impossible month end after a month shift' do

      assert_error(
        lambda {
          Fugit.parse('1M').add(
            ::EtOrbi::EoTime.parse('2020-01-31 12:00 UTC'),
            end_of_month: :reject)
        },
        ArgumentError,
        '2020-01-31 does not exist after shifting 1 month: ' +
        '2020-02-31 is not a valid date')
    end

    test 'rejects an impossible month end after a year shift' do

      assert_error(
        lambda {
          Fugit.parse('1y').add(
            ::EtOrbi::EoTime.parse('2020-02-29 12:00 UTC'),
            end_of_month: :reject)
        },
        ArgumentError,
        '2020-02-29 does not exist after shifting 1 year: ' +
        '2021-02-29 is not a valid date')
    end

    test 'rejects an unknown month-end policy' do

      assert_error(
        lambda {
          Fugit.parse('1M').add(
            ::EtOrbi::EoTime.parse('2020-01-31 12:00 UTC'),
            end_of_month: :nope)
        },
        ArgumentError,
        'unknown month-end policy :nope, expected :clamp, :roll, ' +
        'or :reject')
    end

    [
      [ '1M', '2020-01-31 12:00 UTC', '2020-02-29 12:00 UTC',
        '2020-01-29 12:00 UTC' ],
      [ '1y', '2020-02-29 12:00 UTC', '2021-02-28 12:00 UTC',
        '2020-02-28 12:00 UTC' ],
      [ '1M', '2020-01-31 12:00 UTC', '2020-03-02 12:00 UTC',
        '2020-02-02 12:00 UTC' ],
    ].each do |ds, from, forward, back|

      test "does not guarantee reversibility for #{ds}" do

        d = Fugit.parse(ds)
        t0 = ::EtOrbi::EoTime.parse(from)
        policy = forward.include?('-03-') ? :roll : :clamp
        t1 = d.add(t0, end_of_month: policy)
        t2 = (-d).add(t1, end_of_month: policy)

        assert t1.to_s, ::EtOrbi::EoTime.parse(forward).to_s
        assert t2.to_s, ::EtOrbi::EoTime.parse(back).to_s
      end
    end

    test 'fixed days cross a spring-forward DST transition as elapsed time' do

      t = Fugit.parse('1d').add(
        ::EtOrbi::EoTime.parse('2021-03-13 12:00:00 America/New_York'))

      assert t.to_s, '2021-03-14 13:00:00 -0400'
      assert t.zone.canonical_identifier, 'America/New_York'
    end

    test 'calendar months preserve wall clock time across a DST boundary' do

      t = Fugit.parse('1M').add(
        ::EtOrbi::EoTime.parse('2021-02-14 12:00:00 America/New_York'))

      assert t.to_s, '2021-03-14 12:00:00 -0400'
      assert t.zone.canonical_identifier, 'America/New_York'
    end

    test 'reports a nonexistent local time after a calendar month shift' do

      assert_error(
        lambda {
          Fugit.parse('1M').add(
            ::EtOrbi::EoTime.parse('2021-02-14 02:30:00 America/New_York'))
        },
        ::TZInfo::PeriodNotFound)
    end

    test 'reports an ambiguous local time after a calendar month shift' do

      assert_error(
        lambda {
          Fugit.parse('1M').add(
            ::EtOrbi::EoTime.parse('2021-10-07 01:30:00 America/New_York'))
        },
        ::TZInfo::AmbiguousTime)
    end
    end

    test 'preserves the zone of an EoTime instance (local)' do

      t = ::EtOrbi::EoTime.now
      t1 = Fugit.parse('1Y2M3m') + t

      assert t1.zone, t.zone
    end

    test 'preserves the zone of an EoTime instance (UTC)' do

      t = ::EtOrbi::EoTime.parse('2017-06-22 00:00:00 UTC')
      t1 = Fugit.parse('1Y2M3m') + t

      assert t1.zone.canonical_identifier, 'UTC'
    end
  end

  group '#subtract' do

    test 'subtracts Numeric instances' do

      d = Fugit.parse('1Y2h')

      assert d.add(-1).to_plain_s, '1Y2h-1s'
      assert (d + -1).to_plain_s, '1Y2h-1s'
      assert (d - 1).to_plain_s, '1Y2h-1s'

      assert (d - 1).deflate.to_plain_s, '1Y1h59m59s'
    end

    test 'subtracts Duration instances' do

      d0 = Fugit.parse('1Y2h')
      d1 = Fugit.parse('1Y2h1s')

      assert d0.subtract(d1).to_plain_s, '-1s'
      assert (d0 + -d1).to_plain_s, '-1s'
      assert (d0 - d1).to_plain_s, '-1s'
    end

    test 'subtracts String instances (parses them as Duration)' do

      d = Fugit.parse('1Y2h')
      s = '1Y-1h1s'

      assert d.subtract(s).to_plain_s, '3h1s'
      assert (d - s).to_plain_s, '3h1s'
    end

    test 'subtracts Time instances' do

      d = Fugit.parse('1Y2h')
      t = Time.parse('2016-02-02T11:11:11Z')

      assert(
        Fugit.time_to_plain_s(d.subtract(t), false),
        '2015-02-02 09:11:11')
      assert(
        Fugit.time_to_plain_s(d - t, false),
        '2015-02-02 09:11:11')
    end

    test 'fails else' do

      d = Fugit.parse('1Y2h')
      x = false

      assert_error(
        lambda { d.subtract(x) },
        ArgumentError,
        'cannot subtract FalseClass instance to a Fugit::Duration')
      assert_error(
        lambda { d - x },
        ArgumentError,
        'cannot subtract FalseClass instance to a Fugit::Duration')
    end
  end

  group '#==' do

    test 'returns true when equal' do

      assert(
        Fugit::Duration.new('1Y2m') ==
        Fugit::Duration.new('1Y2m'))

      assert(
        Fugit::Duration.new('1Y2m') ==
        Fugit::Duration.new('2m1Y'))
    end

    test 'returns false else' do

      assert(
        Fugit::Duration.new('1Y2m') == Fugit::Duration.new('1Y3m'),
        false)
      assert(
        Fugit::Duration.new('1Y2m') != Fugit::Duration.new('1Y3m'),
        true)
      assert(
        Fugit::Duration.new('1Y2m') == 1,
        false)
      assert(
        Fugit::Duration.new('1Y2m') != 1,
        true)
    end
  end

  group '#to_long_s' do

    [
      [ '1M1Y1M3h', '2 months, 1 year, and 3 hours' ],
      [ '1Y1M3h', '1 year, 1 month, and 3 hours' ],
    ].each do |duration, long|

      test "renders #{duration.inspect} as #{long.inspect}" do

        assert Fugit::Duration.parse(duration).to_long_s, long
      end
    end

    test 'understands the oxford: false option' do

      assert(
        Fugit::Duration.parse('1Y1M3h').to_long_s(oxford: false),
        '1 year, 1 month and 3 hours')
    end
  end

  group '#to_rufus_h' do

    [

      [ '1y2M', { :y => 1, :M => 2 } ],
      [ '1M1y1M', { :M => 2, :y => 1 } ],
      [ '10d10h', { :d => 10, :h => 10 } ],
      [ '100s', { :s => 100 } ],

      [ '-1y-2M', { :y => -1, :M => -2 } ],
      [ '1M-1y-1M', { :y => -1 } ],

      [ '-1y+2M', { :y => -1, :M => 2 } ],
      [ '1M+1y-1M', { :y => 1 } ],

      [ '1y 2M', { :y => 1, :M => 2 } ],
      [ '1M 1y  1M', { :y => 1, :M => 2 } ],
      [ ' 1M1y1M ', { :y => 1, :M => 2 } ],

      [ '1 year and 2 months', { :y => 1, :M => 2 } ],
      [ '1 y, 2 M, and 2 months', { :y => 1, :M => 4 } ],
      [ '1 y, 2 M and 2 m', { :y => 1, :M => 2, :m => 2 } ],

      [ 'P1Y2M', { :y => 1, :M => 2} ],
      [ 'P10DT10H', { :d => 10, :h => 10 } ],
      [ 'PT100S', { :s => 100 } ],

      [ 'P-1Y-2M', { :y => -1, :M => -2 } ],
      [ 'p1M-1y-1Mt-1M', { :y => -1, :m => -1 } ],

      [ '1.4s', { :s => 1.4 } ],
      [ 'PT1.5S', { :s => 1.5 } ],
      [ '.4s', { :s => 0.4 } ],
      [ 'PT.5S', { :s => 0.5 } ],

      [ '1.0d1.0w1.0d', { :w => 1.0, :d => 2.0 } ],

      [ '-5.s', { :s => -5.0 } ],

      [ '7d7', { :d => 7, :s => 7 } ],
      [ '7', { :s => 7 } ],
      [ '0.3', { :s => 0.3 } ],
      [ '0.1s0.3', { :s => 0.4 } ],

    ].each do |d, h|

      test "renders #{d.inspect} as #{h.inspect}" do

        assert Fugit::Duration.parse(d).to_rufus_h, h
      end
    end
  end

  group '#next_time' do

    test 'accepts duration application options' do

      t = Fugit.parse('1M').next_time(
        ::EtOrbi::EoTime.parse('2020-01-31 12:00 UTC'),
        end_of_month: :clamp)

      assert t.to_s, '2020-02-29 12:00:00 Z'
    end

    test 'returns now + this duration if no argument' do

      t0 = Time.parse('2024-03-01 12:00')
      d = Fugit::Duration.new('1Y')
      t = d.next_time(t0)

      assert t.class, ::EtOrbi::EoTime

      assert t.strftime('%Y-%m-%d'), '2025-03-01'
    end

    test 'returns arg + this duration' do

      d = Fugit::Duration.new('1Y')
      t = d.next_time(Time.parse('2016-12-31'))

      assert t.class, ::EtOrbi::EoTime
      assert Fugit.time_to_plain_s(t, false), '2017-12-31 00:00:00'
    end
  end

  group '#drop_seconds' do

    [
      [ '1M10s', { mon: 1, sec: 10 }, { mon: 1 } ],
      [ '1M', { mon: 1 }, { mon: 1 } ],
      [ 0, { sec: 0 }, { min: 0 } ],
    ].each do |src, h0, h1|

      test "returns a copy of the duration without its seconds (#{src})" do

        d = Fugit::Duration.parse(src)
        d1 = d.drop_seconds

        assert d.h, h0
        assert d1.h, h1
      end
    end
  end

  group '.to_plain_s(o)' do

    test 'works' do

      assert Fugit::Duration.to_plain_s(1000), '16m40s'
      assert Fugit::Duration.to_plain_s('100d'), '14W2D'
    end
  end

  group '.to_iso_s(o)' do

    test 'works' do

      assert Fugit::Duration.to_iso_s(1000), 'PT16M40S'
      assert Fugit::Duration.to_iso_s('100d'), 'P14W2D'
      assert Fugit::Duration.to_iso_s('77d88s'), 'P11WT1M28S'
    end

    test 'may fail with an ArgumentError' do

      assert_error(
        lambda { Fugit::Duration.to_iso_s('77d88k') },
        ArgumentError, 'not a duration "77d88k"')
    end
  end

  group '.to_long_s(o)' do

    test 'works' do

      assert Fugit::Duration.to_long_s(1000), '16 minutes, and 40 seconds'
      assert Fugit::Duration.to_long_s('100d'), '14 weeks, and 2 days'
    end
  end
end
