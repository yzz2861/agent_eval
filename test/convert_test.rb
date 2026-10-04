
#
# Specifying fugit
#


group Fugit do

  group '.convert_cron' do

    group 'from: :unix' do

      {
        '* * * * *' => '* * * * *',
        '5 0 * * *' => '5 0 * * *',
        '30 4 1,15 * 5' => '30 4 1,15 * 5',
        '0 0 1 jan mon' => '0 0 1 1 1',
        '0 0 * * 7' => '0 0 * * 0',
        '0 0 * * sun' => '0 0 * * 0',
        '0 0 29 2 *' => '0 0 29 2 *',
        '0 0 * * 5-7' => '0 0 * * 0,5,6',

      }.each do |src, cron_s|

        test "converts #{src.inspect} to #{cron_s.inspect}" do

          c = Fugit.convert_cron(src, from: :unix)

          assert c.class, Fugit::Cron
          assert c.to_cron_s, cron_s
        end
      end

      test 'keeps the unix OR day semantics' do

        c = Fugit.convert_cron('30 4 1,15 * 5', from: :unix)

        in_zone('UTC') do
          assert c.next_time(Time.utc(2017, 1, 3)).to_s,
            '2017-01-06 04:30:00 Z'
        end
      end

      test 'rejects a 6-field string and hints at the quartz dialect' do

        r = Fugit.convert_cron('0 5 0 * * *', from: :unix)

        assert r.class, Fugit::Convert::Error
        assert r.dialect, :unix
        assert r.issues.first[:reason].match?(/quartz/), true
      end

      test 'rejects a 4-field string' do

        r = Fugit.convert_cron('0 0 * *', from: :unix)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:reason].match?(/expected 5 fields/), true
      end

      test 'rejects ? and keeps its original position' do

        r = Fugit.convert_cron('0 0 ? * *', from: :unix)

        assert r.class, Fugit::Convert::Error

        i = r.issues.first
        assert i[:field], :day_of_month
        assert i[:index], 2
        assert i[:offset], 4
        assert i[:value], '?'
        assert r.input[i[:offset], i[:value].length], i[:value]
      end

      test 'rejects out of range values' do

        r = Fugit.convert_cron('0 0 32 * *', from: :unix)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:reason].match?(/out of range/), true
      end

      test 'rejects non-strings' do

        r = Fugit.convert_cron(nil, from: :unix)

        assert r.class, Fugit::Convert::Error
      end
    end

    group 'from: :quartz' do

      {
        '0 0 12 ? * MON' => '0 12 * * 1',
        '0 0 12 ? * 2' => '0 12 * * 1',
        '0 0 12 ? * MON-FRI' => '0 12 * * 1,2,3,4,5',
        '0 0 12 ? * MON,WED,FRI' => '0 12 * * 1,3,5',
        '15 30 8 ? * 2-6' => '15 30 8 * * 1,2,3,4,5',
        '0 0 12 1 * ?' => '0 12 1 * *',
        '0 0 12 L * ?' => '0 12 -1 * *',
        '0 0 12 L-3 * ?' => '0 12 -3 * *',
        '0 0 12 ? * 6L' => '0 12 * * 5#-1',
        '0 0 12 ? * 6#3' => '0 12 * * 5#3',
        '0 0 12 ? * L' => '0 12 * * 6',
        '0 0 12 ? * 7' => '0 12 * * 6',
        '0 0 12 1 JAN ?' => '0 12 1 1 *',
        '*/20 * * * * ?' => '0,20,40 * * * * *',
        '0 0/15 8 * * ?' => '0,15,30,45 8 * * *',
        '0 0 12 * * ?' => '0 12 * * *',
        '0 0 12 * * ? *' => '0 12 * * *',
        '0 0 12 29 2 ?' => '0 12 29 2 *',

      }.each do |src, cron_s|

        test "converts #{src.inspect} to #{cron_s.inspect}" do

          c = Fugit.convert_cron(src, from: :quartz)

          assert c.class, Fugit::Cron
          assert c.to_cron_s, cron_s
        end
      end

      test 'keeps the seconds' do

        c = Fugit.convert_cron('*/20 * * * * ?', from: :quartz)

        assert c.seconds, [ 0, 20, 40 ]

        in_zone('UTC') do
          nts = c.next(Time.utc(2025, 1, 1)).take(3).collect(&:to_s)
          assert nts, [
            '2025-01-01 00:00:20 Z',
            '2025-01-01 00:00:40 Z',
            '2025-01-01 00:01:00 Z' ]
        end
      end

      test 'fires at the expected weekdays' do

        c = Fugit.convert_cron('0 30 9 ? * MON-FRI', from: :quartz)

        in_zone('UTC') do
          nts = c.next(Time.utc(2025, 1, 2)).take(3).collect(&:to_s)
          assert nts, [
            '2025-01-02 09:30:00 Z',
            '2025-01-03 09:30:00 Z',
            '2025-01-06 09:30:00 Z' ]
        end
      end

      test 'fires on the nth weekday of the month' do

        c = Fugit.convert_cron('0 0 9 ? * 6#3', from: :quartz)

        in_zone('UTC') do
          assert c.next_time(Time.utc(2025, 1, 1)).to_s, '2025-01-17 09:00:00 Z'
        end
      end

      test 'fires on the last weekday of the month' do

        c = Fugit.convert_cron('0 0 9 ? * 6L', from: :quartz)

        in_zone('UTC') do
          assert c.next_time(Time.utc(2025, 1, 1)).to_s, '2025-01-31 09:00:00 Z'
        end
      end

      test 'fires on the last day of the month' do

        c = Fugit.convert_cron('0 0 9 L * ?', from: :quartz)

        in_zone('UTC') do
          assert c.next_time(Time.utc(2025, 2, 1)).to_s, '2025-02-28 09:00:00 Z'
        end
      end

      test 'rejects a bounded year and keeps its original position' do

        r = Fugit.convert_cron('0 0 12 ? * MON 2025', from: :quartz)

        assert r.class, Fugit::Convert::Error

        i = r.issues.first
        assert i[:field], :year
        assert i[:index], 6
        assert i[:offset], 15
        assert i[:value], '2025'
        assert r.input[i[:offset], i[:value].length], i[:value]
      end

      test 'rejects a year range' do

        r = Fugit.convert_cron('0 0 12 ? * MON 2020-2030', from: :quartz)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:field], :year
      end

      test 'rejects restricted day-of-month and day-of-week' do

        r = Fugit.convert_cron('0 0 12 1 * MON', from: :quartz)

        assert r.class, Fugit::Convert::Error
        assert r.issues.length, 2

        i0, i1 = r.issues

        assert i0[:field], :day_of_month
        assert i0[:index], 3
        assert i0[:offset], 7
        assert i0[:value], '1'

        assert i1[:field], :day_of_week
        assert i1[:index], 5
        assert i1[:offset], 11
        assert i1[:value], 'MON'
      end

      test 'rejects W forms' do

        r = Fugit.convert_cron('0 0 12 15W * ?', from: :quartz)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:field], :day_of_month
        assert r.issues.first[:reason].match?(/W/), true
      end

      test 'rejects ? outside of the day fields' do

        r = Fugit.convert_cron('? 0 12 * * MON', from: :quartz)

        assert r.class, Fugit::Convert::Error

        i = r.issues.first
        assert i[:field], :seconds
        assert i[:index], 0
        assert i[:offset], 0
      end

      test 'rejects out of range values' do

        r = Fugit.convert_cron('61 0 12 * * ?', from: :quartz)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:field], :seconds
        assert r.issues.first[:reason].match?(/out of range/), true
      end

      test 'rejects a 5-field string' do

        r = Fugit.convert_cron('0 12 * * MON', from: :quartz)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:reason].match?(/6 or 7/), true
      end

      test 'rejects wrap-around ranges' do

        r = Fugit.convert_cron('0 0 12 ? * FRI-MON', from: :quartz)

        assert r.class, Fugit::Convert::Error
        assert r.issues.first[:reason].match?(/wraps around/), true
      end
    end

    group '(dialect declaration)' do

      test 'requires a declared dialect' do

        assert_error(
          lambda { Fugit.convert_cron('* * * * *') },
          ArgumentError,
          /missing keyword/)
      end

      test 'rejects unknown dialects' do

        assert_error(
          lambda { Fugit.convert_cron('* * * * *', from: :cron) },
          ArgumentError,
          /unknown cron dialect/)
      end

      test 'leaves Fugit.parse_cron interpretation unchanged' do

        assert Fugit.parse_cron('0 0 12 ? * MON'), nil
        assert Fugit.parse_cron('0 0 12 * * 1').class, Fugit::Cron
        assert Fugit.parse_cron('0 0 12 * * 1').to_cron_s, '0 12 * * 1'
      end
    end
  end

  group '.do_convert_cron' do

    test 'returns the cron on success' do

      c = Fugit.do_convert_cron('0 0 12 ? * MON', from: :quartz)

      assert c.class, Fugit::Cron
      assert c.to_cron_s, '0 12 * * 1'
    end

    test 'raises the structured error on failure' do

      assert_error(
        lambda { Fugit.do_convert_cron('0 0 12 ? * MON 2025', from: :quartz) },
        Fugit::Convert::Error,
        /cannot convert quartz cron/)
    end
  end

  group Fugit::Convert::Error do

    test 'exposes input, dialect and issues' do

      r = Fugit.convert_cron('0 0 12 ? * MON 2025', from: :quartz)

      assert r.input, '0 0 12 ? * MON 2025'
      assert r.dialect, :quartz
      assert r.issues.class, Array
      assert r.message.match?(/cannot convert quartz cron/), true

      h = r.to_h
      assert h[:input], r.input
      assert h[:dialect], :quartz
      assert h[:issues], r.issues
    end
  end
end
