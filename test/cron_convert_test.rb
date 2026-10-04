
group Fugit do

  group '.convert_cron' do

    test 'requires an explicit source dialect' do

      assert_error(lambda { Fugit.convert_cron('0 0 * * *') }, ArgumentError)
    end

    test 'rejects unknown dialects' do

      assert_error(
        lambda { Fugit.convert_cron('0 0 * * *', from: :standard) },
        ArgumentError)
    end

    test 'converts Unix five-field cron without changing parse behavior' do

      r = Fugit.convert_cron('5 0 * * *', from: :unix)

      assert_true r[:ok]
      assert r[:source_dialect], :unix
      assert r[:expression], '5 0 * * *'
      assert r[:cron].class, Fugit::Cron
      assert_nil Fugit::Cron.parse('0 0 12 15 * ?')
    end

    test 'preserves seconds when converting Quartz' do

      r = Fugit.convert_cron('10,20 0 12 ? * MON-FRI', from: :quartz)

      assert_true r[:ok]
      assert r[:expression], '10,20 0 12 * * 1,2,3,4,5'
      assert r[:cron].seconds, [ 10, 20 ]
    end

    [

      [ '0 0 12 ? * MON-FRI', '0 0 12 * * 1,2,3,4,5' ],
      [ '0 0 12 ? * 2-6',      '0 0 12 * * 1,2,3,4,5' ],
      [ '0 0 12 15 * ?',       '0 0 12 15 * *' ],
      [ '0 0 12 L * ?',        '0 0 12 -1 * *' ],
      [ '0/15 0 8 ? JAN-MAR MON-FRI', '0,15,30,45 0 8 * 1,2,3 1,2,3,4,5' ],

    ].each do |source, target|

      test "converts #{source.inspect}" do

        r = Fugit.convert_cron(source, from: :quartz)

        assert_true r[:ok]
        assert r[:expression], target
      end
    end

    test 'uses Fugit AND when both Quartz day fields are restricted' do

      source = '0 0 12 10-16 * FRI'
      r = Fugit.convert_cron(source, from: :quartz)

      assert_true r[:ok]
      assert r[:expression], '0 0 12 10,11,12,13,14,15,16 * 5&'

      cron = r[:cron]
      offset = Time.now.utc_offset
      assert_true cron.match?(Time.new(2024, 5, 10, 12, 0, 0, offset))
      assert_not cron.match?(Time.new(2024, 5, 11, 12, 0, 0, offset))
      assert_not cron.match?(Time.new(2024, 5, 17, 12, 0, 0, offset))
    end

    test 'converts nth and last weekday occurrences' do

      first = Fugit.convert_cron('0 0 12 ? * MON#1', from: :quartz)
      last = Fugit.convert_cron('0 0 12 ? * 6L', from: :quartz)

      assert first[:expression], '0 0 12 * * 1#1'
      assert last[:expression], '0 0 12 * * 5#-1'
      offset = Time.now.utc_offset
      assert_true first[:cron].match?(Time.new(2024, 1, 1, 12, 0, 0, offset))
      assert_not first[:cron].match?(Time.new(2024, 1, 8, 12, 0, 0, offset))
      assert_true last[:cron].match?(Time.new(2024, 1, 26, 12, 0, 0, offset))
      assert_not last[:cron].match?(Time.new(2024, 1, 19, 12, 0, 0, offset))
    end

    [

      [ '0 0 12 15W * ?', :unsupported_feature, :day_of_month, 3, 8 ],
      [ '0 0 12 LW * ?', :unsupported_feature, :day_of_month, 3, 8 ],
      [ '0 0 12 ? * 1C', :unsupported_feature, :day_of_week, 5, 12 ],
      [ '0 0 12 15 * ? 2024', :unsupported_year, :year, 6, 15 ],
      [ '0 0 12 15 * ? 2024-2025', :unsupported_year, :year, 6, 15 ],
      [ '0 0 12 ? * ?', :unsupported_day_combination, :day_of_week, 5, 12 ],
      [ '0 0 12 * * *', :unsupported_day_combination, :day_of_week, 5, 12 ],
      [ '0 0 12 32 * ?', :unsupported_syntax, :day_of_month, 3, 8 ],
      [ '0 0 12 15 * ? 1999-2999', :unsupported_year, :year, 6, 15 ],

    ].each do |source, code, field, index, column|

      test "retains position for #{source.inspect}" do

        r = Fugit.convert_cron(source, from: :quartz)

        assert_false r[:ok]
        assert_nil r[:expression]
        assert r[:source], source
        assert r[:errors].first[:code], code
        assert r[:errors].first[:field], field
        assert r[:errors].first[:field_index], index
        assert r[:errors].first[:column], column
      end
    end

    test 'retains an external base position in structured errors' do

      source = '0 0 12 15 * ? 2024'
      r = Fugit.convert_cron(source, from: :quartz, base_position: 10)

      assert_false r[:ok]
      assert r[:errors].first[:position], 24
      assert r[:errors].first[:column], 25
    end

    test 'supports dialect aliases' do

      r = Fugit.convert_cron('0 0 12 15 * ?', dialect: 'quartz')

      assert_true r[:ok]
      assert r[:expression], '0 0 12 15 * *'
    end

    test 'do_convert_cron raises a structured conversion error' do

      assert_error(
        lambda { Fugit.do_convert_cron('0 0 12 15 * ? 2024', from: :quartz) },
        Fugit::CronConversionError)
    end
  end
end
