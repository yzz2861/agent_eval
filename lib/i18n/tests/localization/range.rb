# encoding: utf-8

module I18n
  module Tests
    module Localization
      module Range
        def setup
          super
          setup_range_translations
        end

        test "localize range: uses same day formats for equal dates" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 3, 1)
          assert_equal '01.03.2008', I18n.l_range(range, :locale => :de)
        end

        test "localize range: uses same month formats for different days in one month" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 3, 8)
          assert_equal '01–08.03.2008', I18n.l_range(range, :locale => :de)
        end

        test "localize range: uses cross month formats for different months in one year" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 5, 8)
          assert_equal '01.03 – 08.05.2008', I18n.l_range(range, :locale => :de)
        end

        test "localize range: uses cross year formats for different years" do
          range = ::Date.new(2008, 12, 20)..::Date.new(2009, 1, 5)
          assert_equal '20.12.2008 – 05.01.2009', I18n.l_range(range, :locale => :de)
        end

        test "localize range: chooses the first displayed field that differs" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 5, 8)
          assert_equal 'März – Mai', I18n.l_range(range, :format => :month_only, :locale => :de)
        end

        test "localize range: falls back to two complete dates when a range pattern is missing" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 5, 8)
          assert_equal '01.03 - 08.05', I18n.l_range(range, :format => :plain, :locale => :range_test)
        end

        test "localize range: supports hash patterns with explicit endpoints" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 3, 8)
          assert_equal '1. – 8. März', I18n.l_range(range, :format => :wordy, :locale => :de)
        end

        test "localize range: supports Range arguments and separate arguments" do
          range = ::Date.new(2008, 3, 1)..::Date.new(2008, 3, 8)
          assert_equal I18n.l_range(range, :locale => :de), I18n.l_range(range.begin, range.end, :locale => :de)
          assert_equal I18n.l_range(range, :locale => :de), I18n.l(range, :locale => :de)
        end

        test "localize range: uses same day time formats for equal calendar days in an explicit time zone" do
          start_time = ::Time.utc(2008, 3, 1, 23, 0)
          end_time = ::Time.new(2008, 3, 2, 7, 0, 0, '+08:00')
          assert_equal '01.03 23:00–23:00', I18n.l_range(start_time, end_time, :format => :range_default, :time_zone => '+00:00', :locale => :de)
        end

        test "localize range: converts DateTime endpoints to the explicit time zone" do
          start_time = ::DateTime.new(2008, 3, 1, 23, 0, 0, '+00:00')
          end_time = ::DateTime.new(2008, 3, 2, 7, 0, 0, Rational(8, 24))
          assert_equal '01.03 23:00–23:00', I18n.l_range(start_time, end_time, :format => :range_default, :time_zone => '+00:00', :locale => :de)
        end

        test "localize range: interprets a Date endpoint in the explicit time zone" do
          start_date = ::Date.new(2008, 3, 1)
          end_time = ::Time.utc(2008, 3, 1, 23, 0)
          assert_equal '01.03 00:00–23:00', I18n.l_range(start_date, end_time, :format => :range_default, :time_zone => '+00:00', :locale => :de)
        end

        test "localize range: requires a time zone when endpoint offsets differ" do
          start_time = ::Time.utc(2008, 3, 1, 23, 0)
          end_time = ::Time.new(2008, 3, 2, 7, 0, 0, '+08:00')
          error = assert_raises(ArgumentError) { I18n.l_range(start_time, end_time, :locale => :de) }
          assert_match(/different time zones/, error.message)
        end

        test "localize range: compares actual time before selecting a calendar mode" do
          start_time = ::Time.new(2008, 3, 2, 7, 0, 0, '+08:00')
          end_time = ::Time.utc(2008, 3, 1, 23, 0)
          assert_equal '02.03 07:00–07:00', I18n.l_range(start_time, end_time, :format => :range_default, :time_zone => '+08:00', :locale => :de)
        end

        test "localize range: raises when the actual start time is later than the end time" do
          start_time = ::Time.utc(2008, 3, 1, 23, 0)
          end_time = ::Time.new(2008, 3, 2, 6, 0, 0, '+08:00')
          error = assert_raises(ArgumentError) do
            I18n.l_range(start_time, end_time, :format => :range_default, :time_zone => '+00:00', :locale => :de)
          end
          assert_match(/start must be earlier/, error.message)
        end

        protected

          def setup_range_translations
            I18n.backend.store_translations :de, {
              :date => {
                :formats => {
                  :default => '%d.%m.%Y',
                  :month_only => '%B',
                  :wordy => '%d. %B'
                },
                :day_names => %w(Sonntag Montag Dienstag Mittwoch Donnerstag Freitag Samstag),
                :abbr_day_names => %w(So Mo Di Mi Do Fr Sa),
                :month_names => %w(Januar Februar März April Mai Juni Juli August September Oktober November Dezember).unshift(nil),
                :abbr_month_names => %w(Jan Feb Mär Apr Mai Jun Jul Aug Sep Okt Nov Dez).unshift(nil),
                :range_formats => {
                  :default => {
                    :same_day => ['%d.%m.%Y', nil],
                    :same_month => ['%d', '–%d.%m.%Y'],
                    :cross_month => ['%d.%m', ' – %d.%m.%Y'],
                    :cross_year => ['%d.%m.%Y', ' – %d.%m.%Y']
                  },
                  :month_only => {
                    :cross_month => {
                      :template => '%{start} – %{end}',
                      :start => :month_only,
                      :end => :month_only
                    }
                  },
                  :wordy => {
                    :same_month => {
                      :start => '%-d.',
                      :end => '%-d. %B',
                      :template => '%{start} – %{end}'
                    }
                  }
                }
              },
              :time => {
                :formats => {
                  :range_default => '%d.%m %H:%M'
                },
                :am => 'am',
                :pm => 'pm',
                :range_formats => {
                  :range_default => {
                    :same_day => ['%d.%m %H:%M', '–%H:%M']
                  }
                }
              }
            }

            I18n.backend.store_translations :range_test, {
              :date => {
                :formats => {
                  :plain => '%d.%m'
                },
                :range_formats => {
                  :plain => {
                    :same_day => ['%d.%m', nil],
                    :same_month => ['%d', '–%d.%m'],
                    :cross_year => ['%d.%m', ' – %d.%m']
                  }
                }
              }
            }
          end
      end
    end
  end
end
