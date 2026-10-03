# encoding: utf-8

module I18n
  module Tests
    module Localization
      module Range
        def setup
          super
          setup_range_translations
          @start_date = ::Date.new(2008, 3, 10)
        end

        test "localize_range Date: same day uses the same_day pattern" do
          assert_equal '10.03.2008', I18n.localize_range(@start_date, ::Date.new(2008, 3, 10), :locale => :de)
        end

        test "localize_range Date: same month uses the same_month pattern" do
          assert_equal '10 – 12.03.2008', I18n.localize_range(@start_date, ::Date.new(2008, 3, 12), :locale => :de)
        end

        test "localize_range Date: different month in the same year uses the different_month pattern" do
          assert_equal '10.03 – 05.04.2008', I18n.localize_range(@start_date, ::Date.new(2008, 4, 5), :locale => :de)
        end

        test "localize_range Date: different year uses the different_year pattern" do
          assert_equal '10.03.2008 – 15.05.2009', I18n.localize_range(@start_date, ::Date.new(2009, 5, 15), :locale => :de)
        end

        test "localize_range: accepts a Range object" do
          assert_equal '10 – 12.03.2008', I18n.localize_range(@start_date..::Date.new(2008, 3, 12), :locale => :de)
        end

        test "localize_range: a format without a year field treats the year as not displayed" do
          assert_equal '10. Mär – 05. Apr', I18n.localize_range(@start_date, ::Date.new(2009, 4, 5), :format => :short, :locale => :de)
        end

        test "localize_range: a day-only format never varies below the displayed day" do
          assert_equal '10 – 12', I18n.localize_range(@start_date, ::Date.new(2008, 3, 12), :format => '%d', :locale => :de)
        end

        test "localize_range: missing range patterns fall back to two full dates joined by the separator" do
          assert_equal '10. März 2008 – 12. März 2008', I18n.localize_range(@start_date, ::Date.new(2008, 3, 12), :format => :long, :locale => :de)
        end

        test "localize_range: a raw format string falls back to two full dates" do
          assert_equal '10.03.2008 – 12.03.2008', I18n.localize_range(@start_date, ::Date.new(2008, 3, 12), :format => '%d.%m.%Y', :locale => :de)
        end

        test "localize_range: uses the locale separator" do
          I18n.backend.store_translations :fr, {
            :date => {
              :formats => { :default => "%d.%m.%Y" },
              :range_separator => ' bis ',
              :ranges => {
                :default => { :same_month => ["%d", "%d.%m.%Y"] }
              }
            }
          }
          assert_equal '10 bis 12.03.2008',
            I18n.localize_range(@start_date, ::Date.new(2008, 3, 12), :locale => :fr)
        end

        test "localize_range: falls back to two full dates when the variant is missing" do
          assert_equal '10.03.2008 – 15.05.2009',
            I18n.localize_range(@start_date, ::Date.new(2009, 5, 15), :format => :compact, :locale => :de)
        end

        test "localize_range: same-year same-month ranges across years are classified by the most significant displayed difference" do
          assert_equal '03.2008 – 03.2009', I18n.localize_range(::Date.new(2008, 3, 10), ::Date.new(2009, 3, 10), :format => '%m.%Y', :locale => :de)
        end

        test "localize_range Time: same day uses the time same_day pattern" do
          start_time = ::Time.utc(2008, 3, 10, 6)
          end_time = ::Time.utc(2008, 3, 10, 18)
          assert_equal '10.03.2008 06:00 – 18:00', I18n.localize_range(start_time, end_time, :format => :short, :locale => :de)
        end

        test "localize_range Time: different days use the date granularity patterns" do
          start_time = ::Time.utc(2008, 3, 10, 6)
          end_time = ::Time.utc(2008, 3, 12, 18)
          assert_equal '10.03 06:00 – 12.03 18:00 2008', I18n.localize_range(start_time, end_time, :format => :short, :locale => :de)
        end

        test "localize_range: raises when the start is later than the end based on the actual instants" do
          assert_raises(ArgumentError) do
            I18n.localize_range(::Time.utc(2008, 3, 2, 0), ::Time.utc(2008, 3, 1, 23), :locale => :de)
          end
        end

        test "localize_range: equal instants in different zones are ordered as equal and rendered together" do
          start_time = ::Time.utc(2008, 3, 1, 23)
          end_time = ::DateTime.civil(2008, 3, 2, 1, 0, 0, '+02:00')
          assert_equal '02.03.2008 01:00 – 01:00', I18n.localize_range(start_time, end_time, :format => :short, :time_zone => '+02:00', :locale => :de)
        end

        test "localize_range: raises without a time zone when the ends use different offsets" do
          start_time = ::Time.utc(2008, 3, 10, 6)
          end_time = ::DateTime.civil(2008, 3, 10, 8, 0, 0, '+02:00')
          error = assert_raises(ArgumentError) do
            I18n.localize_range(start_time, end_time, :locale => :de)
          end
          assert_match(/different time zones/, error.message)
        end

        test "localize_range: renders both ends in the explicitly given time zone" do
          start_time = ::Time.utc(2008, 3, 10, 23)
          end_time = ::Time.utc(2008, 3, 11, 1, 0)
          assert_equal '11.03.2008 08:00 – 10:00',
            I18n.localize_range(start_time, end_time, :format => :short, :time_zone => '+09:00', :locale => :de)
        end

        test "localize_range: an integer offset is accepted as the rendering time zone" do
          start_time = ::Time.utc(2008, 3, 10, 6)
          end_time = ::Time.utc(2008, 3, 10, 8)
          assert_equal '10.03.2008 08:00 – 10:00',
            I18n.localize_range(start_time, end_time, :format => :short, :time_zone => 7200, :locale => :de)
        end

        test "localize_range: ends with the same offset keep their zone" do
          start_time = ::Time.utc(2008, 3, 10, 6).getlocal('+02:00')
          end_time = ::Time.utc(2008, 3, 10, 8).getlocal('+02:00')
          assert_equal '10.03.2008 08:00 – 10:00', I18n.localize_range(start_time, end_time, :format => :short, :locale => :de)
        end

        test "localize_range: raises on a reversed date range" do
          assert_raises(ArgumentError) do
            I18n.localize_range(::Date.new(2008, 4, 1), ::Date.new(2008, 3, 1), :locale => :de)
          end
        end

        test "localize_range: raises on non date/time objects" do
          assert_raises(I18n::ArgumentError) do
            I18n.localize_range(Object.new, @start_date, :locale => :de)
          end
        end

        test "localize_range: given an unknown format it raises I18n::MissingTranslationData" do
          assert_raises(I18n::MissingTranslationData) do
            I18n.localize_range(@start_date, ::Date.new(2008, 3, 12), :format => :missing, :locale => :de)
          end
        end

        test "localize_range: does not modify the options hash" do
          options = { :locale => :de, :time_zone => '+09:00' }
          I18n.localize_range(::Time.utc(2008, 3, 10, 6), ::Time.utc(2008, 3, 10, 8), **options)
          assert_equal({ :locale => :de, :time_zone => '+09:00' }, options)
        end

        test "single localize is unaffected by range support" do
          assert_equal '10.03.2008', I18n.l(@start_date, :locale => :de)
          assert_equal '10. März 2008', I18n.l(@start_date, :format => :long, :locale => :de)
        end

        test "localize_range: a format that resolves to a Proc falls back to two fully localized values" do
          setup_time_proc_translations
          date = ::Date.new(2008, 3, 1)
          result = I18n.localize_range(date, ::Date.new(2008, 3, 3), :format => :proc, :locale => :ru)
          assert_equal '[Sat, 01 Mar 2008, {}] – [Mon, 03 Mar 2008, {}]', result
        end

        protected

          def setup_range_translations
            I18n.backend.store_translations :de, {
              :date => {
                :formats => {
                  :default => "%d.%m.%Y",
                  :long => "%d. %B %Y",
                  :short => "%d. %b",
                  :compact => "%d.%m.%Y"
                },
                :ranges => {
                  :default => {
                    :same_day => ["%d.%m.%Y", ""],
                    :same_month => ["%d", "%d.%m.%Y"],
                    :different_month => ["%d.%m", "%d.%m.%Y"],
                    :different_year => ["%d.%m.%Y", "%d.%m.%Y"]
                  },
                  :short => {
                    :same_month => ["%d.", "%d. %b"],
                    :different_month => ["%d. %b", "%d. %b"],
                    :different_year => ["%d. %b %Y", "%d. %b %Y"]
                  }
                },
                :day_names => %w(Sonntag Montag Dienstag Mittwoch Donnerstag Freitag Samstag),
                :abbr_day_names => %w(So Mo Di Mi Do Fr  Sa),
                :month_names => %w(Januar Februar März April Mai Juni Juli August September Oktober November Dezember).unshift(nil),
                :abbr_month_names => %w(Jan Feb Mär Apr Mai Jun Jul Aug Sep Okt Nov Dez).unshift(nil)
              },
              :time => {
                :formats => {
                  :default => "%a, %d. %b %Y %H:%M:%S %z",
                  :short => "%d. %b %H:%M",
                  :long => "%d. %B %Y %H:%M"
                },
                :ranges => {
                  :short => {
                    :same_day => ["%d.%m.%Y %H:%M", "%H:%M"],
                    :same_month => ["%d.%m %H:%M", "%d.%m %H:%M %Y"],
                    :different_month => ["%d.%m %H:%M", "%d.%m %H:%M %Y"],
                    :different_year => ["%d.%m.%Y %H:%M", "%d.%m.%Y %H:%M"]
                  }
                },
                :am => 'am',
                :pm => 'pm'
              }
            }

            I18n.backend.store_translations :de, {
              :date => {
                :ranges => {
                  :compact => {
                    :same_month => ["%d", "%d.%m.%Y"]
                  }
                }
              }
            }
          end
      end
    end
  end
end
