# frozen-string-literal: true
#
# The time_bucket extension supports truncating times to fixed-size
# intervals and to calendar months.  Load it into a database before using
# the expressions:
#
#   DB.extension :time_bucket
#
# Fixed-size intervals are specified as an integer number of seconds:
#
#   Sequel.time_bucket(:created_at, 900)
#   Sequel.time_bucket(:created_at, 900,
#     origin: Time.utc(2024, 1, 1), timezone: 'America/New_York')
#
# Calendar month intervals use a separate expression so they are never
# confused with fixed-length intervals:
#
#   Sequel.month_bucket(:created_at)
#   Sequel.month_bucket(:created_at, 3,
#     origin: Time.utc(2024, 1, 1), timezone: 'America/New_York')
#
# Returned objects are regular Sequel expressions, so they can be selected,
# aliased, grouped, ordered, and combined with other expressions.
#
# Related module: Sequel::SQL::TimeBucket

module Sequel
  module SQL
    module Builders
      # Return an expression that truncates +expr+ to fixed-width buckets
      # containing +seconds+ seconds.  +origin+ sets the bucket boundary used
      # for both future and past timestamps, and +timezone+ sets the calendar
      # timezone.
      def time_bucket(expr, seconds, origin: Time.utc(1970), timezone: nil)
        TimeBucket::Seconds.new(expr, seconds, origin, timezone)
      end

      # Return an expression that truncates +expr+ to calendar month buckets.
      # +months+ is the number of months in each bucket, and +origin+ sets the
      # month from which bucket numbering starts.
      def month_bucket(expr, months = 1, origin: Time.utc(1970), timezone: nil)
        TimeBucket::Months.new(expr, months, origin, timezone)
      end

      # Alias for #time_bucket, emphasizing that the interval is fixed seconds.
      alias fixed_seconds_bucket time_bucket

      # Alias for #month_bucket, emphasizing that the interval is calendar months.
      alias calendar_month_bucket month_bucket
    end

    # Namespace for time bucket expressions.
    module TimeBucket
      DEFAULT_TIMEZONE = 'UTC'.freeze

      # Shared behavior for time bucket expressions.
      class Base < GenericExpression
        attr_reader :expr, :interval, :origin, :timezone

        def initialize(expr, interval, origin, timezone)
          interval = typecast_interval(interval)
          origin = typecast_origin(origin)
          if interval.is_a?(Integer) && interval <= 0
            raise(Sequel::InvalidValue, "time bucket interval must be positive")
          end

          @expr = expr
          @interval = interval
          @origin = origin
          @timezone = timezone
          freeze
        end

        def to_s_append(dataset, sql)
          dataset.time_bucket_sql_append(sql, self)
        end

        def sequel_ast_transform(transformer)
          expression = transformer.call(expr)
          interval = transformer.call(self.interval)
          origin = self.origin.is_a?(SQL::Expression) ? transformer.call(self.origin) : self.origin
          timezone = transformer.call(self.timezone) unless self.timezone.nil?
          copy = self.class.allocate
          copy.instance_variable_set(:@expr, expression)
          copy.instance_variable_set(:@interval, interval)
          copy.instance_variable_set(:@origin, origin)
          copy.instance_variable_set(:@timezone, timezone)
          copy.freeze
        end

        private

        def typecast_interval(value)
          case value
          when Integer
            value
          when Symbol, SQL::Expression
            value
          when Numeric
            if value.to_i == value
              value.to_i
            else
              raise(Sequel::InvalidValue, "time bucket interval must be an integer")
            end
          else
            raise(Sequel::InvalidValue, "time bucket interval must be an integer")
          end
        end

        def typecast_origin(value)
          case value
          when Time, DateTime
            value.getutc
          when Symbol, SQL::Expression
            value
          when Date
            Time.utc(value.year, value.month, value.day)
          else
            raise(Sequel::InvalidValue, "time bucket origin must be a Time, DateTime, or Date")
          end
        end
      end

      # A bucket based on a fixed number of seconds.
      class Seconds < Base
      end

      # A bucket based on a number of calendar months.
      class Months < Base
      end

      # Methods added to datasets when the extension is loaded.
      module DatasetMethods
        def time_bucket_sql_append(sql, bucket)
          case db.database_type
          when :sqlite
            raise(InvalidOperation, "time bucket expressions are not supported on #{db.adapter_scheme}") unless db.adapter_scheme == :sqlite
            sqlite_time_bucket_sql_append(sql, bucket)
          when :postgres
            unless [:postgres, :postgresql, :mock].include?(db.adapter_scheme)
              raise(InvalidOperation, "time bucket expressions are not supported on #{db.adapter_scheme}")
            end
            postgres_time_bucket_sql_append(sql, bucket)
          else
            raise(InvalidOperation, "time bucket expressions are not supported on #{db.adapter_scheme}")
          end
        end

        private

        def sqlite_time_bucket_sql_append(sql, bucket)
          function = bucket.is_a?(Months) ? :sequel_month_bucket : :sequel_time_bucket
          arguments = [bucket.expr, bucket.interval, bucket.origin, bucket.timezone || TimeBucket::DEFAULT_TIMEZONE]
          sql << function.to_s << '('
          arguments.each_with_index do |argument, index|
            sql << ', ' unless index.zero?
            literal_append(sql, argument)
          end
          sql << ')'
        end

        def postgres_time_bucket_sql_append(sql, bucket)
          timezone = bucket.timezone || TimeBucket::DEFAULT_TIMEZONE
          if bucket.is_a?(Months)
            local = Sequel.lit('? AT TIME ZONE ?', bucket.expr, timezone)
            origin = Sequel.lit('? AT TIME ZONE ?', bucket.origin, timezone)
            origin_month = Sequel.function(:date_trunc, 'month', origin)
            months = postgres_month_index(local) - postgres_month_index(origin_month)
            bucket_count = Sequel.cast(Sequel.function(:floor, Sequel.cast(months, Float) / Sequel.cast(bucket.interval, Float)), Integer)
            bucket_start = Sequel.function(:make_interval, Sequel.lit('months := ?', bucket_count * bucket.interval))
            expression = origin_month + bucket_start
          else
            width = Sequel.function(:make_interval, Sequel.lit('secs := CAST(? AS integer)', bucket.interval))
            local = Sequel.lit('? AT TIME ZONE ?', bucket.expr, timezone)
            origin = Sequel.lit('? AT TIME ZONE ?', bucket.origin, timezone)
            expression = Sequel.function(:date_bin, width, local, origin)
          end

          literal_append(sql, Sequel.lit('? AT TIME ZONE ?', expression, timezone))
        end

        def postgres_month_index(expr)
          (Sequel.extract(:year, expr) * 12) + Sequel.extract(:month, expr) - 1
        end
      end

      # SQLite scalar functions used by the SQLite expressions.  Input values
      # are ordinary bound or literalized values; interval names are never
      # interpolated.
      module SQLiteFunctions
        def self.register(connection)
          connection.create_function('sequel_time_bucket', 4) do |function, value, seconds, origin, timezone|
            function.result = bucket_fixed(value, seconds, origin, timezone)
          end
          connection.create_function('sequel_month_bucket', 4) do |function, value, months, origin, timezone|
            function.result = bucket_months(value, months, origin, timezone)
          end
        end

        def self.bucket_fixed(value, seconds, origin, timezone)
          return nil if value.nil?
          seconds = integer_argument(seconds, 'seconds')
          origin_time = utc_time_argument(origin, 'origin')
          local_time = utc_to_local(parse_time(value), timezone)
          local_origin = utc_to_local(origin_time, timezone)
          bucket = ((wall_time(local_time) - wall_time(local_origin)).to_r / seconds).floor
          bucket_wall_time = wall_time(local_origin) + (bucket * seconds)
          local_bucket = wall_time_at_period(bucket_wall_time, local_time)
          format_time(local_to_utc(local_bucket, timezone))
        end

        def self.bucket_months(value, months, origin, timezone)
          return nil if value.nil?
          months = integer_argument(months, 'months')
          origin_time = utc_time_argument(origin, 'origin')
          local_time = utc_to_local(parse_time(value), timezone)
          local_origin = first_of_month(utc_to_local(origin_time, timezone))
          bucket = ((month_index(local_time) - month_index(local_origin)).to_r / months).floor
          format_time(local_to_utc(add_months(local_origin, bucket * months), timezone))
        end

        def self.integer_argument(value, name)
          value = value.to_i unless value.is_a?(Integer)
          unless value > 0
            raise(Sequel::InvalidValue, "time bucket #{name} must be positive")
          end
          value
        end
        private_class_method :integer_argument

        def self.utc_time_argument(value, name)
          time = parse_time(value)
          unless time.utc?
            raise(Sequel::InvalidValue, "time bucket #{name} must be UTC")
          end
          time
        end
        private_class_method :utc_time_argument

        def self.parse_time(value)
          case value
          when Time
            value.getutc
          when DateTime
            Time.at(value.to_r * 86400).utc
          when Numeric
            Time.at(value).utc
          when String
            normalized = value.sub(' ', 'T')
            unless normalized.match?(/[zZ]|[+-]\d\d:?\d\d\z/)
              normalized = "#{normalized}Z"
            end
            Time.iso8601(normalized).getutc
          else
            raise(Sequel::InvalidValue, "unsupported time bucket value: #{value.inspect}")
          end
        end
        private_class_method :parse_time

        def self.utc_to_local(time, timezone)
          case timezone
          when nil, 'UTC', 'utc', 'Etc/UTC'
            time
          else
            timezone_object(timezone).utc_to_local(time.getutc)
          end
        end
        private_class_method :utc_to_local

        def self.local_to_utc(time, timezone)
          case timezone
          when nil, 'UTC', 'utc', 'Etc/UTC'
            time
          else
            tz = timezone_object(timezone)
            begin
              tz.local_to_utc(time, true)
            rescue TZInfo::PeriodNotFound
              period = tz.period_for_local(time - 1, true)
              wall_seconds = time.to_i + time.utc_offset
              Time.at(wall_seconds - period.utc_total_offset).utc
            end
          end
        end
        private_class_method :local_to_utc

        def self.timezone_object(timezone)
          require 'tzinfo'
          case timezone
          when TZInfo::Timezone
            timezone
          when String
            TZInfo::Timezone.get(timezone)
          else
            raise(Sequel::InvalidValue, "unsupported time bucket timezone: #{timezone.inspect}")
          end
        end
        private_class_method :timezone_object

        def self.first_of_month(time)
          Time.new(time.year, time.month, 1, 0, 0, 0, time.utc_offset)
        end
        private_class_method :first_of_month

        def self.month_index(time)
          (time.year * 12) + time.month - 1
        end
        private_class_method :month_index

        def self.add_months(time, months)
          year, month = (month_index(time) + months).divmod(12)
          Time.new(year, month + 1, 1, 0, 0, 0, time.utc_offset)
        end
        private_class_method :add_months

        def self.wall_time(time)
          Time.utc(
            time.year,
            time.month,
            time.day,
            time.hour,
            time.min,
            time.sec + Rational(time.nsec, 1_000_000_000)
          )
        end
        private_class_method :wall_time

        def self.wall_time_at_period(time, reference)
          Time.at(time.to_r - reference.utc_offset).getlocal(reference.utc_offset)
        end
        private_class_method :wall_time_at_period

        def self.format_time(time)
          time.getutc.strftime('%Y-%m-%d %H:%M:%S.%6N')
        end
        private_class_method :format_time
      end

      # Registers the SQLite helper functions on each SQLite connection.
      module SQLiteDatabaseMethods
        def self.extended(database)
          return unless database.respond_to?(:pool)

          database.pool.all_connections do |connection|
            SQLiteFunctions.register(connection)
          end
        end

        private

        def connect(server)
          connection = super
          SQLiteFunctions.register(connection)
          connection
        end
      end
    end
  end

  Database.register_extension(:time_bucket) do |database|
    database.extend_datasets(SQL::TimeBucket::DatasetMethods)
    if database.adapter_scheme == :sqlite && defined?(SQLite3::Database)
      database.extend(SQL::TimeBucket::SQLiteDatabaseMethods)
    end
  end
end
