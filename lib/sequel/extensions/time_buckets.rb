# frozen_string_literal: true
#
# The time_buckets extension adds database expressions for grouping
# timestamps into fixed-size intervals or calendar months.
#
# Fixed-width buckets are measured in seconds and use an explicit origin:
#
#   DB.extension :time_buckets
#   Sequel.time_bucket(:created_at, 900, origin: Time.utc(2024, 1, 1))
#
# Calendar month buckets use calendar boundaries in an optional timezone:
#
#   Sequel.month_bucket(:created_at, timezone: 'America/New_York')
#
# The returned objects are Sequel expressions and can be selected, aliased,
# grouped, ordered, and composed with other expressions.
#
# Related modules: Sequel::SQL::TimeBucket, Sequel::SQL::MonthBucket

module Sequel
  module SQL
    module Builders
      # Return an expression that buckets +expr+ into fixed-width intervals.
      # +seconds+ is the interval width in seconds.
      # Options:
      # :origin :: Timestamp from which bucket boundaries are calculated (default: Unix epoch).
      # :timezone :: Timezone used to display the bucket boundaries.
      def time_bucket(expr, seconds, opts=OPTS)
        TimeBucket.new(expr, seconds, opts[:origin] || Time.at(0).utc, opts[:timezone])
      end

      # Return an expression that buckets +expr+ by calendar month.
      # Options:
      # :timezone :: Timezone used to determine calendar month boundaries.
      def month_bucket(expr, opts=OPTS)
        MonthBucket.new(expr, opts[:timezone])
      end
    end

    class TimeBucket < GenericExpression
      module DatasetMethods
        def time_bucket_sql_append(sql, bucket)
          case db.database_type
          when :sqlite
            args = [bucket.expr, bucket.seconds, bucket.origin]
            args << bucket.timezone if bucket.timezone
            literal_append(sql, Sequel.function(:sequel_time_bucket, *args))
          when :postgres
            timezone = bucket.timezone || 'UTC'
            expr = Sequel.cast(bucket.expr, :timestamptz)
            origin = Sequel.cast(bucket.origin, :timestamptz)
            delta = Sequel.extract(:epoch, expr) - Sequel.extract(:epoch, origin)
            seconds = Sequel.function(:floor, delta / bucket.seconds.to_f) * bucket.seconds
            interval = Sequel.cast(Sequel.cast_string(seconds) + ' seconds', :interval)
            literal_append(sql, Sequel.function(:timezone, timezone, origin + interval))
          else
            raise Error, "time_bucket is not supported on #{db.database_type}"
          end
        end

        def month_bucket_sql_append(sql, bucket)
          case db.database_type
          when :sqlite
            args = [bucket.expr]
            args << bucket.timezone if bucket.timezone
            literal_append(sql, Sequel.function(:sequel_month_bucket, *args))
          when :postgres
            timezone = bucket.timezone || 'UTC'
            expr = Sequel.cast(bucket.expr, :timestamptz)
            result = Sequel.function(:date_trunc, 'month', Sequel.function(:timezone, timezone, expr))
            literal_append(sql, result)
          else
            raise Error, "month_bucket is not supported on #{db.database_type}"
          end
        end
      end

      attr_reader :expr, :seconds, :origin, :timezone

      def initialize(expr, seconds, origin, timezone)
        raise InvalidValue, "time bucket seconds must be a positive integer" unless seconds.is_a?(Integer) && seconds > 0

        @expr = expr
        @seconds = seconds
        @origin = origin
        @timezone = timezone
        freeze
      end

      def sequel_ast_transform(transformer)
        self.class.new(transformer.call(expr), seconds, transformer.call(origin), timezone)
      end

      to_s_method :time_bucket_sql
    end

    class MonthBucket < GenericExpression
      attr_reader :expr, :timezone

      def initialize(expr, timezone)
        @expr = expr
        @timezone = timezone
        freeze
      end

      def sequel_ast_transform(transformer)
        self.class.new(transformer.call(expr), timezone)
      end

      to_s_method :month_bucket_sql
    end
  end

  module TimeBuckets
    module DatabaseMethods
      TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%6N'.freeze
      UNIX_EPOCH_DATETIME = DateTime.new(1970, 1, 1).freeze

      def self.extended(db)
        db.extend_datasets(SQL::TimeBucket::DatasetMethods)
        db.pool.all_connections { |conn| db.send(:register_time_bucket_functions, conn) }
        db.singleton_class.send(:alias_method, :connect_without_time_buckets, :connect)
        db.singleton_class.send(:define_method, :connect) do |server|
          conn = connect_without_time_buckets(server)
          send(:register_time_bucket_functions, conn)
          conn
        end
      end

      def register_time_bucket_functions(conn)
        database = self
        conn.create_function('sequel_time_bucket', -1) do |function, timestamp, seconds, origin, timezone = 'UTC'|
          function.result = database.send(:bucket_time, timestamp, seconds, origin, timezone)
        end

        conn.create_function('sequel_month_bucket', -1) do |function, timestamp, timezone = 'UTC'|
          function.result = database.send(:bucket_month, timestamp, timezone)
        end
      end

      def bucket_time(timestamp, seconds, origin, timezone)
        return if timestamp.nil?

        timestamp = sqlite_utc_timestamp(timestamp)
        origin = sqlite_utc_timestamp(origin)
        origin_seconds = datetime_epoch_seconds(origin)
        timestamp_seconds = datetime_epoch_seconds(timestamp)
        bucket_seconds = origin_seconds + Rational(timestamp_seconds - origin_seconds, seconds).floor * seconds
        local = local_time(Time.at(bucket_seconds).utc.to_datetime, timezone)
        wall_time(local).strftime(TIME_FORMAT)
      end

      def bucket_month(timestamp, timezone)
        return if timestamp.nil?

        local = local_time(sqlite_utc_timestamp(timestamp), timezone)
        Time.utc(local.year, local.month, 1).strftime(TIME_FORMAT)
      end

      def sqlite_utc_timestamp(value)
        case value
        when Numeric
          Time.at(value).utc.to_datetime
        when String
          value = DateTime.parse(value =~ /(?:Z|[+-]\d{2}:?\d{2})\z/ ? value : value + 'Z')
          value.new_offset(0)
        else
          raise InvalidValue, "unsupported SQLite timestamp for time_buckets: #{value.class}"
        end
      end

      def local_time(timestamp, timezone)
        return timestamp if timezone == 'UTC'

        if timezone =~ /\A([+-])(\d{2}):(\d{2})\z/
          offset = ($2.to_i * 3600 + $3.to_i * 60) * ($1 == '-' ? -1 : 1)
          return timestamp.new_offset(Rational(offset, 86400))
        end

        begin
          require 'tzinfo'
        rescue LoadError
          raise LoadError, "named timezones in time_buckets require tzinfo"
        end
        TZInfo::Timezone.get(timezone.to_s).utc_to_local(timestamp)
      end

      def datetime_epoch_seconds(datetime)
        (datetime - UNIX_EPOCH_DATETIME).to_r * 86400
      end

      def wall_time(datetime)
        Time.utc(datetime.year, datetime.month, datetime.day,
                 datetime.hour, datetime.min, datetime.sec + datetime.sec_fraction)
      end

      private :register_time_bucket_functions, :bucket_time, :bucket_month,
              :sqlite_utc_timestamp, :local_time, :datetime_epoch_seconds,
              :wall_time
    end
  end

  Dataset.register_extension(:time_buckets, SQL::TimeBucket::DatasetMethods)
  Database.register_extension(:time_buckets) do |db|
    case db.database_type
    when :sqlite
      if db.adapter_scheme == :amalgalite
        raise Error, "time_buckets extension is not supported on the amalgalite adapter"
      end
      db.extend_datasets(SQL::TimeBucket::DatasetMethods)
      if db.adapter_scheme == :sqlite
        db.extend(TimeBuckets::DatabaseMethods)
      end
    when :postgres
      db.extend_datasets(SQL::TimeBucket::DatasetMethods)
    else
      raise Error, "time_buckets extension is not supported on #{db.database_type}"
    end
  end
end
