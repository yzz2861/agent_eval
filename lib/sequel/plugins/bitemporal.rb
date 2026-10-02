# frozen_string_literal: true

module Sequel
  module Plugins
    # Stores records on independent business-valid and system-version axes.
    # Both axes use half-open [start, end) intervals, where a nil end is open.
    # This means [10, 20) contains 10 but not 20, and two intervals such as
    # [10, 20) and [20, 30) touch without overlapping.
    #
    # Required table columns represent:
    # * one business key
    # * valid_start and valid_end
    # * system_start and system_end
    #
    # Usage:
    #
    #   DB.create_table(:prices) do
    #     primary_key :id
    #     Integer :product_id, null: false
    #     Integer :cents, null: false
    #     Integer :valid_start, null: false
    #     Integer :valid_end
    #     Integer :system_start, null: false
    #     Integer :system_end
    #   end
    #
    #   class Price < Sequel::Model(:prices)
    #     plugin :bitemporal, key: :product_id
    #   end
    #
    #   Price.record_bitemporal(1, {cents: 100},
    #                           valid_start: 10, recorded_at: 100)
    #   Price.record_bitemporal(1, {cents: 90},
    #                           valid_start: 12, valid_end: 15,
    #                           recorded_at: 200)
    #
    #   # Yesterday's system view still shows the old correction-free price.
    #   Price.bitemporal_as_of(13, 199).map(:cents) # => [100]
    #
    #   # Today's system view shows the backdated business correction.
    #   Price.bitemporal_as_of(13, 200).map(:cents) # => [90]
    #
    # Writes are performed in a transaction. On SQLite, an IMMEDIATE
    # transaction is used; elsewhere the transaction uses serializable
    # isolation. Rows selected for splitting also use FOR UPDATE where the
    # database supports it.
    module Bitemporal
      Error = Class.new(Sequel::Error)

      def self.configure(model, opts=OPTS)
        model.instance_exec do
          @bitemporal_key_column = opts[:key] || :business_key
          @bitemporal_valid_start_column = opts[:valid_start] || :valid_start
          @bitemporal_valid_end_column = opts[:valid_end] || :valid_end
          @bitemporal_system_start_column = opts[:system_start] || :system_start
          @bitemporal_system_end_column = opts[:system_end] || :system_end
        end
      end

      module ClassMethods
        attr_reader :bitemporal_key_column
        attr_reader :bitemporal_valid_start_column
        attr_reader :bitemporal_valid_end_column
        attr_reader :bitemporal_system_start_column
        attr_reader :bitemporal_system_end_column

        Plugins.inherited_instance_variables(self,
          :@bitemporal_key_column=>nil,
          :@bitemporal_valid_start_column=>nil,
          :@bitemporal_valid_end_column=>nil,
          :@bitemporal_system_start_column=>nil,
          :@bitemporal_system_end_column=>nil)

        Plugins.def_dataset_methods(self, :bitemporal_as_of)

        # Return rows visible at a business and/or system as-of time. Nil for
        # either time means that axis is not filtered.
        def bitemporal_as_of(valid_time=nil, system_time=nil)
          dataset.bitemporal_as_of(valid_time, system_time)
        end

        # Record a new fact or correction for one business key. +attributes+
        # contains the non-interval data columns. The business interval is
        # [valid_start, valid_end), with nil valid_end meaning open-ended. The
        # system interval starts at recorded_at and remains open until a later
        # correction supersedes it.
        def record_bitemporal(key, attributes=OPTS, opts=OPTS)
          valid_start = opts[:valid_start]
          valid_end = opts[:valid_end]
          recorded_at = opts[:recorded_at]

          validate_bitemporal_intervals(valid_start, valid_end, recorded_at)

          values = attributes.dup
          values.delete_if{|column, _| bitemporal_managed_columns.include?(column)}
          values[bitemporal_key_column] = key
          values[bitemporal_valid_start_column] = valid_start
          values[bitemporal_valid_end_column] = valid_end
          values[bitemporal_system_start_column] = recorded_at
          values[bitemporal_system_end_column] = nil

          transaction_options = bitemporal_transaction_options(opts)
          if transaction_options
            db.transaction(transaction_options) do
              _record_bitemporal(values, valid_start, valid_end, recorded_at)
            end
          else
            _record_bitemporal(values, valid_start, valid_end, recorded_at)
          end
        end

        private

        def _record_bitemporal(values, valid_start, valid_end, recorded_at)
          overlap = bitemporal_overlap_dataset(
            values[bitemporal_key_column], valid_start, valid_end)
          rows = overlap.order(bitemporal_system_start_column).all
          current = rows.select{|row| row[bitemporal_system_end_column].nil?}

          return insert_bitemporal_version(values) if rows.empty?

          duplicate = validate_bitemporal_system_time(
            rows, recorded_at, values)
          return duplicate if duplicate

          if current.empty?
            insert_bitemporal_version(values)
          else
            split_bitemporal_rows(current, valid_start, valid_end, recorded_at)
            insert_bitemporal_version(values)
          end
        end

        def validate_bitemporal_intervals(valid_start, valid_end, recorded_at)
          if valid_start.nil? || recorded_at.nil?
            raise Bitemporal::Error, "valid_start and recorded_at are required"
          end

          unless valid_start.respond_to?(:<) && (valid_end.nil? || valid_end.respond_to?(:>))
            raise Bitemporal::Error, "bitemporal interval bounds must be comparable"
          end

          if valid_end && !(valid_start < valid_end)
            raise Bitemporal::Error, "business interval must be half-open and non-empty"
          end

          unless recorded_at.respond_to?(:<=)
            raise Bitemporal::Error, "system interval start must be comparable"
          end
        end

        def validate_bitemporal_system_time(rows, recorded_at, values)
          latest_system_start = rows.map{|row| row[bitemporal_system_start_column]}.max
          duplicate = rows.find do |row|
            row[bitemporal_system_start_column] == recorded_at &&
              bitemporal_duplicate_correction?([row], values)
          end
          return duplicate if duplicate
          return nil if latest_system_start < recorded_at

          raise Bitemporal::Error,
            "recorded_at must be later than the existing system version (#{latest_system_start.inspect})"
        end

        def bitemporal_duplicate_correction?(rows, values)
          rows.length == 1 && rows.all? do |row|
            values.all?{|column, value| row[column] == value}
          end
        end

        def split_bitemporal_rows(rows, valid_start, valid_end, recorded_at)
          rows.each do |row|
            row_start = row[bitemporal_valid_start_column]
            row_end = row[bitemporal_valid_end_column]

            close_current_bitemporal_row(row, recorded_at)

            if row_start < valid_start
              insert_bitemporal_fragment(row, row_start, valid_start, recorded_at)
            end

            if valid_end && (row_end.nil? || valid_end < row_end)
              insert_bitemporal_fragment(row, valid_end, row_end, recorded_at)
            end
          end
        end

        def close_current_bitemporal_row(row, recorded_at)
          n = dataset.where(bitemporal_identity_filter(row)).
            where(bitemporal_system_end_column=>nil).
            update(bitemporal_system_end_column=>recorded_at)
          raise Bitemporal::Error, "bitemporal row was modified concurrently" unless n == 1
        end

        def insert_bitemporal_fragment(row, fragment_start, fragment_end, recorded_at)
          fragment = bitemporal_fragment_values(row)
          fragment[bitemporal_valid_start_column] = fragment_start
          fragment[bitemporal_valid_end_column] = fragment_end
          fragment[bitemporal_system_start_column] = recorded_at
          fragment[bitemporal_system_end_column] = nil
          dataset.insert(fragment)
        end

        def insert_bitemporal_version(values)
          dataset.insert(values)
          dataset.where(values).first
        end

        def bitemporal_overlap_dataset(key, valid_start, valid_end)
          dataset.where(bitemporal_key_column=>key).
            where(bitemporal_overlap_condition(
              bitemporal_valid_start_column,
              bitemporal_valid_end_column,
              valid_start,
              valid_end)).
            for_update
        end

        def bitemporal_overlap_condition(start_column, end_column, range_start, range_end)
          end_open_or_after_start = Sequel.expr(end_column=>nil) |
            (Sequel.expr(end_column) > range_start)
          return end_open_or_after_start unless range_end

          (Sequel.expr(start_column) < range_end) & end_open_or_after_start
        end

        def bitemporal_as_of_condition(start_column, end_column, time)
          (Sequel.expr(start_column) <= time) &
            (Sequel.expr(end_column=>nil) | (Sequel.expr(end_column) > time))
        end

        def bitemporal_identity_filter(row)
          {
            bitemporal_key_column=>row[bitemporal_key_column],
            bitemporal_valid_start_column=>row[bitemporal_valid_start_column],
            bitemporal_valid_end_column=>row[bitemporal_valid_end_column],
            bitemporal_system_start_column=>row[bitemporal_system_start_column]
          }
        end

        def bitemporal_fragment_values(row)
          values = {}
          dataset.columns.each do |column|
            next if Array(primary_key).include?(column)
            next if column == bitemporal_valid_start_column
            next if column == bitemporal_valid_end_column
            next if column == bitemporal_system_start_column
            next if column == bitemporal_system_end_column
            values[column] = row[column]
          end
          values
        end

        def bitemporal_managed_columns
          [
            bitemporal_key_column,
            bitemporal_valid_start_column,
            bitemporal_valid_end_column,
            bitemporal_system_start_column,
            bitemporal_system_end_column
          ]
        end

        def bitemporal_transaction_options(opts)
          return nil if opts[:transaction] == false
          if db.database_type == :sqlite
            {:mode=>:immediate}
          else
            {:isolation=>:serializable}
          end
        end
      end

      module DatasetMethods
        # Filter the dataset to rows in effect at +valid_time+ and visible at
        # +system_time+, where nil for either argument disables that axis.
        def bitemporal_as_of(valid_time=nil, system_time=nil)
          m = model
          ds = self

          if valid_time
            ds = ds.where(m.send(:bitemporal_as_of_condition,
              m.bitemporal_valid_start_column,
              m.bitemporal_valid_end_column,
              valid_time))
          end

          if system_time
            ds = ds.where(m.send(:bitemporal_as_of_condition,
              m.bitemporal_system_start_column,
              m.bitemporal_system_end_column,
              system_time))
          end

          ds
        end
      end
    end
  end
end
