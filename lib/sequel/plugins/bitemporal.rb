# frozen-string-literal: true

module Sequel
  module Plugins
    # The bitemporal plugin adds support for bitemporal (two timeline)
    # versioning to a model.  Each row records a revision of an entity
    # (identified by a single business key column) along two half-open
    # intervals:
    #
    # * the business validity interval (+valid_from+...valid_to+), which
    #   describes when the recorded fact was in effect in the real world, and
    # * the system version interval (+system_from+...system_to+), which
    #   describes when the revision was visible in the database.
    #
    # Both intervals are half-open: the from column is inclusive and the to
    # column is exclusive, so adjacent intervals where one row's to column
    # equals another row's from column do not overlap.  A NULL to column
    # represents an open-ended interval (valid/visible until further notice).
    #
    # This allows recording corrections retroactively (for example, entering
    # a price today that was already effective last week) while still being
    # able to answer what the system showed at any point in the past, via
    # the +as_of+ dataset method, which takes a valid time and a system time.
    #
    # Revisions are recorded with Model.record_revision, which closes the
    # system version of any currently visible revision whose validity
    # interval overlaps the new one, inserts carry-over revisions for the
    # non-overlapping parts of those intervals (preserving their attribute
    # values), and inserts the new revision, all inside a transaction, so a
    # failure partway through rolls everything back.  Old system versions
    # are never modified or deleted, only closed, so the full history of
    # what the system showed remains queryable.
    #
    # The plugin validates that revisions visible in the same system view
    # (rows with a NULL system_to) never have overlapping validity intervals
    # for the same business key.
    #
    # The table backing the model needs four time columns in addition to
    # the business key column and the attribute columns.  Usage:
    #
    #   DB.create_table(:prices) do
    #     primary_key :id
    #     String :key
    #     Integer :amount
    #     Time :valid_from
    #     Time :valid_to, :null=>true
    #     Time :system_from
    #     Time :system_to, :null=>true
    #   end
    #
    #   class Price < Sequel::Model(:prices)
    #     plugin :bitemporal
    #   end
    #
    #   # Record a price effective from 2026-09-01:
    #   Price.record_revision('sku-1', {amount: 100}, valid_from: Time.utc(2026, 9, 1))
    #
    #   # Later, record a correction effective from 2026-09-15, keeping the
    #   # old system versions around:
    #   Price.record_revision('sku-1', {amount: 120}, valid_from: Time.utc(2026, 9, 15))
    #
    #   # What does the system currently show as the price on 2026-09-20?
    #   Price.as_of(Time.utc(2026, 9, 20), Time.now).all
    #
    #   # What did the system show yesterday for 2026-09-20?
    #   Price.as_of(Time.utc(2026, 9, 20), Time.now - 86400).all
    #
    # Options:
    # :key :: The business key column identifying the entity (default: :key)
    # :valid_from :: The validity interval start column (default: :valid_from)
    # :valid_to :: The validity interval end column (default: :valid_to)
    # :system_from :: The system version interval start column (default: :system_from)
    # :system_to :: The system version interval end column (default: :system_to)
    # :system_time :: A proc called to get the current system time when
    #                 recording revisions (default: proc{Time.now})
    module Bitemporal
      # Set the bitemporal column configuration for the model.
      def self.configure(model, opts=OPTS)
        model.instance_eval do
          @bitemporal_key_column = (opts[:key] || :key).to_sym
          @bitemporal_valid_from_column = (opts[:valid_from] || :valid_from).to_sym
          @bitemporal_valid_to_column = (opts[:valid_to] || :valid_to).to_sym
          @bitemporal_system_from_column = (opts[:system_from] || :system_from).to_sym
          @bitemporal_system_to_column = (opts[:system_to] || :system_to).to_sym
          @bitemporal_system_time_proc = opts[:system_time] || lambda{Time.now}
        end
      end

      module ClassMethods
        # The column identifying the entity a revision belongs to.
        attr_reader :bitemporal_key_column

        # The inclusive start of the business validity interval.
        attr_reader :bitemporal_valid_from_column

        # The exclusive end of the business validity interval (NULL if open-ended).
        attr_reader :bitemporal_valid_to_column

        # The inclusive start of the system version interval.
        attr_reader :bitemporal_system_from_column

        # The exclusive end of the system version interval (NULL if currently visible).
        attr_reader :bitemporal_system_to_column

        Plugins.inherited_instance_variables(self, :@bitemporal_key_column=>nil,
          :@bitemporal_valid_from_column=>nil, :@bitemporal_valid_to_column=>nil,
          :@bitemporal_system_from_column=>nil, :@bitemporal_system_to_column=>nil,
          :@bitemporal_system_time_proc=>nil)
        Plugins.def_dataset_methods(self, [:as_of, :valid_as_of, :system_as_of, :current_system_view])

        # Record a new revision for the entity identified by +key+, with the
        # given attribute values, effective for the half-open validity
        # interval +valid_from+...+valid_to+ (open-ended if +valid_to+ is
        # nil).  The revision becomes visible in the system view at
        # +system_time+ (defaults to the current time).
        #
        # Any revision currently visible in the system view whose validity
        # interval overlaps the new interval is closed (its system_to is set
        # to +system_time+), and carry-over revisions preserving the old
        # attribute values are inserted for the non-overlapping parts of
        # those intervals.  Everything runs inside a transaction, so a
        # failure rolls back all changes.  Returns the created revision.
        def record_revision(key, attributes, valid_from:, valid_to: nil, system_time: nil)
          vf = bitemporal_valid_from_column
          vt = bitemporal_valid_to_column
          sf = bitemporal_system_from_column
          st = bitemporal_system_to_column

          if valid_to && valid_from >= valid_to
            raise Sequel::InvalidValue, "valid_from (#{valid_from}) must be before valid_to (#{valid_to})"
          end

          system_time ||= @bitemporal_system_time_proc.call

          db.transaction do
            bitemporal_overlapping_current(key, valid_from, valid_to).all.each do |row|
              old_valid_from = row.get_column_value(vf)
              old_valid_to = row.get_column_value(vt)

              row.update(st=>system_time)

              if old_valid_from < valid_from
                bitemporal_insert_carry_over(row, old_valid_from, valid_from, system_time)
              end
              if valid_to && (old_valid_to.nil? || old_valid_to > valid_to)
                bitemporal_insert_carry_over(row, valid_to, old_valid_to, system_time)
              end
            end

            create(attributes.merge(bitemporal_key_column=>key, vf=>valid_from, vt=>valid_to, sf=>system_time, st=>nil))
          end
        end

        private

        # Dataset of currently visible revisions for +key+ whose validity
        # interval overlaps the half-open interval +valid_from+...+valid_to+.
        def bitemporal_overlapping_current(key, valid_from, valid_to)
          vf = bitemporal_valid_from_column
          vt = bitemporal_valid_to_column
          ds = current_system_view.where(bitemporal_key_column=>key).
            where(Sequel.|({vt=>nil}, Sequel[vt] > valid_from))
          ds = ds.where(Sequel[vf] < valid_to) if valid_to
          ds
        end

        # Insert a revision copying the attribute values of +source+,
        # visible from +system_time+, valid for +valid_from+...+valid_to+.
        def bitemporal_insert_carry_over(source, valid_from, valid_to, system_time)
          vf = bitemporal_valid_from_column
          vt = bitemporal_valid_to_column
          sf = bitemporal_system_from_column
          st = bitemporal_system_to_column

          excluded = [vf, vt, sf, st]
          excluded.concat(Array(primary_key)) if primary_key
          attributes = {}
          (columns - excluded).each{|c| attributes[c] = source.get_column_value(c)}
          attributes[vf] = valid_from
          attributes[vt] = valid_to
          attributes[sf] = system_time
          attributes[st] = nil
          create(attributes)
        end
      end

      module InstanceMethods
        # Whether this revision is currently visible in the system view
        # (its system version interval is open-ended).
        def current_system_version?
          get_column_value(model.bitemporal_system_to_column).nil?
        end

        # Validates that the validity interval is not empty, and that it
        # does not overlap the validity interval of another revision for
        # the same business key in the same system view.
        def validate
          super
          vf = model.bitemporal_valid_from_column
          vt = model.bitemporal_valid_to_column
          valid_from = get_column_value(vf)
          valid_to = get_column_value(vt)

          if valid_from && valid_to && valid_from >= valid_to
            errors.add(vf, "must be before #{vt}")
          end

          return unless current_system_version?

          ds = model.current_system_view.
            where(model.bitemporal_key_column=>get_column_value(model.bitemporal_key_column)).
            where(Sequel.|({vt=>nil}, Sequel[vt] > valid_from))
          ds = ds.where(Sequel[vf] < valid_to) if valid_to
          ds = ds.exclude(model.primary_key=>pk) unless new?
          errors.add(vf, "overlaps another revision in the same system view") unless ds.empty?
        end
      end

      module DatasetMethods
        # Revisions whose validity interval contains +valid_time+ and whose
        # system version interval contains +system_time+; in other words,
        # what the system showed at +system_time+ as being in effect at
        # +valid_time+.
        def as_of(valid_time, system_time)
          valid_as_of(valid_time).system_as_of(system_time)
        end

        # Revisions whose validity interval contains +valid_time+.
        def valid_as_of(valid_time)
          vf = model.bitemporal_valid_from_column
          vt = model.bitemporal_valid_to_column
          where(Sequel[vf] <= valid_time).
            where(Sequel.|({vt=>nil}, Sequel[vt] > valid_time))
        end

        # Revisions whose system version interval contains +system_time+.
        def system_as_of(system_time)
          sf = model.bitemporal_system_from_column
          st = model.bitemporal_system_to_column
          where(Sequel[sf] <= system_time).
            where(Sequel.|({st=>nil}, Sequel[st] > system_time))
        end

        # Revisions currently visible in the system view (system_to IS NULL).
        def current_system_view
          where(model.bitemporal_system_to_column=>nil)
        end
      end
    end
  end
end
