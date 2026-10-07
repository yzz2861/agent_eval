# frozen_string_literal: false
require_relative 'drb'
require 'monitor'
require 'securerandom'
require 'weakref'

module DRb

  # Timer id conversion keeps exported objects alive while a client holds an
  # active lease or while a remote call is in progress.  The default lease
  # duration is 600 seconds and can be changed upon initialization.
  #
  # A leased proxy exposes its lease with __drb_lease.  The lease can be
  # renewed with #renew! before it expires or released explicitly with
  # #release.  Expired and released references raise
  # DRb::DRbInvalidReferenceError.
  #
  # To use TimerIdConv:
  #
  #  DRb.install_id_conv TimerIdConv.new 60 # one minute

  class TimerIdConv < DRbIdConv
    InvalidReferenceError = DRbInvalidReferenceError
    InvalidIndexError = DRbInvalidReferenceError

    class LeaseService # :nodoc:
      include DRbUndumped

      def initialize(holder)
        @holder = holder
      end

      def renew_lease(token)
        @holder.renew(token)
      end

      def release_lease(token)
        @holder.release(token)
      end
    end

    class TimerHolder2 # :nodoc:
      InvalidReferenceError = DRbInvalidReferenceError
      InvalidIndexError = DRbInvalidReferenceError

      include MonitorMixin

      class Registration
        attr_reader :id

        def initialize(object, id, clock)
          @weakref = WeakRef.new(object)
          @id = id
          @leases = {}
          @active_calls = 0
          @clock = clock
        end

        class LeaseEntry
          def initialize(object, deadline)
            @object = object
            @deadline = deadline
          end

          attr_reader :object
          attr_accessor :deadline
        end

        def alive?
          @weakref.__getobj__.__id__ == @id
        rescue WeakRef::RefError
          false
        end

        def stale?
          prune!
          !alive? || (@leases.empty? && @active_calls.zero?)
        end

        def add_lease(lease_id, deadline, object)
          @leases[lease_id] = LeaseEntry.new(object, deadline)
        end

        def valid_lease?(lease_id, now)
          prune!
          (entry = @leases[lease_id]) && entry.deadline > now
        end

        def renew(lease_id, deadline, now)
          entry = @leases[lease_id]
          return nil unless entry && entry.deadline > now
          entry.deadline = deadline
          true
        end

        def release(lease_id, now)
          entry = @leases.delete(lease_id)
          !!(entry && entry.deadline > now)
        end

        def begin_call
          @active_calls += 1
          @weakref.__getobj__
        end

        def end_call
          @active_calls -= 1 if @active_calls > 0
        end

        def object
          return nil unless alive?
          @weakref.__getobj__
        rescue WeakRef::RefError
          nil
        end

        private
        def prune!
          return if @leases.empty?
          now = @clock.call
          @leases.delete_if { |_, entry| entry.deadline <= now }
        end
      end

      def initialize(keeping=600, clock=nil)
        super()
        @keeping = keeping
        @now = make_clock(clock)
        @registrations = {}
        @service = LeaseService.new(self)
      end

      def add(obj)
        synchronize do
          cleanup
          id = obj.__id__
          registration = @registrations[id]
          if registration.nil? || !registration.alive?
            registration = Registration.new(obj, id, @now)
            @registrations[id] = registration
          end
          lease_id = SecureRandom.hex(16) while lease_id.nil? || lease_id?(lease_id)
          deadline = now + @keeping
          registration.add_lease(lease_id, deadline, obj)
          [DRbLease::TOKEN_MARKER, id, lease_id, deadline].freeze
        end
      end

      def fetch(ref)
        synchronize do
          cleanup
          raise InvalidReferenceError, "invalid reference" unless leased_ref?(ref)
          _, id, lease_id, = ref
          registration = @registrations[id]
          obj = registration&.object
          raise InvalidReferenceError, "invalid reference" unless obj
          raise InvalidReferenceError, "invalid reference" unless registration.valid_lease?(lease_id, now)
          obj
        end
      end

      def begin_call(ref)
        synchronize do
          cleanup
          return nil if ref == DRbLease::SERVICE_REF
          raise InvalidReferenceError, "invalid reference" unless leased_ref?(ref)
          _, id, lease_id, = ref
          registration = @registrations[id]
          obj = registration&.object
          raise InvalidReferenceError, "invalid reference" unless obj
          raise InvalidReferenceError, "invalid reference" unless registration.valid_lease?(lease_id, now)
          registration.begin_call
          [id, obj]
        end
      end

      def end_call(guard)
        object_id = guard.is_a?(Array) ? guard.first : guard
        synchronize do
          registration = @registrations[object_id]
          registration&.end_call
          cleanup
        end
      end

      def renew(token)
        synchronize do
          cleanup
          raise InvalidReferenceError, "invalid reference" unless leased_ref?(token)
          _, id, lease_id, = token
          deadline = now + @keeping
          renewed = @registrations[id]&.renew(lease_id, deadline, now)
          raise InvalidReferenceError, "invalid reference" unless renewed
          deadline
        end
      end

      def release(token)
        synchronize do
          cleanup
          raise InvalidReferenceError, "invalid reference" unless leased_ref?(token)
          _, id, lease_id, = token
          released = @registrations[id]&.release(lease_id, now)
          cleanup
          !!released
        end
      end

      def service
        @service
      end

      def cleanup
        @registrations.delete_if do |_, registration|
          registration.stale?
        end
      end

      private
      def make_clock(clock)
        case clock
        when nil
          -> { Time.now }
        when Proc, Method
          clock
        else
          if clock.respond_to?(:now)
            -> { clock.now }
          else
            raise ArgumentError, "clock must respond to now or be callable"
          end
        end
      end

      def now
        @now.call
      end

      def leased_ref?(ref)
        ref.is_a?(Array) && ref.length == 4 && ref.first == DRbLease::TOKEN_MARKER
      end

      def lease_id?(lease_id)
        @registrations.each_value do |registration|
          return true if registration.instance_variable_get(:@leases).key?(lease_id)
        end
        false
      end
    end

    # Creates a new TimerIdConv which will grant leases for +keeping+ seconds.
    # +clock+ is an injectable clock responding to #now or a callable object.
    def initialize(keeping=600, clock=nil)
      @holder = TimerHolder2.new(keeping, clock)
    end

    def to_obj(ref) # :nodoc:
      return super if ref.nil?
      return @holder.service if ref == DRbLease::SERVICE_REF
      @holder.fetch(ref)
    end

    def to_id(obj) # :nodoc:
      return DRbLease::SERVICE_REF if obj.equal?(@holder.service)
      @holder.add(obj)
    end

    def begin_call(ref) # :nodoc:
      @holder.begin_call(ref)
    end

    def end_call(object_id) # :nodoc:
      @holder.end_call(object_id)
    end
  end
end

# DRb.install_id_conv(TimerIdConv.new)
