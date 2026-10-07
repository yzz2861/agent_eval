# frozen_string_literal: false
require_relative 'drb'
require 'monitor'
require 'securerandom'

module DRb

  # Timer id conversion grants clients explicit leases on exported objects.
  # A lease contains its expiry time and can be renewed or released by the
  # client.  The server keeps a strong reference to an object only while at
  # least one lease for that object is valid, or while a remote call that
  # started before expiry is still running or sending its reply.
  # Every proxy creation is granted an independent, unguessable lease id.
  #
  # To use TimerIdConv:
  #
  #  DRb.install_id_conv TimerIdConv.new(60) # one minute

  # When an undumpable object is marshalled, its proxy carries the returned
  # Lease.  Call Lease#renew before expiry or Lease#release when the proxy is
  # no longer needed.

  class TimerIdConv < DRbIdConv
    # Base class for errors raised when a lease cannot be used.
    class LeaseError < InvalidReferenceError; end

    # Raised when a lease id was never issued or has already been released.
    class InvalidLeaseError < LeaseError; end

    # Raised when a lease id was issued, but its server-clock expiry has
    # passed and no call is temporarily retaining it.
    class ExpiredLeaseError < InvalidLeaseError; end

    # A client-visible lease for an exported object.
    class Lease
      MARSHAL_VERSION = 1

      def self._load(data) # :nodoc:
        version, id, expires_at, uri, manager = Marshal.load(data)
        unless version == MARSHAL_VERSION
          raise ArgumentError, "invalid lease version: #{version}"
        end
        allocate.tap do |lease|
          lease.send(:initialize_lease, id, expires_at, uri: uri, manager: manager)
        end
      end

      def self.for_holder(holder, id, expires_at) # :nodoc:
        allocate.tap do |lease|
          uri = DRb.uri rescue nil
          manager = DRbObject.new_with(uri, TimerHolder2::LEASE_MANAGER_REF) if uri
          lease.send(:initialize_lease, id, expires_at,
                         holder: holder, uri: uri, manager: manager)
        end
      end

      # The stable identifier of this lease. A new object never reuses an id
      # from a released or expired lease.
      attr_reader :id

      # The server-clock time at which this lease expires unless renewed.
      attr_reader :expires_at

      # Extends the lease using the server clock. +duration+ defaults to the
      # keeping period configured on the server. Returns the updated lease.
      def renew(duration = nil)
        @expires_at = if @holder
          @holder.renew(@id, duration)
        else
          lease_manager.renew(@id, duration)
        end
        self
      end

      # Releases this lease. Returns true when this call released the lease;
      # returns false when it had already expired or been released.
      def release
        if @holder
          @holder.release(@id)
        else
          lease_manager.release(@id)
        end
      end

      # Convenience check using the local clock. The server clock is still
      # authoritative for renewal and method dispatch.
      def expired?
        Time.now > @expires_at
      end

      def _dump(_level) # :nodoc:
        Marshal.dump([MARSHAL_VERSION, @id, @expires_at, @uri, @lease_manager])
      end

      private

      def initialize_lease(id, expires_at, holder: nil, uri: nil, manager: nil)
        @id = id
        @expires_at = expires_at
        @holder = holder
        @uri = uri
        @lease_manager = manager
      end

      def lease_manager
        @lease_manager ||= DRbObject.new_with(@uri, TimerHolder2::LEASE_MANAGER_REF)
      end
    end

    class TimerHolder2 # :nodoc:
      include MonitorMixin

      Entry = Struct.new(:object, :expires_at)
      TOMBSTONE_LIMIT = 4096

      class CallGuard # :nodoc:
        def initialize(holder, id)
          @holder = holder
          @id = id
          @finished = false
        end

        def finish
          return if @finished
          holder = @holder
          id = @id
          remove_instance_variable(:@holder)
          remove_instance_variable(:@id)
          holder.finish_call(id)
          @finished = true
        end
      end

      class LeaseManager # :nodoc:
        def initialize(holder)
          @holder = holder
        end

        def renew(id, duration = nil)
          @holder.renew(id, duration)
        end

        def release(id)
          @holder.release(id)
        end
      end

      class LeaseManagerRef < String
        def self._load(_data)
          TimerIdConv::TimerHolder2::LEASE_MANAGER_REF
        end

        def _dump(_level)
          ''
        end
      end

      LEASE_MANAGER_REF = LeaseManagerRef.new('__drb_timer_id_conv_lease_manager__')
      InvalidIndexError = TimerIdConv::InvalidLeaseError

      def initialize(keeping = 600, clock: Time)
        super()
        @keeping = keeping
        @clock = clock.method(:now)
        @leases = {}
        @tombstones = {}
        @active_calls = Hash.new(0)
        @active_objects = {}
        @cond = new_cond
        @closing = false
        @lease_manager = LeaseManager.new(self)
      end

      def add(obj)
        synchronize do
          reap_locked
          id = unique_id
          expires_at = now + @keeping
          @leases[id] = Entry.new(obj, expires_at)
          @reaper ||= start_reaper
          @cond.broadcast
          Lease.for_holder(self, id, expires_at)
        end
      end

      def fetch(ref)
        id = lease_id(ref)
        synchronize do
          raise_expired(id) if @tombstones.key?(id)
          entry = @leases[id]
          if entry.nil?
            raise_invalid(id)
          elsif entry.expires_at <= now
            raise_expired(id)
          end

          keepalives = Thread.current['DRb']&.[]('keepalives')
          if keepalives
            @active_calls[id] += 1
            @active_objects[id] = entry.object
            keepalives << CallGuard.new(self, id)
          end
          entry.object
        end
      end

      def renew(id, duration = nil)
        duration ||= @keeping
        unless duration.is_a?(Numeric) && duration > 0
          raise ArgumentError, "duration must be positive"
        end

        synchronize do
          raise_expired(id) if @tombstones.key?(id)
          entry = @leases[id]
          if entry.nil?
            raise_invalid(id)
          elsif entry.expires_at <= now
            raise_expired(id)
          end
          entry.expires_at = now + duration
          @cond.signal
          entry.expires_at
        end
      end

      def release(id)
        synchronize do
          reap_locked
          @tombstones.delete(id)
          entry = @leases.delete(id)
          @cond.signal if entry
          !entry.nil?
        end
      end

      def lease_manager?(ref)
        ref == LEASE_MANAGER_REF
      end

      def lease_manager
        @lease_manager
      end

      def finish_call(id) # :nodoc:
        synchronize do
          return unless @active_calls.key?(id)

          remaining = @active_calls[id] - 1
          if remaining > 0
            @active_calls[id] = remaining
          else
            @active_calls.delete(id)
            entry = @leases[id]
            if entry&.expires_at&.<=(now)
              entry.object = nil
              add_tombstone_locked(id)
              @leases.delete(id)
            end
            @active_objects.delete(id)
          end
        end
      end

      def finish_request(call_guards) # :nodoc:
        call_guards.each(&:finish)
      end

      def reap
        synchronize { reap_locked }
      end

      def close
        synchronize do
          @closing = true
          @cond.broadcast
        end
        reaper, @reaper = @reaper, nil
        reaper&.join
        self
      end

      private

      def add_tombstone_locked(id)
        @tombstones.delete(id)
        @tombstones[id] = true
        while @tombstones.size > TOMBSTONE_LIMIT
          @tombstones.delete(@tombstones.each_key.first)
        end
      end

      def start_reaper
        Thread.new do
          begin
            loop do
              synchronize do
                @cond.wait until @closing || next_expiry
                return if @closing
                expiry = next_expiry
                delay = expiry - Time.now
                delay = 1 if delay <= 0
                @cond.wait(delay)
                reap_locked
              end
            end
          rescue Exception
            nil
          end
        end
      end

      def next_expiry
        @leases.each_value.map(&:expires_at).min
      end

      def reap_locked
        current = now
        @leases.each_key do |id|
          entry = @leases[id]
          next unless entry.expires_at <= current
          next if @active_calls[id] > 0
          entry.object = nil
          add_tombstone_locked(id)
          @leases.delete(id)
        end
        @cond.broadcast
      end

      def unique_id
        loop do
          id = generate_id
          return id unless @leases.key?(id) || @tombstones.key?(id)
        end
      end

      def generate_id
        SecureRandom.urlsafe_base64(32)
      end

      def lease_id(ref)
        case ref
        when Lease
          ref.id
        when String
          ref
        else
          raise InvalidLeaseError, "invalid lease reference: #{ref.inspect}"
        end
      end

      def raise_invalid(id)
        raise InvalidLeaseError, "invalid lease: #{id}"
      end

      def raise_expired(id)
        raise ExpiredLeaseError, "expired lease: #{id}"
      end

      def now
        @clock.call
      end
    end

    # Creates a new TimerIdConv which grants leases for +keeping+ seconds.
    # +clock+ defaults to Time and must respond to #now.
    def initialize(keeping = 600, clock: Time)
      @holder = TimerHolder2.new(keeping, clock: clock)
    end

    def to_obj(ref) # :nodoc:
      return super if ref.nil?
      return @holder.lease_manager if @holder.lease_manager?(ref)
      @holder.fetch(ref)
    end

    def to_id(obj) # :nodoc:
      return TimerHolder2::LEASE_MANAGER_REF if obj.equal?(@holder.lease_manager)
      @holder.add(obj)
    end

    def close # :nodoc:
      @holder.close
    end

    def finish_request(call_guards) # :nodoc:
      @holder.finish_request(call_guards)
    end

    def reap # :nodoc:
      @holder.reap
    end
  end
end

# DRb.install_id_conv(TimerIdConv.new)
