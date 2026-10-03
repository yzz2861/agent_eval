require 'concurrent/synchronization/lockable_object'
require 'concurrent/utility/native_integer'

module Concurrent

  # A reusable synchronization aid for a variable number of parties working in
  # rounds. Parties may register, arrive at the current phase, wait for the
  # phase to advance, or arrive and deregister.
  class Phaser < Synchronization::LockableObject

    # Create a new `Phaser` with `parties` initially registered parties.
    #
    # A phaser created with zero parties is not terminated. It accepts
    # registrations until the last registered party deregisters, after which it
    # becomes terminated permanently.
    #
    # @param [Integer] parties the number of initially registered parties
    # @raise [ArgumentError] if `parties` is not a non-negative integer
    def initialize(parties = 0)
      Utility::NativeInteger.ensure_integer_and_bounds parties
      Utility::NativeInteger.ensure_positive parties

      super()
      synchronize { ns_initialize parties }
    end

    # @return [Integer] the current phase number; negative after termination
    def phase
      synchronize { @phase }
    end
    alias get_phase phase

    # @return [Integer] the number of parties registered in the current phase
    def registered_parties
      synchronize { @registered_parties }
    end
    alias get_registered_parties registered_parties

    # @return [Integer] the number of registered parties that have arrived
    def arrived_parties
      synchronize { @arrived_parties }
    end
    alias get_arrived_parties arrived_parties

    # @return [Integer] the number of registered parties that have not arrived
    def unarrived_parties
      synchronize { @unarrived_parties }
    end
    alias get_unarrived_parties unarrived_parties

    # @return [Integer] the number of threads currently waiting for a phase
    #   advance
    def number_waiting
      synchronize { @waiting_count }
    end

    # @return [Boolean] whether the phaser has terminated permanently
    def terminated?
      synchronize { @phase < 0 }
    end

    # Register parties for the current phase when called before the last
    # arrival, or for the next phase when called after advancement has begun.
    #
    # @param [Integer] parties the number of parties to register
    # @return [Integer] the phase to which the parties belong
    # @raise [ArgumentError] if `parties` is not a positive integer
    # @raise [LifecycleError] if the phaser has terminated
    def register(parties = 1)
      Utility::NativeInteger.ensure_integer_and_bounds parties
      Utility::NativeInteger.ensure_positive_and_no_zero parties

      synchronize do
        ns_ensure_active!
        Utility::NativeInteger.ensure_upper_bound @registered_parties + parties
        @registered_parties += parties
        @unarrived_parties += parties
        @phase
      end
    end
    alias bulk_register register

    # Arrive at the current phase without waiting.
    #
    # @return [Integer] the arrived phase; negative after termination
    # @raise [LifecycleError] if the phaser has terminated or no party can
    #   arrive
    def arrive
      synchronize do
        ns_ensure_active!
        raise LifecycleError, 'no registered party can arrive' if @unarrived_parties.zero?

        arrived_phase = @phase
        @arrived_parties += 1
        @unarrived_parties -= 1

        if @unarrived_parties.zero?
          ns_advance
          @phase < 0 ? @phase : arrived_phase
        else
          arrived_phase
        end
      end
    end

    # Arrive at the current phase and deregister the arriving party.
    #
    # Deregistering the last party terminates the phaser.
    #
    # @return [Integer] the arrived phase, or a negative phase if this call
    #   terminates the phaser
    # @raise [LifecycleError] if the phaser has terminated or no party can
    #   arrive
    def arrive_and_deregister
      synchronize do
        ns_ensure_active!
        raise LifecycleError, 'no registered party can arrive and deregister' if @unarrived_parties.zero?

        arrived_phase = @phase
        @registered_parties -= 1
        @unarrived_parties -= 1

        if @unarrived_parties.zero?
          ns_advance
          @phase < 0 ? @phase : arrived_phase
        else
          arrived_phase
        end
      end
    end

    # Wait for the indicated phase to advance.
    #
    # A timeout only stops the calling thread waiting. It does not deregister
    # the caller and does not undo an arrival made before waiting.
    #
    # @param [Integer] waited_phase the phase to wait for; defaults to the
    #   current phase captured while synchronized
    # @param [Numeric, nil] timeout the maximum waiting time in seconds
    # @return [Integer, false] the current phase after advancement or
    #   termination, or `false` on timeout
    def await_advance(waited_phase = nil, timeout = nil)
      synchronize do
        waited_phase = @phase if waited_phase.nil?
        return @phase if @phase < 0 || @phase != waited_phase

        @waiting_count += 1
        begin
          advanced = ns_wait_until(timeout) { @phase < 0 || @phase != waited_phase }
          advanced ? @phase : false
        ensure
          @waiting_count -= 1
        end
      end
    end

    # Arrive at the current phase and wait for all other registered parties to
    # arrive. A timeout only stops waiting; the caller remains registered.
    #
    # @param [Numeric, nil] timeout the maximum waiting time in seconds
    # @return [Integer, false] the advanced phase, a negative phase after
    #   termination, or `false` on timeout
    def arrive_and_await_advance(timeout = nil)
      arrived_phase = arrive
      return arrived_phase if arrived_phase < 0

      await_advance arrived_phase, timeout
    end
    alias arrive_and_wait_advance arrive_and_await_advance

    protected

    # Called by the last arriving party before the phase state changes. Override
    # to perform phase actions or customize termination. This method is called
    # while the phaser is synchronized.
    #
    # @param [Integer] phase the phase being completed
    # @param [Integer] registered_parties the number of parties still registered
    # @return [Boolean] whether the phaser should terminate
    def on_advance(phase, registered_parties)
      registered_parties.zero?
    end

    def ns_initialize(parties)
      @phase = 0
      @registered_parties = parties
      @arrived_parties = 0
      @unarrived_parties = parties
      @waiting_count = 0
    end

    def ns_ensure_active!
      raise LifecycleError, 'cannot use a terminated phaser' if @phase < 0
    end

    def ns_advance
      completed_phase = @phase
      terminate = on_advance completed_phase, @registered_parties

      if terminate
        @phase = -(completed_phase + 1)
        @registered_parties = 0
        @arrived_parties = 0
        @unarrived_parties = 0
      else
        @phase = completed_phase + 1
        @arrived_parties = 0
        @unarrived_parties = @registered_parties
      end

      ns_broadcast
    end
  end
end
