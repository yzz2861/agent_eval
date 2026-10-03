require 'concurrent/errors'
require 'concurrent/synchronization/lockable_object'
require 'concurrent/utility/native_integer'

module Concurrent

  # A reusable synchronization aid for batches of work where the number of
  # participating parties may change between phases.
  #
  # Parties register before arriving at a phase. Once every registered party
  # has arrived, the phaser advances to the next phase. A party may also
  # atomically arrive and deregister, reducing the number of parties used by
  # following phases.
  #
  # @example
  #   phaser = Concurrent::Phaser.new(3)
  #
  #   workers = 3.times.map do |index|
  #     Thread.new do
  #       loop do
  #         result = phaser.arrive_and_wait
  #         break unless result
  #         work(index)
  #       end
  #     end
  #   end
  class Phaser < Synchronization::LockableObject

    # Create a new `Phaser`.
    #
    # @param [Integer] parties the number of parties initially registered
    # @yield optional action to run while advancing. The action receives the
    #   completed phase number and the number of parties registered for the
    #   next phase.
    # @raise [ArgumentError] if `parties` is not a non-negative integer
    def initialize(parties = 0, &action)
      Utility::NativeInteger.ensure_integer_and_bounds parties
      Utility::NativeInteger.ensure_positive parties

      super(&nil)
      synchronize { ns_initialize parties, &action }
    end

    # @return [Integer] the current phase, or the final phase after termination
    def phase
      synchronize { @phase }
    end

    # @return [Integer] the number of registered parties in the current phase
    def registered_parties
      synchronize { @registered_parties }
    end

    # @return [Integer] the number of parties which have arrived in the current phase
    def arrived_parties
      synchronize { @arrived_parties }
    end

    # @return [Integer] the number of parties which have not arrived in the current phase
    def unarrived_parties
      synchronize { @unarrived_parties }
    end

    # @return [Boolean] whether the phaser has permanently terminated
    def terminated?
      synchronize { @terminated }
    end

    # Register one party for the current phase.
    #
    # Registration is serialized with phase advancement. A registration which
    # completes before the last arrival is counted in the current phase; a
    # registration which completes afterward is counted in the next phase.
    #
    # @return [Integer] the phase for which the party was registered
    # @raise [Concurrent::LifecycleError] if the phaser has terminated
    def register
      bulk_register 1
    end

    # Register several parties for the current phase.
    #
    # @param [Integer] parties the number of parties to register
    # @return [Integer] the phase for which the parties were registered
    # @raise [ArgumentError] if `parties` is not a positive integer
    # @raise [Concurrent::LifecycleError] if the phaser has terminated
    def bulk_register(parties)
      Utility::NativeInteger.ensure_integer_and_bounds parties
      Utility::NativeInteger.ensure_positive_and_no_zero parties

      synchronize do
        raise LifecycleError, 'cannot register parties with a terminated phaser' if @terminated

        Utility::NativeInteger.ensure_integer_and_bounds @registered_parties + parties
        @registered_parties += parties
        @unarrived_parties += parties
        @phase
      end
    end

    # Record one arrival for the current phase without waiting for advancement.
    #
    # @return [Integer] the phase in which the arrival was recorded
    # @raise [Concurrent::LifecycleError] if the phaser has terminated
    # @raise [Concurrent::IllegalOperationError] if there is nothing left to arrive
    def arrive
      synchronize do
        ns_ensure_active
        ns_arrive
      end
    end

    # Atomically record one arrival and deregister the arriving party.
    #
    # If this is the last registered party, the phaser terminates. Otherwise
    # the deregistered party is absent from all later phases.
    #
    # @return [Integer] the phase in which the arrival was recorded
    # @raise [Concurrent::LifecycleError] if the phaser has terminated
    # @raise [Concurrent::IllegalOperationError] if there is nothing left to arrive
    def arrive_and_deregister
      synchronize do
        ns_ensure_active

        arrival_phase = @phase
        @arrived_parties += 1
        @unarrived_parties -= 1
        @registered_parties -= 1

        ns_advance if @unarrived_parties.zero?
        arrival_phase
      end
    end

    # Arrive and block until the phaser advances.
    #
    # A timeout only stops this call from waiting. The arrival remains counted
    # and the party remains registered.
    #
    # @param [Numeric, nil] timeout the maximum time to wait in seconds
    # @return [Boolean] `true` when the phaser advanced or terminated,
    #   `false` on timeout
    def arrive_and_wait(timeout = nil)
      arrival_phase = arrive
      await_advance(arrival_phase, timeout)
    end

    # Wait for a phase to complete.
    #
    # Unlike {#arrive_and_wait}, this does not record an arrival or change
    # registration. A timeout only stops this call from waiting.
    #
    # @param [Integer] phase_to_await the phase to wait for
    # @param [Numeric, nil] timeout the maximum time to wait in seconds
    # @return [Boolean] `true` when the phase completed or the phaser terminated,
    #   `false` on timeout
    # @raise [ArgumentError] if `phase_to_await` is not an integer
    def await_advance(phase_to_await = phase, timeout = nil)
      Utility::NativeInteger.ensure_integer_and_bounds phase_to_await
      Utility::NativeInteger.ensure_positive phase_to_await

      synchronize do
        return true if @terminated
        raise LifecycleError, 'cannot await a future phase' if phase_to_await > @phase

        ns_wait_until(timeout) { @phase != phase_to_await || @terminated }
      end
    end

    protected

    def ns_initialize(parties, &action)
      @phase = 0
      @registered_parties = parties
      @arrived_parties = 0
      @unarrived_parties = parties
      @terminated = false
      @action = action
    end

    def ns_ensure_active
      raise LifecycleError, 'cannot use a terminated phaser' if @terminated
      if @registered_parties.zero? || @unarrived_parties.zero?
        raise IllegalOperationError, 'all registered parties have already arrived'
      end
    end

    def ns_arrive
      arrival_phase = @phase
      @arrived_parties += 1
      @unarrived_parties -= 1
      ns_advance if @unarrived_parties.zero?
      arrival_phase
    end

    def ns_advance
      completed_phase = @phase
      @action.call(completed_phase, @registered_parties) if @action

      @phase += 1
      if @registered_parties.zero?
        @terminated = true
        @arrived_parties = 0
        @unarrived_parties = 0
      else
        @arrived_parties = 0
        @unarrived_parties = @registered_parties
      end

      ns_broadcast
    end
  end
end
