require 'concurrent/atomic/phaser'

module Concurrent
  RSpec.describe Phaser do
    class ControlledPhaser < described_class
      attr_reader :advances

      def initialize(parties, advance_queue = nil)
        super(parties)
        @advance_queue = advance_queue
        @advances = []
      end

      protected

      def on_advance(phase, registered_parties)
        @advances << [phase, registered_parties]
        @advance_queue.pop if @advance_queue
        super
      end
    end

    describe '#initialize' do
      it 'starts with zero registered parties without terminating' do
        phaser = described_class.new

        expect(phaser.phase).to eq 0
        expect(phaser.registered_parties).to eq 0
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 0
        expect(phaser).not_to be_terminated
      end

      it 'accepts a positive number of initially registered parties' do
        phaser = described_class.new(1)

        expect(phaser.registered_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1
      end

      it 'rejects negative or non-integer parties' do
        expect { described_class.new(-1) }.to raise_error(ArgumentError)
        expect { described_class.new('1') }.to raise_error(ArgumentError)
      end
    end

    describe '#register' do
      it 'adds parties to the current phase' do
        phaser = described_class.new(1)

        expect(phaser.register).to eq 0
        expect(phaser.register(2)).to eq 0
        expect(phaser.registered_parties).to eq 4
        expect(phaser.unarrived_parties).to eq 4
      end

      it 'assigns a registration made during advancement to the next phase' do
        advance_queue = Queue.new
        phaser = ControlledPhaser.new(1, advance_queue)

        arrival = in_thread { phaser.arrive }
        repeat_until_success { expect(phaser.advances).to eq [[0, 1]] }

        registration = in_thread { phaser.register }
        repeat_until_success { expect(registration.status).to eq 'sleep' }

        advance_queue << :continue
        join_with [arrival, registration]

        expect(registration.value).to eq 1
        expect(phaser.phase).to eq 1
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2
      end

      it 'rejects registrations after termination' do
        phaser = described_class.new(1)
        phaser.arrive_and_deregister

        expect(phaser).to be_terminated
        expect { phaser.register }.to raise_error(LifecycleError)
      end
    end

    describe '#arrive' do
      it 'advances after all currently registered parties arrive' do
        phaser = described_class.new(2)

        expect(phaser.arrive).to eq 0
        expect(phaser.phase).to eq 0
        expect(phaser.arrived_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1

        expect(phaser.arrive).to eq 0
        expect(phaser.phase).to eq 1
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2
      end

      it 'does not carry an arrival into the following phase' do
        phaser = described_class.new(2)
        phaser.arrive
        phaser.arrive

        expect(phaser.phase).to eq 1
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2

        expect(phaser.arrive).to eq 1
        expect(phaser.phase).to eq 1
        expect(phaser.unarrived_parties).to eq 1
      end

      it 'supports workers registering between rounds' do
        phaser = described_class.new(1)

        expect(phaser.arrive).to eq 0
        expect(phaser.register).to eq 1
        expect(phaser.unarrived_parties).to eq 2

        expect(phaser.arrive).to eq 1
        expect(phaser.phase).to eq 1
        expect(phaser.arrive).to eq 1
        expect(phaser.phase).to eq 2
      end
    end

    describe '#arrive_and_deregister' do
      it 'removes the arriving party from future phases' do
        phaser = described_class.new(2)

        expect(phaser.arrive_and_deregister).to eq 0
        expect(phaser.phase).to eq 0
        expect(phaser.registered_parties).to eq 1
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 1

        expect(phaser.arrive_and_deregister).to eq(-1)
        expect(phaser.phase).to eq(-1)
        expect(phaser).to be_terminated
      end

      it 'terminates the only party of an otherwise empty phaser' do
        phaser = described_class.new
        phaser.register

        expect(phaser.arrive_and_deregister).to eq(-1)
        expect(phaser.registered_parties).to eq 0
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 0
      end

      it 'does not allow arrival after termination' do
        phaser = described_class.new(1)
        phaser.arrive_and_deregister

        expect { phaser.arrive }.to raise_error(LifecycleError)
        expect { phaser.arrive_and_deregister }.to raise_error(LifecycleError)
      end
    end

    describe '#await_advance' do
      it 'waits for and returns the advanced phase' do
        phaser = described_class.new(1)
        results = Queue.new
        waiter = in_thread { results << phaser.await_advance }

        repeat_until_success { expect(phaser.number_waiting).to eq 1 }
        expect(phaser.arrive).to eq 0
        join_with waiter

        expect(results.pop(true)).to eq 1
        expect(phaser.phase).to eq 1
        expect(phaser.number_waiting).to eq 0
        expect(phaser.registered_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1
      end

      it 'returns immediately for a completed phase' do
        phaser = described_class.new(1)
        phaser.arrive

        expect(phaser.await_advance(0, 0)).to eq 1
      end

      it 'returns the terminated phase without raising' do
        phaser = described_class.new(1)
        phaser.arrive_and_deregister

        expect(phaser.await_advance(nil, 0)).to eq(-1)
      end

      it 'does not deregister or arrive when a timeout expires' do
        phaser = described_class.new(2)

        expect(phaser.await_advance(nil, 0)).to be(false)
        expect(phaser.number_waiting).to eq 0
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2

        expect(phaser.arrive).to eq 0
        expect(phaser.phase).to eq 0
        expect(phaser.registered_parties).to eq 2
        expect(phaser.unarrived_parties).to eq 1

        expect(phaser.arrive).to eq 0
        expect(phaser.registered_parties).to eq 2
        expect(phaser.unarrived_parties).to eq 2
      end
    end

    describe '#arrive_and_await_advance' do
      it 'keeps the caller registered after a wait timeout' do
        phaser = described_class.new(2)

        expect(phaser.arrive_and_await_advance(0)).to be(false)
        expect(phaser.phase).to eq 0
        expect(phaser.number_waiting).to eq 0
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1

        expect(phaser.arrive).to eq 0
        expect(phaser.phase).to eq 1
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2
      end
    end
  end
end
