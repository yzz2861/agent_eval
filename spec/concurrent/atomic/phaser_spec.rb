require 'concurrent/atomic/phaser'
require 'concurrent/atomic/count_down_latch'

module Concurrent

  RSpec.describe Phaser do

    describe '#initialize' do
      it 'accepts zero initially registered parties' do
        phaser = described_class.new

        expect(phaser.phase).to eq 0
        expect(phaser.registered_parties).to eq 0
        expect(phaser).not_to be_terminated
      end

      it 'raises if the initial party count is negative' do
        expect { described_class.new(-1) }.to raise_error(ArgumentError)
      end

      it 'raises if the initial party count is not an integer' do
        expect { described_class.new(:one) }.to raise_error(ArgumentError)
      end
    end

    describe '#register' do
      it 'adds a party to an active phaser' do
        phaser = described_class.new

        expect(phaser.register).to eq 0
        expect(phaser.registered_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1
      end

      it 'raises LifecycleError after termination' do
        phaser = described_class.new(1)
        phaser.arrive_and_deregister

        expect { phaser.register }.to raise_error(LifecycleError)
        expect { phaser.bulk_register(2) }.to raise_error(LifecycleError)
      end

      it 'validates bulk registration counts' do
        phaser = described_class.new

        expect { phaser.bulk_register(0) }.to raise_error(ArgumentError)
        expect { phaser.bulk_register(-1) }.to raise_error(ArgumentError)
        expect { phaser.bulk_register(:one) }.to raise_error(ArgumentError)
      end
    end

    describe '#arrive' do
      it 'raises IllegalOperationError without registered parties' do
        phaser = described_class.new

        expect { phaser.arrive }.to raise_error(IllegalOperationError)
      end

      it 'raises LifecycleError after termination' do
        phaser = described_class.new(1)
        phaser.arrive_and_deregister

        expect { phaser.arrive }.to raise_error(LifecycleError)
        expect { phaser.arrive_and_deregister }.to raise_error(LifecycleError)
      end
    end

    describe 'advancement' do
      it 'runs phases with a changing number of parties' do
        events = []
        phaser = described_class.new(2) do |completed_phase, parties|
          events << [completed_phase, parties]
        end

        phaser.arrive
        expect(phaser.arrive_and_deregister).to eq 0

        expect(phaser.phase).to eq 1
        expect(phaser.registered_parties).to eq 1
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 1
        expect(events).to eq [[0, 1]]

        phaser.arrive_and_deregister

        expect(phaser.phase).to eq 2
        expect(phaser.registered_parties).to eq 0
        expect(phaser).to be_terminated
        expect(events).to eq [[0, 1], [1, 0]]
      end

      it 'assigns a concurrent registration to the current phase when it completes first' do
        arrival_started = CountDownLatch.new(1)
        allow_arrival = CountDownLatch.new(1)

        phaser = Class.new(described_class) do
          define_method(:arrive) do
            arrival_started.count_down
            allow_arrival.wait
            super()
          end
        end.new(1)

        arrival = in_thread { phaser.arrive }
        arrival_started.wait(1)

        expect(phaser.register).to eq 0
        expect(phaser.registered_parties).to eq 2

        allow_arrival.count_down
        expect(arrival.value).to eq 0

        expect(phaser.phase).to eq 0
        expect(phaser.arrived_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1

        expect(phaser.arrive).to eq 0
        expect(phaser.phase).to eq 1
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2
      end

      it 'assigns a concurrent registration to the next phase when advancement completes first' do
        advance_started = CountDownLatch.new(1)
        allow_advance = CountDownLatch.new(1)
        register_started = CountDownLatch.new(1)

        phaser = described_class.new(2) do
          advance_started.count_down
          allow_advance.wait
        end

        remaining_worker = in_thread { phaser.arrive }
        expect(remaining_worker.value).to eq 0
        exiting_worker = in_thread { phaser.arrive_and_deregister }
        advance_started.wait(1)

        registration = in_thread do
          register_started.count_down
          phaser.register
        end

        register_started.wait(1)
        repeat_until_success { expect(registration.status).to eq 'sleep' }
        allow_advance.count_down

        expect(exiting_worker.value).to eq 0
        expect(registration.value).to eq 1
        expect(phaser.phase).to eq 1
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2
      end

      it 'rejects a registration blocked until the last party terminates the phaser' do
        advance_started = CountDownLatch.new(1)
        allow_advance = CountDownLatch.new(1)
        register_started = CountDownLatch.new(1)

        phaser = described_class.new(1) do
          advance_started.count_down
          allow_advance.wait
        end

        arrival = in_thread { phaser.arrive_and_deregister }
        advance_started.wait(1)

        registration = in_thread do
          register_started.count_down
          begin
            phaser.register
            :registered
          rescue LifecycleError
            :terminated
          end
        end

        register_started.wait(1)
        repeat_until_success { expect(registration.status).to eq 'sleep' }
        allow_advance.count_down

        expect(arrival.value).to eq 0
        expect(registration.value).to eq :terminated
        expect(phaser.phase).to eq 1
        expect(phaser.registered_parties).to eq 0
        expect(phaser).to be_terminated
      end
    end

    describe '#arrive_and_wait' do
      it 'wakes waiting parties and terminates after the last party deregisters' do
        phaser = described_class.new(2)
        worker = in_thread do
          advanced = phaser.arrive_and_wait
          phaser.arrive_and_deregister
          advanced
        end

        repeat_until_success { expect(phaser.arrived_parties).to eq 1 }
        phaser.arrive_and_deregister

        join_with worker
        expect(worker.value).to be(true)
        expect(phaser.phase).to eq 2
        expect(phaser.registered_parties).to eq 0
        expect(phaser).to be_terminated
      end

      it 'does not deregister or recount an arrival when waiting times out' do
        phaser = described_class.new(2)

        expect(phaser.arrive_and_wait(0)).to be(false)
        expect(phaser.phase).to eq 0
        expect(phaser.registered_parties).to eq 2
        expect(phaser.arrived_parties).to eq 1
        expect(phaser.unarrived_parties).to eq 1

        expect(phaser.await_advance(0, 0)).to be(false)
        expect(phaser.arrived_parties).to eq 1

        phaser.arrive
        expect(phaser.phase).to eq 1
        expect(phaser.arrived_parties).to eq 0
        expect(phaser.unarrived_parties).to eq 2

        phaser.arrive
        expect(phaser.phase).to eq 1
        expect(phaser.arrived_parties).to eq 1

        phaser.arrive
        expect(phaser.phase).to eq 2
        expect(phaser.registered_parties).to eq 2
      end
    end

    describe '#await_advance' do
      it 'returns immediately for an already completed phase' do
        phaser = described_class.new(1)
        phaser.arrive

        expect(phaser.await_advance(0, 0)).to be(true)
      end

      it 'returns true immediately after termination' do
        phaser = described_class.new(1)
        phaser.arrive_and_deregister

        expect(phaser.await_advance(phaser.phase, 0)).to be(true)
      end

      it 'validates the awaited phase' do
        phaser = described_class.new(1)

        expect { phaser.await_advance(1) }.to raise_error(LifecycleError)
        expect { phaser.await_advance(-1) }.to raise_error(ArgumentError)
        expect { phaser.await_advance(:one) }.to raise_error(ArgumentError)
      end
    end
  end
end
