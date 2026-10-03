# frozen_string_literal: true

require "timeout"
require "concurrent/atomic/cyclic_barrier"

RSpec.describe(Dry::Monads::Lazy) do
  mixin = Dry::Monads::Lazy::Mixin
  include mixin

  subject { Lazy { 1 + 2 } }

  it_behaves_like "a monad"

  describe "#value!" do
    it "forces the computation" do
      run = false
      m = Lazy { run = true }

      expect(run).to be(false)
      m.value!
      expect(run).to be(true)
    end

    it "runs the computation on the current thread" do
      expect(Lazy { Thread.current }.value!).to be(Thread.main)
    end
  end

  describe "#force!" do
    it "is an alias for #value!" do
      expect(subject.method(:force!)).to eql(subject.method(:value!))
    end
  end

  describe "#force" do
    it "is an exception-safe version of force!" do
      forced = false
      m = Lazy { forced = true; 1 / 0 }

      expect { m.force }.not_to raise_error
      expect(forced).to be(true)
    end
  end

  describe "circular dependencies" do
    it "detects recursive forcing on the same thread" do
      lazy = nil
      lazy = Lazy { lazy.value! }

      expect { lazy.value! }.to raise_error(described_class::CircularDependencyError) do |error|
        expect(error.chain).to eq([lazy, lazy])
        expect(error.message).to include("circular dependency detected")
      end
    end

    it "reports a finite dependency chain" do
      first = nil
      second = nil
      third = nil
      first = Lazy { second.value! }
      second = Lazy { third.value! }
      third = Lazy { first.value! }

      expect { first.value! }.to raise_error(described_class::CircularDependencyError) do |error|
        expect(error.chain).to eq([first, second, third, first])
      end
    end

    it "detects a waiting cycle between two threads and releases all waiters" do
      first_started = Queue.new
      second_started = Queue.new
      release_owners = Queue.new
      cycle_barrier = Concurrent::CyclicBarrier.new(2)
      first = nil
      second = nil
      first = Lazy do
        first_started << true
        release_owners.pop
        cycle_barrier.wait
        second.value!
      end
      second = Lazy do
        second_started << true
        release_owners.pop
        cycle_barrier.wait
        first.value!
      end

      threads = []

      begin
        Timeout.timeout(5) do
          threads << Thread.new do
            first.value!
          rescue described_class::CircularDependencyError => error
            error
          end
          threads << Thread.new do
            second.value!
          rescue described_class::CircularDependencyError => error
            error
          end
          first_started.pop
          second_started.pop

          threads << Thread.new do
            first.value!
          rescue described_class::CircularDependencyError => error
            error
          end
          threads << Thread.new do
            second.value!
          rescue described_class::CircularDependencyError => error
            error
          end

          wait_until { described_class.const_get(:DEPENDENCIES).instance_variable_get(:@waiting).size == 2 }
          2.times { release_owners << true }

          errors = threads.map { |thread| thread.join.value }

          expect(errors).to all(be_a(described_class::CircularDependencyError))
          expect(errors.uniq).to contain_exactly(an_instance_of(described_class::CircularDependencyError))
          expect(errors.first.chain.size).to eq(3)
        end
      ensure
        threads.each { |thread| thread.kill unless thread.join(0.01) }
        expect(described_class.const_get(:DEPENDENCIES).instance_variable_get(:@waiting)).to be_empty
      end
    end

    it "does not treat concurrent waiters of one lazy as a cycle" do
      barrier = Concurrent::CyclicBarrier.new(2)
      owner_arrived = Queue.new
      computations = 0
      mutex = Mutex.new
      lazy = Lazy do
        mutex.synchronize { computations += 1 }
        owner_arrived << true
        barrier.wait
        :done
      end

      threads = []

      begin
        Timeout.timeout(5) do
          threads << Thread.new { lazy.value! }
          owner_arrived.pop
          2.times { threads << Thread.new { lazy.value! } }
          wait_until { described_class.const_get(:DEPENDENCIES).instance_variable_get(:@waiting).size == 2 }

          barrier.wait
          expect(lazy.value!).to be(:done)
          expect(threads.map { |thread| thread.join.value }).to eq(%i[done done done])
          expect(computations).to be(1)
        end
      ensure
        threads.each { |thread| thread.kill unless thread.join(0.01) }
      end
    end

    it "computes a concurrently forced lazy value only once" do
      owner_arrived = Queue.new
      release = Queue.new
      computations = 0
      mutex = Mutex.new
      lazy = Lazy do
        mutex.synchronize { computations += 1 }
        owner_arrived << true
        release.pop
        :done
      end

      Timeout.timeout(5) do
        owner = Thread.new { lazy.force }
        owner_arrived.pop

        concurrent_forces = 3.times.map { Thread.new { lazy.force } }
        expect(concurrent_forces.map { |thread| thread.join.value }).to all(be(lazy))

        release << true
        owner.join

        expect(lazy.value!).to be(:done)
        expect(computations).to be(1)
      end
    end

    it "propagates a user exception to concurrent waiters" do
      error_class = Class.new(StandardError)
      barrier = Concurrent::CyclicBarrier.new(2)
      computations = 0
      mutex = Mutex.new
      lazy = Lazy do
        mutex.synchronize { computations += 1 }
        barrier.wait
        raise error_class, "boom"
      end

      Timeout.timeout(5) do
        waiter = Thread.new do
          Thread.current.report_on_exception = false
          lazy.value!
        end
        barrier.wait

        expect { waiter.join }.to raise_error(error_class, "boom")
        expect { lazy.value! }.to raise_error(error_class, "boom")
        expect(computations).to be(1)
      end
    end

    it "keeps the original exception semantics for ordinary computation errors" do
      error_class = Class.new(StandardError)
      lazy = Lazy { raise error_class, "boom" }

      expect { lazy.value! }.to raise_error(error_class, "boom")
      expect(lazy).to be_evaluated
    end

    def wait_until
      deadline = Time.now + 2

      loop do
        return if yield
        raise "condition was not met before timeout" if Time.now >= deadline

        sleep(0.01)
      end
    end
  end

  describe "#fmap" do
    it "transforms the underlying value" do
      expect(subject.fmap { _1 * 2 }.value!).to be(6)
    end

    it "guarantees a single run" do
      eff = 0
      m = subject.fmap { eff += 1 }
      expect(m.value!).to be(1)
      expect(m.value!).to be(1)
      expect(eff).to be(1)
    end

    it "delays the execution until the result is required" do
      eff = 0
      m = subject.fmap { eff += 1 }.fmap { eff += 1 }
      expect(eff).to be(0)
      m.force
      expect(eff).to be(2)
    end
  end

  describe "#bind" do
    it "composes computations" do
      expect(subject.bind { |x| Lazy { x * 2 } }.value!).to be(6)
    end
  end

  describe "#to_s" do
    it "introspects the value" do
      expect(subject.to_s).to eql("Lazy(?)")

      subject.value!
      expect(subject.to_s).to eql("Lazy(3)")

      expect(Lazy { 1 / 0 }.force.to_s).to eql("Lazy(!#<ZeroDivisionError: divided by 0>)")
    end
  end

  describe "#discard" do
    it "nullifies the value" do
      expect(Lazy { 1 }.discard.value!).to be mixin::Unit
    end
  end

  describe "#evaluated?" do
    it "checks if the value is computed" do
      expect(subject.evaluated?).to be(false)
    end
  end
end
