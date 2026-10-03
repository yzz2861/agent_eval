# frozen_string_literal: true

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

  describe "cyclic dependency detection" do
    let(:error_class) { Dry::Monads::Lazy::CyclicDependencyError }

    # Fallback timeout so that a regression cannot hang the suite forever
    def join_threads(threads, timeout: 10)
      threads.each do |thread|
        next if thread.join(timeout)

        thread.kill
        raise "thread did not finish within #{timeout}s, possible deadlock"
      end
    end

    def capture_error
      yield
      nil
    rescue => e
      e
    end

    def wait_graph
      Dry::Monads::Lazy.class_eval("WAIT_GRAPH")
    end

    it "detects direct self-recursion on the same thread" do
      lazy = nil
      lazy = Lazy { lazy.value! }

      expect { lazy.value! }.to raise_error(error_class) { |error|
        expect(error.message).to include("cyclic dependency detected")
        expect(error.chain).to eql([lazy, lazy])
      }
    end

    it "detects indirect recursion on the same thread" do
      first = second = nil
      first = Lazy { second.value! }
      second = Lazy { first.value! }

      expect { first.value! }.to raise_error(error_class) { |error|
        expect(error.chain).to eql([first, second, first])
        expect(error.message).to include(" -> ")
      }
    end

    it "detects a cycle of two threads waiting on each other" do
      barrier = Concurrent::CyclicBarrier.new(2)
      first = second = nil
      first = Lazy { barrier.wait(10); second.value! }
      second = Lazy { barrier.wait(10); first.value! }

      errors = Queue.new
      threads = [
        Thread.new { errors << capture_error { first.value! } },
        Thread.new { errors << capture_error { second.value! } }
      ]
      join_threads(threads)

      raised = 2.times.map { errors.pop }
      expect(raised).to all(be_a(error_class))
      expect(raised.first.chain.size).to be >= 2
      expect(raised.first.chain.first).to equal(raised.first.chain.last)
    end

    it "releases unrelated waiters of the broken computations" do
      started = Queue.new
      barrier = Concurrent::CyclicBarrier.new(2)
      first = second = nil
      first = Lazy { started << true; barrier.wait(10); second.value! }
      second = Lazy { barrier.wait(10); first.value! }

      bystander_error = Queue.new
      owner = Thread.new { capture_error { first.value! } }
      started.pop
      bystander = Thread.new { bystander_error << capture_error { first.value! } }
      sleep 0.1 # let the bystander block on the running computation
      breaker = Thread.new { capture_error { second.value! } }
      join_threads([owner, bystander, breaker])

      expect(bystander_error.pop).to be_a(error_class)
    end

    it "computes the value only once when forced concurrently" do
      barrier = Concurrent::CyclicBarrier.new(8)
      calls = 0
      lazy = Lazy { sleep 0.05; calls += 1 }

      threads = 8.times.map { Thread.new { barrier.wait(10); lazy.value! } }
      join_threads(threads)

      expect(calls).to be(1)
      expect(threads.map(&:value)).to all(be(1))
    end

    it "cleans up the wait graph after a detected cycle" do
      barrier = Concurrent::CyclicBarrier.new(2)
      first = second = nil
      first = Lazy { barrier.wait(10); second.value! }
      second = Lazy { barrier.wait(10); first.value! }

      threads = [
        Thread.new { capture_error { first.value! } },
        Thread.new { capture_error { second.value! } }
      ]
      join_threads(threads)

      %i[@owners @waiting @computing].each do |ivar|
        expect(wait_graph.instance_variable_get(ivar)).to be_empty
      end
    end

    it "keeps the original semantics for errors raised by the computation" do
      started = Queue.new
      release = Queue.new
      lazy = Lazy { started << true; release.pop; 1 / 0 }

      owner = Thread.new { capture_error { lazy.value! } }
      started.pop
      waiter = Thread.new { capture_error { lazy.value! } }
      sleep 0.1 # let the waiter block on the running computation
      release << true
      join_threads([owner, waiter])

      expect(owner.value).to be_a(ZeroDivisionError)
      expect(waiter.value).to be_a(ZeroDivisionError)
      expect { lazy.value! }.to raise_error(ZeroDivisionError)
    end

    it "allows new computations after a detected cycle" do
      lazy = nil
      lazy = Lazy { lazy.value! }
      expect { lazy.value! }.to raise_error(error_class)

      expect(Lazy { 1 + 2 }.value!).to be(3)
    end
  end
end
