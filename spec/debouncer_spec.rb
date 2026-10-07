
require 'spec_helper'

describe Rufus::Scheduler::Debouncer do

  class ManualClock

    attr_accessor :now

    def initialize(now = 1000.0)

      @now = now
    end

    def advance(seconds)

      @now += seconds
    end
  end

  class FakeScheduledJob

    attr_accessor :next_time, :unscheduled_at
    attr_reader :debouncer, :key, :delay

    def initialize(scheduler, debouncer, key, delay, clock)

      @scheduler = scheduler
      @debouncer = debouncer
      @key = key
      @delay = delay
      @clock = clock
      @next_time = clock.now + delay
    end

    def unschedule

      @unscheduled_at = @clock.now
    end

    def trigger

      return if unscheduled_at

      round =
        @debouncer.claim_timer(@key, self, @clock.now)

      @debouncer.execute(round) if round

      if round == false && @next_time <= @clock.now
        raise 'future job unexpectedly left behind'
      end
    end
  end

  class FakeScheduler

    attr_reader :jobs, :clock

    def initialize(clock)

      @clock = clock
      @jobs = []
      @up = true
    end

    def up?

      @up
    end

    def schedule_debouncer_timer(debouncer, key, delay)

      job =
        FakeScheduledJob.new(self, debouncer, key, delay, @clock)
      @jobs << job
      job
    end

    def in(delay, &block)

      job = Object.new
      job.define_singleton_method(:unschedule) {}
      job
    end

    def run_due

      @jobs
        .select { |job| ! job.unscheduled_at && job.next_time <= @clock.now }
        .each(&:trigger)
    end

    def shutdown

      @up = false
    end
  end

  let(:clock) { ManualClock.new }
  let(:scheduler) { FakeScheduler.new(clock) }

  def new_debouncer(opts={}, &block)

    Rufus::Scheduler::Debouncer.new(
      scheduler,
      {
        quiet: 5,
        max_wait: 10,
        clock: clock,
        merge: lambda { |previous, event| [ previous, event ].flatten.compact }
      }.merge(opts),
      &block
    )
  end

  it 'waits for the quiet period and coalesces payloads in submission order' do

    batches = []
    debouncer = new_debouncer { |batch| batches << batch }

    debouncer.submit(:orders, :first)
    clock.advance(4)
    debouncer.submit(:orders, :second)

    scheduler.run_due
    expect(batches).to eq([])

    clock.advance(1)
    scheduler.run_due
    expect(batches).to eq([])

    clock.advance(4)
    scheduler.run_due

    expect(batches.size).to eq(1)
    expect(batches.first.key).to eq(:orders)
    expect(batches.first.payload).to eq([ :first, :second ])
    expect(batches.first.first_event.at).to eq(1000.0)
    expect(batches.first.last_event.at).to eq(1004.0)
  end

  it 'does not let continuous events wait longer than max_wait' do

    batches = []
    debouncer = new_debouncer { |batch| batches << batch }

    debouncer.submit(:orders, 1)

    8.times do |index|
      clock.advance(1)
      debouncer.submit(:orders, index + 2)
    end

    scheduler.run_due
    expect(batches).to eq([])

    clock.advance(2)
    scheduler.run_due

    expect(batches.map(&:payload)).to eq([ (1..9).to_a ])
  end

  it 'starts a new round for events received while a round is running' do

    synchronization = Mutex.new
    running = ConditionVariable.new
    is_running = false
    should_finish = false
    batches = []
    debouncer = new_debouncer do |batch|

      batches << batch

      synchronization.synchronize do

        is_running = true
        running.signal

        running.wait(synchronization) until should_finish
      end
    end

    debouncer.submit(:orders, :first)
    clock.advance(5)

    thread = Thread.new { scheduler.run_due }

    synchronization.synchronize do

      running.wait(synchronization) until is_running
    end

    debouncer.submit(:orders, :second)

    expect(debouncer.pending?(:orders)).to eq(true)
    expect(batches.map(&:payload)).to eq([ :first ])

    synchronization.synchronize do

      should_finish = true
      running.signal
    end

    thread.join

    clock.advance(5)
    scheduler.run_due

    expect(batches.map(&:payload)).to eq([ :first, :second ])
  end

  it 'leaves the current round pending when merging raises' do

    merge = lambda { |previous, event| previous + event }
    batches = []
    debouncer = new_debouncer(merge: merge) { |batch| batches << batch }

    debouncer.submit(:orders, [ :first ])

    expect {
      debouncer.submit(:orders, :second)
    }.to raise_error(TypeError)

    expect(debouncer.pending?(:orders)).to eq(true)

    debouncer.submit(:orders, [ :second ])
    clock.advance(5)

    scheduler.run_due

    expect(batches.first.payload).to eq([ :first, :second ])
  end

  it 'keeps keys independent' do

    batches = []
    debouncer = new_debouncer { |batch| batches << batch }

    debouncer.submit(:a, :a1)
    clock.advance(2)
    debouncer.submit(:b, :b1)
    clock.advance(3)
    scheduler.run_due

    expect(batches.map { |batch| [ batch.key, batch.payload ] }).to eq(
      [ [ :a, :a1 ] ]
    )

    clock.advance(2)
    scheduler.run_due

    expect(batches.map { |batch| [ batch.key, batch.payload ] }).to eq(
      [ [ :a, :a1 ], [ :b, :b1 ] ]
    )
  end

  it 'lets flush win against a not-yet-claimed due job' do

    batches = []
    debouncer = new_debouncer { |batch| batches << batch }

    debouncer.submit(:orders, :first)
    clock.advance(5)

    flushed = debouncer.flush(:orders)
    scheduler.run_due

    expect(batches.map(&:payload)).to eq([ :first ])
    expect(flushed.payload).to eq(:first)
  end

  it 'waits for a running round when flushing that key' do

    synchronization = Mutex.new
    running = ConditionVariable.new
    is_running = false
    should_finish = false
    batches = []
    debouncer = new_debouncer do |batch|

      batches << batch

      synchronization.synchronize do

        is_running = true
        running.signal
        running.wait(synchronization) until should_finish
      end
    end

    debouncer.submit(:orders, :first)
    clock.advance(5)

    runner = Thread.new { scheduler.run_due }

    synchronization.synchronize do

      running.wait(synchronization) until is_running
    end

    waiter = Thread.new { debouncer.flush(:orders) }

    synchronization.synchronize do

      should_finish = true
      running.signal
    end

    flushed = waiter.value
    runner.join

    expect(flushed.payload).to eq(:first)
    expect(batches.map(&:payload)).to eq([ :first ])
  end

  it 'flushes and waits for all pending and running keys' do

    synchronization = Mutex.new
    running = ConditionVariable.new
    is_running = false
    should_finish = false
    batches = []
    debouncer = new_debouncer do |batch|

      batches << batch

      synchronization.synchronize do

        is_running = true
        running.signal
        running.wait(synchronization) until should_finish
      end
    end

    debouncer.submit(:running, :first)
    clock.advance(5)

    runner = Thread.new { scheduler.run_due }

    synchronization.synchronize do

      running.wait(synchronization) until is_running
    end

    debouncer.submit(:pending, :second)

    synchronization.synchronize do

      should_finish = true
      running.signal
    end

    flushed = debouncer.flush
    runner.join

    expect(flushed.map { |batch| [ batch.key, batch.payload ] }).to eq(
      [ [ :running, :first ], [ :pending, :second ] ]
    )
  end

  it 'lets a new event win against a job due in the same instant' do

    batches = []
    debouncer = new_debouncer { |batch| batches << batch }

    debouncer.submit(:orders, :first)
    clock.advance(5)
    debouncer.submit(:orders, :second)

    scheduler.run_due

    expect(batches).to eq([])
    expect(scheduler.jobs.first.unscheduled_at).to eq(nil)

    clock.advance(5)
    scheduler.run_due

    expect(batches.map(&:payload)).to eq([ [ :first, :second ] ])
  end

  it 'does not let cancel take a job once it has claimed the round' do

    batches = []
    debouncer = new_debouncer { |batch| batches << batch }

    debouncer.submit(:orders, :first)
    clock.advance(5)

    claimed = debouncer.claim_timer(
      :orders, scheduler.jobs.first, clock.now)

    expect(debouncer.cancel(:orders)).to eq(nil)

    debouncer.execute(claimed)

    expect(batches.map(&:payload)).to eq([ :first ])
  end

  it 'cancels pending events and returns their batch' do

    debouncer = new_debouncer {}

    debouncer.submit(:orders, :first)
    clock.advance(1)
    debouncer.submit(:orders, :second)

    canceled = debouncer.cancel(:orders)
    clock.advance(5)
    scheduler.run_due

    expect(canceled.payload).to eq([ :first, :second ])
    expect(scheduler.jobs.first.unscheduled_at).to eq(1001.0)
  end

  it 'validates waits' do

    expect {
      new_debouncer(quiet: 0) {}
    }.to raise_error(ArgumentError, 'quiet must be > 0')

    expect {
      new_debouncer(max_wait: 1) {}
    }.to raise_error(ArgumentError, 'max_wait must be >= quiet')
  end

  it 'is created by the scheduler factory' do

    real_scheduler = Rufus::Scheduler.new(frequency: 10)

    begin

      debouncer =
        real_scheduler.debounce(
          5,
          max_wait: 10,
          clock: clock,
          merge: lambda { |previous, event| [ previous, event ] }
        ) {}

      expect(debouncer).to be_a(Rufus::Scheduler::Debouncer)
      expect(real_scheduler.jobs.size).to eq(0)

      debouncer.submit(:orders, :first)

      expect(real_scheduler.jobs.size).to eq(1)
      expect(real_scheduler.jobs.first).to be_a(
        Rufus::Scheduler::Debouncer::TimerJob
      )
    ensure

      real_scheduler.shutdown(:kill)
    end
  end
end
