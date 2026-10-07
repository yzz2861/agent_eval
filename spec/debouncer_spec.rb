
require 'spec_helper'


describe Rufus::Scheduler::Debouncer do

  class ControlledClock

    class Job

      attr_reader :due_at, :sequence

      def initialize(due_at, block, clock, sequence)

        @due_at = due_at
        @block = block
        @clock = clock
        @sequence = sequence
        @cancelled = false
      end

      def unschedule

        @cancelled = true
      end

      def cancelled?

        @cancelled
      end

      def fire

        return if @cancelled

        @clock.remove_job(self)
        @block.call
      end
    end

    attr_accessor :now
    attr_reader :jobs

    def initialize

      @now = 0
      @jobs = []
      @sequence = 0
    end

    def schedule(delay, block)

      @sequence += 1

      job = Job.new(@now + delay, block, self, @sequence)
      @jobs << job
      job
    end

    def scheduled_job

      @jobs
        .reject(&:cancelled?)
        .min_by { |job| [ job.due_at, job.sequence ] }
    end

    def advance(seconds)

      @now += seconds

      while (job = due_job)
        job.fire
      end
    end

    def remove_job(job)

      @jobs.delete(job)
    end

    private

    def due_job

      @jobs
        .reject(&:cancelled?)
        .select { |job| job.due_at <= @now }
        .min_by { |job| [ job.due_at, job.sequence ] }
    end
  end

  def new_debouncer(clock, options={}, &block)

    merge = options.delete(:merge) || lambda { |a, b| Array(a) + Array(b) }
    block ||= lambda { |_, _| }

    Rufus::Scheduler::Debouncer.new(
      nil,
      {
        :quiet => 2,
        :max_wait => 5,
        :clock => clock,
        :schedule => lambda { |delay, callback| clock.schedule(delay, callback) },
        :merge => merge
      }.merge(options),
      &block)
  end

  it 'waits for a quiet period and records first and last events' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock) { |_, _, batch| batches << batch }

    debouncer.submit(:a, 1)
    clock.advance(1)
    debouncer.submit(:a, 2)
    clock.advance(1)
    debouncer.submit(:a, 3)

    expect(batches).to be_empty

    clock.advance(1)
    expect(batches).to be_empty

    clock.advance(1)

    expect(batches.size).to eq(1)
    expect(batches.first.key).to eq(:a)
    expect(batches.first.payload).to eq([ 1, 2, 3 ])
    expect(batches.first.first_event.payload).to eq(1)
    expect(batches.first.last_event.payload).to eq(3)
    expect(batches.first.first_event.time).to eq(0)
    expect(batches.first.last_event.time).to eq(2)
  end

  it 'runs sustained events once max_wait is reached' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock) { |_, payload| batches << payload }

    (1..5).each do |n|
      clock.advance(1) unless n == 1
      debouncer.submit(:a, n)
    end

    expect(batches).to be_empty

    clock.advance(1)

    expect(batches).to eq([ [ 1, 2, 3, 4, 5 ] ])
    expect(debouncer.pending?(:a)).to eq(false)
  end

  it 'starts a new round for an event submitted while the callback runs' do

    clock = ControlledClock.new
    batches = []
    debouncer = nil

    debouncer =
      new_debouncer(
        clock,
        :merge => lambda { |_, incoming| incoming }
      ) do |key, payload|
        batches << payload
        debouncer.submit(key, 'during') if payload == 'first'
      end

    debouncer.submit(:a, 'first')
    clock.advance(2)

    expect(batches).to eq([ 'first' ])
    expect(debouncer.pending?(:a)).to eq(true)

    clock.advance(2)

    expect(batches).to eq([ 'first', 'during' ])
  end

  it 'lets flush claim pending events before a due timer' do

    clock = ControlledClock.new
    timer_batches = []
    debouncer = new_debouncer(clock) { |_, payload| timer_batches << payload }
    debouncer.submit(:a, 1)
    debouncer.submit(:a, 2)

    clock.now = 2
    timer = clock.scheduled_job

    flushed = debouncer.flush(:a)
    timer.fire

    expect(flushed.payload).to eq([ 1, 2 ])
    expect(timer_batches).to eq([ [ 1, 2 ] ])
    expect(debouncer.flush(:a)).to eq(nil)
  end

  it 'ignores a stale timer after a quiet period gets extended' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock) { |_, payload| batches << payload }

    debouncer.submit(:a, 1)
    stale_timer = clock.scheduled_job

    clock.advance(1)
    debouncer.submit(:a, 2)

    stale_timer.fire

    expect(batches).to be_empty

    clock.advance(2)

    expect(batches).to eq([ [ 1, 2 ] ])
  end

  it 'does not let flush take a batch already claimed by a due timer' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock) { |_, payload| batches << payload }
    debouncer.submit(:a, 1)

    clock.now = 2
    timer = clock.scheduled_job
    timer.fire

    expect(batches).to eq([ 1 ])
    expect(debouncer.flush(:a)).to eq(nil)
  end

  it 'lets cancel claim pending events before a due timer' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock) { |_, payload| batches << payload }
    debouncer.submit(:a, 1)
    clock.now = 2
    timer = clock.scheduled_job

    cancelled = debouncer.cancel(:a)
    timer.fire

    expect(cancelled.payload).to eq(1)
    expect(batches).to be_empty
    expect(debouncer.pending?(:a)).to eq(false)
  end

  it 'does not cancel a batch already claimed by a due timer' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock) { |_, payload| batches << payload }
    debouncer.submit(:a, 1)
    timer = clock.scheduled_job

    clock.advance(2)
    timer.fire

    expect(batches).to eq([ 1 ])
    expect(debouncer.cancel(:a)).to eq(nil)
  end

  it 'flushes and cancels each key independently' do

    clock = ControlledClock.new
    debouncer = new_debouncer(clock)

    debouncer.submit(:a, 1)
    debouncer.submit(:b, 2)

    expect(debouncer.flush(:a).payload).to eq(1)
    expect(debouncer.pending_keys).to eq([ :b ])

    expect(debouncer.cancel(:b).payload).to eq(2)
    expect(debouncer.pending_keys).to eq([])
  end

  it 'flushes and cancels all pending keys' do

    clock = ControlledClock.new
    debouncer = new_debouncer(clock)

    debouncer.submit(:a, 1)
    debouncer.submit(:b, 2)

    expect(debouncer.flush.collect(&:key)).to eq([ :a, :b ])

    debouncer.submit(:c, 3)
    debouncer.submit(:d, 4)

    expect(debouncer.cancel.collect(&:payload)).to eq([ 3, 4 ])
  end

  it 'keeps the previous payload when merge raises' do

    clock = ControlledClock.new
    batches = []
    merge =
      lambda do |current, incoming|
        fail 'bad event' if incoming == :bad
        Array(current) + Array(incoming)
      end
    debouncer = new_debouncer(clock, :merge => merge) do |_, payload|
      batches << payload
    end

    debouncer.submit(:a, 1)

    expect {
      debouncer.submit(:a, :bad)
    }.to raise_error(RuntimeError, 'bad event')

    clock.advance(2)

    expect(batches).to eq([ 1 ])
  end

  it 'merges current payload before incoming payload in submission order' do

    clock = ControlledClock.new
    batches = []
    merge = lambda { |current, incoming| "#{current}>#{incoming}" }
    debouncer = new_debouncer(clock, :merge => merge) do |_, payload|
      batches << payload
    end

    debouncer.submit(:a, 'one')
    debouncer.submit(:a, 'two')
    clock.advance(2)

    expect(batches).to eq([ 'one>two' ])
  end

  it 'accepts quiet_period as an alias for quiet' do

    clock = ControlledClock.new
    batches = []
    debouncer = new_debouncer(clock)

    debouncer =
      Rufus::Scheduler::Debouncer.new(
        nil,
        :quiet_period => 1,
        :max_wait => 5,
        :clock => clock,
        :schedule => lambda { |delay, callback| clock.schedule(delay, callback) },
        :merge => lambda { |a, b| Array(a) + Array(b) }
      ) { |_, payload| batches << payload }

    debouncer.submit(:a, 1)
    clock.advance(1)

    expect(batches).to eq([ 1 ])
  end

  it 'works when attached to a real scheduler' do

    scheduler = Rufus::Scheduler.new

    begin

      debouncer =
        scheduler.debouncer(
          :quiet => 10,
          :max_wait => 20,
          :merge => lambda { |a, b| Array(a) + Array(b) }
        ) { |_, _| }

      debouncer.submit(:a, 1)
      debouncer.submit(:a, 2)

      expect(debouncer.flush(:a).payload).to eq([ 1, 2 ])
    ensure
      scheduler.shutdown
    end
  end
end
