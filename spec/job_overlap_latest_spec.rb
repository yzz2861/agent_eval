
#
# Specifying rufus-scheduler
#
# overlap: :latest
#

require 'spec_helper'


describe 'Rufus::Scheduler :overlap => :latest' do

  before :each do

    @taoe = Thread.abort_on_exception
    Thread.abort_on_exception = false

    @ose = $stderr
    $stderr = StringIO.new

    @scheduler = Rufus::Scheduler.new

    @mutex = Mutex.new
    @starts = []
    @active = 0
    @max_active = 0

    @gate = Queue.new
      # event gate: each job instance pops one permit before ending
  end

  after :each do

    @scheduler.shutdown

    Thread.abort_on_exception = @taoe

    $stderr = @ose
  end

  def gated_job(schedule, opts={})

    @scheduler.send(:schedule_every, schedule, opts) do

      @mutex.synchronize do
        @starts << [ Time.now, Thread.current ]
        @active += 1
        @max_active = @active if @active > @max_active
      end

      @gate.pop # wait for a permit before ending

      @mutex.synchronize { @active -= 1 }
    end
  end

  def starts

    @mutex.synchronize { @starts.dup }
  end

  def max_active

    @mutex.synchronize { @max_active }
  end

  it 'merges triggers into a single pending slot while a run is active' do

    job = gated_job('0.3', overlap: :latest)

    wait_until { starts.size == 1 }

    sleep 1.1 # ~3 triggers get merged while the first run is gated

    p0 = job.latest_pending

    expect(p0).not_to eq(nil)
    expect(p0.merged).to be >= 2

    sleep 0.7 # ~2 more triggers, the slot keeps the latest time

    p1 = job.latest_pending

    expect(p1).not_to eq(nil)
    expect(p1.merged).to be > p0.merged
    expect(p1.time).to be > p0.time

    expect(max_active).to eq(1) # thread limit: a single run at a time

    job.pause # no further scheduled triggers

    @gate << :go # let the first run end

    wait_until { starts.size == 2 }

    expect(job.latest_pending).to eq(nil) # slot got consumed

    @gate << :go # let the follow-up run end

    sleep 0.8

    expect(starts.size).to eq(2) # nothing else ran
    expect(max_active).to eq(1)
  end

  it 'drops the pending slot when unscheduled' do

    job = gated_job('0.3', overlap: :latest)

    wait_until { starts.size == 1 }

    sleep 1.0

    expect(job.latest_pending).not_to eq(nil)

    job.unschedule

    expect(job.latest_pending).to eq(nil)

    @gate << :go

    sleep 0.8

    expect(starts.size).to eq(1) # the pending trigger never ran
  end

  it 'merges manual triggers (trigger_off_schedule) into the pending slot' do

    job = gated_job('10s', overlap: :latest)

    job.trigger_off_schedule

    wait_until { starts.size == 1 }

    job.trigger_off_schedule
    job.trigger_off_schedule

    p = job.latest_pending

    expect(p).not_to eq(nil)
    expect(p.merged).to eq(2)

    @gate << :go

    wait_until { starts.size == 2 }

    @gate << :go

    sleep 0.5

    expect(starts.size).to eq(2)
    expect(max_active).to eq(1)
  end

  it 'does not fill the pending slot while the job is paused' do

    job =
      @scheduler.schedule_every('0.3', overlap: :latest) do
        @mutex.synchronize { @starts << [ Time.now, Thread.current ] }
      end

    job.pause

    sleep 1.0

    expect(starts.size).to eq(0)
    expect(job.latest_pending).to eq(nil)

    job.resume

    wait_until { starts.size > 0 }
  end

  it 'dispatches the pending run via the work queue, not recursively' do

    job = gated_job('0.3', overlap: :latest, blocking: true)

    wait_until { starts.size == 1 }

      # the first run monopolizes the scheduler thread (blocking: true)
    expect(starts.last[1]).to eq(@scheduler.thread)

    job.trigger_off_schedule # merges into the pending slot

    expect(job.latest_pending).not_to eq(nil)

    job.pause # no further scheduled triggers

    @gate << :go

    wait_until { starts.size == 2 }

      # the follow-up run happened on a work thread, it was not
      # called recursively on the scheduler thread stack
    expect(starts.last[1]).not_to eq(@scheduler.thread)
    expect(starts.last[1][:rufus_scheduler_work_thread]).to eq(true)

    @gate << :go

    sleep 0.5

    expect(starts.size).to eq(2)
    expect(max_active).to eq(1)
  end

  it 'loses no trigger and runs no slot twice when completions and triggers race' do

    job = gated_job('0.3', overlap: :latest)

    wait_until { starts.size == 1 }

    sleep 1.0 # make sure some merging happened

    expect(job.latest_pending).not_to eq(nil)

    pusher =
      Thread.new do
        24.times do
          @gate << :go
          sleep(0.11 + rand * 0.17) # racy vs the 0.3s schedule
        end
      end

    wait_until(14, 0.2) { ! pusher.alive? }

    job.pause # no further scheduled triggers

      # drain: hand out permits until nothing is active or pending
    wait_until(14, 0.05) do
      @gate << :go
      job.latest_pending.nil? &&
        @active < 1 &&
        starts.size == job.count
    end

      # every dispatched run (job.count) got started exactly once
    expect(starts.size).to eq(job.count)
    expect(job.latest_pending).to eq(nil)
    expect(max_active).to eq(1)
  end
end
