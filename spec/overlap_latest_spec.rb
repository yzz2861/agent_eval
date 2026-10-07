
#
# Specifying rufus-scheduler
#

require 'spec_helper'


describe 'overlap: :latest' do

  before :each do

    @scheduler = Rufus::Scheduler.new

    @gate = Queue.new
      # event gate, job instances block on it until the test
      # pushes a token and lets them end

    @clock = Mutex.new
    @starts = []
    @ends = []
    @run_threads = []
    @concurrent = 0
    @max_concurrent = 0
  end

  after :each do

    @gate.close
    @scheduler.shutdown
  end

  def make_job(frequency='10s', opts={})

    @scheduler.schedule_every(frequency, { overlap: :latest }.merge(opts)) do

      @clock.synchronize do
        @concurrent += 1
        @max_concurrent = @concurrent if @concurrent > @max_concurrent
        @starts << monow
        @run_threads << Thread.current
      end

      @gate.pop

      @clock.synchronize do
        @concurrent -= 1
        @ends << monow
      end
    end
  end

  it 'starts immediately when no instance is running' do

    job = make_job

    job.trigger_off_schedule

    wait_until { @starts.size == 1 }

    expect(job.pending_trigger).to eq(nil)

    @gate << :go
    wait_until { @ends.size == 1 }
  end

  it 'coalesces triggers into a single pending slot (latest time, merge count)' do

    job = make_job

    job.trigger_off_schedule
    wait_until { @starts.size == 1 }

    t1 = Time.at(1_700_000_001)
    t2 = Time.at(1_700_000_002)
    t3 = Time.at(1_700_000_003)

    job.trigger_off_schedule(t1)
    job.trigger_off_schedule(t2)
    job.trigger_off_schedule(t3)

    pt = job.pending_trigger

    expect(pt.time).to eq(t3)
    expect(pt.merged).to eq(2)

    expect(@starts.size).to eq(1)
      # the three triggers above did not start anything

    @gate << :go
    wait_until { @starts.size == 2 }

    expect(job.pending_trigger).to eq(nil)
    expect(@starts[1]).to be >= @ends[0]
      # the pending run starts after the current run has ended

    @gate << :go
    wait_until { @ends.size == 2 }

    sleep 0.4

    expect(@starts.size).to eq(2)
      # exactly one pending run, not one per coalesced trigger
    expect(@max_concurrent).to eq(1)
  end

  it 'coalesces scheduled triggers while a run is in flight' do

    job = make_job('0.3s')

    wait_until { @starts.size == 1 }

    sleep 1.2

    pt = job.pending_trigger

    expect(pt).not_to eq(nil)
    expect(pt.merged).to be >= 2
    expect(@starts.size).to eq(1)

    @gate << :go
    wait_until { @starts.size == 2 }

    job.pause
    job.unschedule

    @gate << :go
    wait_until { @ends.size == 2 }

    sleep 0.5

    expect(@starts.size).to eq(2)
    expect(@max_concurrent).to eq(1)
  end

  it 'starts the pending run off of the current thread stack' do

    job = make_job('0.3s', blocking: true)
      # blocking: the first run happens on the scheduler thread

    wait_until { @starts.size == 1 }

    expect(@run_threads[0]).to eq(@scheduler.thread)

    job.trigger_off_schedule

    expect(job.pending_trigger).not_to eq(nil)

    @gate << :go
    wait_until { @starts.size == 2 }

    expect(@run_threads[1]).not_to eq(@scheduler.thread)
      # the pending run was queued, not recursed into
      # from the scheduler thread
    expect(@starts[1]).to be >= @ends[0]

    @gate << :go
    wait_until { @ends.size == 2 }
  end

  it 'clears the pending slot when unscheduled' do

    job = make_job

    job.trigger_off_schedule
    wait_until { @starts.size == 1 }

    job.trigger_off_schedule

    expect(job.pending_trigger).not_to eq(nil)

    job.unschedule

    expect(job.pending_trigger).to eq(nil)

    @gate << :go
    wait_until { @ends.size == 1 }

    sleep 0.4

    expect(@starts.size).to eq(1)
  end

  it 'does not start the pending run once the scheduler is down' do

    job = make_job

    job.trigger_off_schedule
    wait_until { @starts.size == 1 }

    job.trigger_off_schedule

    expect(job.pending_trigger).not_to eq(nil)

    @scheduler.shutdown

    expect(job.pending_trigger).to eq(nil)

    @gate << :go
    sleep 0.5

    expect(@starts.size).to eq(1)
  end

  it 'pauses claiming of new triggers but runs an already pending one' do

    job = make_job('0.3s')

    job.pause

    sleep 1

    expect(@starts.size).to eq(0)
    expect(job.pending_trigger).to eq(nil)
      # nothing is claimed nor coalesced while paused

    job.resume
    wait_until { @starts.size == 1 }

    job.trigger_off_schedule

    expect(job.pending_trigger).not_to eq(nil)

    job.pause

    @gate << :go
    wait_until { @starts.size == 2 }
      # the pending run starts even though the job is paused,
      # pause only prevents new claims

    job.resume

    @gate << :go
    wait_until { @ends.size == 2 }
  end

  it 'merges manual triggers (trigger_off_schedule) into the pending slot' do

    job = make_job

    job.trigger_off_schedule
    wait_until { @starts.size == 1 }

    50.times { job.trigger_off_schedule }

    expect(job.pending_trigger.merged).to eq(49)
    expect(job.threads.size).to eq(1)

    @gate << :go
    wait_until { @starts.size == 2 }

    @gate << :go
    wait_until { @ends.size == 2 }

    sleep 0.4

    expect(@starts.size).to eq(2)
    expect(@max_concurrent).to eq(1)
  end

  it 'caps the work threads it uses' do

    @scheduler.max_work_threads = 3

    job = make_job

    job.trigger_off_schedule
    wait_until { @starts.size == 1 }

    10.times { job.trigger_off_schedule }

    expect(@scheduler.work_threads.size).to be <= 3

    @gate << :go
    wait_until { @starts.size == 2 }

    expect(@scheduler.work_threads.size).to be <= 3

    @gate << :go
    wait_until { @ends.size == 2 }

    expect(@max_concurrent).to eq(1)
  end

  it 'neither loses nor duplicates runs when triggers and completions race' do

    job = make_job

    job.trigger_off_schedule
    wait_until { @starts.size == 1 }

    30.times do |i|

      trigger_thread = Thread.new { job.trigger_off_schedule }
      @gate << :go
      trigger_thread.join

      wait_until { @starts.size == i + 2 }
        # each trigger yields exactly one follow-up run,
        # whether it lands before or after the completion
    end

    @gate << :go
    wait_until { @ends.size == 31 }

    sleep 0.4

    expect(@starts.size).to eq(31)
    expect(@ends.size).to eq(31)
    expect(job.pending_trigger).to eq(nil)
    expect(@max_concurrent).to eq(1)

    @starts.each_with_index do |s, i|
      expect(s).to be >= @ends[i - 1] if i > 0
    end
  end
end
