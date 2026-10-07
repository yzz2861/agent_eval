require 'spec_helper'

describe Rufus::Scheduler do
  before(:each) do
    skip 'Process.fork is not available' unless Process.respond_to?(:fork)
  end

  after(:each) do
    $rufus_fork_spec_child_pid = nil
  end

  it 'rejects an inherited scheduler, then copies a schedule after takeover' do
    status_r, status_w = IO.pipe
    trigger_r, trigger_w = IO.pipe
    sync_r, sync_w = IO.pipe

    scheduler = Rufus::Scheduler.new(:frequency => 0.03)
    old_job =
      scheduler.schedule_every('10s') do |job|
        if $rufus_fork_spec_child_pid == $$
          trigger_w.puts("#{job.id}|#{job.scheduler.pid}|#{job.count}")
          trigger_w.flush
        end
      end
    parent_in_job_id =
      scheduler.in('0.05s') do |job|
        if $rufus_fork_spec_child_pid == $$
          trigger_w.puts("#{job.id}|#{job.scheduler.pid}|#{job.count}")
          trigger_w.flush
        end
      end

    pid = Process.fork do
      begin
        $rufus_fork_spec_child_pid = $$

        status_r.close
        sync_w.close

        begin
          scheduler.in('0s') { }
          status_w.puts('SCHEDULE:ok')
        rescue Rufus::Scheduler::ForkedSchedulerError
          status_w.puts('SCHEDULE:ForkedSchedulerError')
        end

        begin
          old_job.trigger_off_schedule
          status_w.puts('TRIGGER:ok')
        rescue Rufus::Scheduler::ForkedSchedulerError
          status_w.puts('TRIGGER:ForkedSchedulerError')
        end

        status_w.flush
        sync_r.read(1)

        scheduler.after_fork(:copy_jobs => true)

        new_job = scheduler.every_jobs.first

        status_w.puts("PID:#{scheduler.pid}")
        status_w.puts("PARENT_PID:#{scheduler.parent_pid}")
        status_w.puts("JOBS:2")
        status_w.puts("NEW_JOB:#{new_job.id != old_job.id}")
        status_w.puts("PARENT_JOB:#{new_job.forked_from_job_id == old_job.id}")
        status_w.puts("JOB_PID:#{new_job.scheduler.pid == $$}")
        status_w.flush

        sleep(0.5)

        scheduler.shutdown(:wait => 2)

        status_w.puts("THREADS:#{scheduler.threads.size}")
        status_w.puts("WORK_THREADS:#{scheduler.work_threads.size}")
        status_w.flush

        exit!(0)
      rescue => e
        status_w.puts("CHILD_ERROR:#{e.class}:#{e.message}")
        status_w.flush
        exit!(1)
      end
    end

    status_w.close
    trigger_w.close
    sync_r.close

    expect(status_r.gets.chomp).to eq('SCHEDULE:ForkedSchedulerError')
    expect(status_r.gets.chomp).to eq('TRIGGER:ForkedSchedulerError')

    sync_w.puts('go')
    sync_w.close

    Process.wait(pid)

    expect($?).to be_success

    status = status_r.read
    trigger = trigger_r.read.chomp

    expect(status).not_to include('CHILD_ERROR')

    expect(status).to include("PID:#{pid}")
    expect(status).to include("PARENT_PID:#{$$}")
    expect(status).to include('JOBS:2')
    expect(status).to include('NEW_JOB:true')
    expect(status).to include('PARENT_JOB:true')
    expect(status).to include('JOB_PID:true')
    expect(status).to include('THREADS:0')
    expect(status).to include('WORK_THREADS:0')

    trigger_id, trigger_pid, trigger_count = trigger.split('|')

    expect(trigger_id).not_to eq(old_job.id)
    expect(trigger_id).not_to eq(parent_in_job_id)
    expect(trigger_pid).to eq(pid.to_s)
    expect(trigger_count).to eq('1')

    expect(scheduler.pid).to eq($$)
    expect(scheduler).to be_up

    ran_in_parent = Queue.new
    scheduler.in('0.1s') { ran_in_parent << true }

    expect(ran_in_parent.pop).to be(true)

    scheduler.shutdown(:kill)
  end

  it 'can take over a forked scheduler with an empty schedule' do
    r, w = IO.pipe

    scheduler = Rufus::Scheduler.new
    scheduler.every('1s') { }

    pid = Process.fork do
      begin
        r.close

        scheduler.after_fork(false)

        w.puts("UP:#{scheduler.up?}")
        w.puts("FORKED:#{scheduler.forked?}")
        w.puts("JOBS:#{scheduler.jobs.size}")
        w.puts("PID:#{scheduler.pid}")
        w.flush

        scheduler.shutdown(:wait => 1)

        w.puts("THREADS:#{scheduler.threads.size}")
        w.flush

        exit!(0)
      rescue => e
        w.puts("CHILD_ERROR:#{e.class}:#{e.message}")
        w.flush
        exit!(1)
      end
    end

    w.close
    Process.wait(pid)

    expect($?).to be_success

    status = r.read

    expect(status).to include('UP:true')
    expect(status).to include('FORKED:false')
    expect(status).to include('JOBS:0')
    expect(status).to include("PID:#{pid}")
    expect(status).to include('THREADS:0')

    expect(scheduler).to be_up

    scheduler.shutdown(:kill)
  end

  it 'copies repeatable definitions without reviving expired one-time jobs' do

    r, w = IO.pipe

    scheduler = Rufus::Scheduler.new(:frequency => 0.03)
    expired_job = scheduler.schedule_in('0.01s') { }
    repeat_job = scheduler.schedule_every('10s') { }

    sleep(0.1)

    pid = Process.fork do
      begin
        r.close

        scheduler.after_fork(:copy_schedule => true)

        w.puts("JOBS:#{scheduler.jobs.size}")
        w.puts("COPIED_REPEAT:#{scheduler.every_jobs.size}")
        copied_job = scheduler.every_jobs.first
        w.puts("PARENT_JOB:#{copied_job.forked_from_job_id == repeat_job.id}")
        w.puts("HAS_EXPIRED:#{scheduler.jobs.any? { |j| j.id == expired_job.id }}")
        w.puts("HAS_REPEAT:#{scheduler.jobs.any? { |j| j.id == repeat_job.id }}")
        w.puts("FORKED:#{scheduler.forked?}")
        w.flush

        scheduler.shutdown(:wait => 1)

        exit!(0)
      rescue => e
        w.puts("CHILD_ERROR:#{e.class}:#{e.message}")
        w.flush
        exit!(1)
      end
    end

    w.close
    Process.wait(pid)

    expect($?).to be_success

    status = r.read

    expect(status).not_to include('CHILD_ERROR')
    expect(status).to include('JOBS:1')
    expect(status).to include('COPIED_REPEAT:1')
    expect(status).to include('PARENT_JOB:true')
    expect(status).to include('HAS_EXPIRED:false')
    expect(status).to include('HAS_REPEAT:false')
    expect(status).to include('FORKED:false')

    scheduler.shutdown(:kill)
  end

  it 'does not let a child shutdown release the parent file lock' do
    r, w = IO.pipe
    lockfile = File.expand_path('rufus-fork-spec.lock', Dir.pwd)

    scheduler = Rufus::Scheduler.new(:lockfile => lockfile)

    pid = Process.fork do
      begin
        r.close

        begin
          scheduler.shutdown
          w.puts('SHUTDOWN:ok')
        rescue Rufus::Scheduler::ForkedSchedulerError
          w.puts('SHUTDOWN:ForkedSchedulerError')
        end

        scheduler.after_fork

        w.puts("CHILD_UP:#{scheduler.up?}")

        file = File.new(lockfile, File::RDWR | File::CREAT)
        locked = file.flock(File::LOCK_NB | File::LOCK_EX)

        w.puts("CHILD_LOCK:#{locked.inspect}")
        w.flush

        exit!(0)
      rescue => e
        w.puts("CHILD_ERROR:#{e.class}:#{e.message}")
        w.flush
        exit!(1)
      end
    end

    w.close
    Process.wait(pid)

    expect($?).to be_success

    status = r.read

    expect(status).to include('SHUTDOWN:ForkedSchedulerError')
    expect(status).to include('CHILD_UP:false')
    expect(status).to include('CHILD_LOCK:false')

    expect(scheduler).to be_up

    file = File.new(lockfile, File::RDWR | File::CREAT)
    expect(file.flock(File::LOCK_NB | File::LOCK_EX)).to eq(false)
    file.close

    scheduler.shutdown(:kill)

    file = File.new(lockfile, File::RDWR | File::CREAT)
    expect(file.flock(File::LOCK_NB | File::LOCK_EX)).to eq(0)
    file.close
  ensure
    FileUtils.rm_f(lockfile)
  end
end
