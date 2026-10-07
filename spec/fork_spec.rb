
#
# Specifying rufus-scheduler
#

require 'spec_helper'


describe Rufus::Scheduler do

  describe '#pid' do

    it 'returns the pid of the process that started the scheduler' do

      scheduler = Rufus::Scheduler.new

      expect(scheduler.pid).to eq(Process.pid)

      scheduler.shutdown
    end
  end

  describe '#forked?' do

    it 'returns false in the process that started the scheduler' do

      scheduler = Rufus::Scheduler.new

      expect(scheduler.forked?).to eq(false)

      scheduler.shutdown
    end
  end

  describe '#fork_child' do

    it 'fails when not called from a forked child process' do

      scheduler = Rufus::Scheduler.new

      expect {
        scheduler.fork_child
      }.to raise_error(ArgumentError, /not in a forked child process/)

      scheduler.shutdown
    end
  end

  if Process.respond_to?(:fork)
  context 'in a forked child process' do

    # forks a short-lived child process, the child block gets the write
    # end of a pipe, returns [ child_pid, lines_written_by_the_child ]
    #
    def in_child(scheduler)

      rd, wr = IO.pipe

      pid =
        fork do
          rd.close
          yield(wr)
          wr.close
          exit!(0)
        end

      wr.close
      lines = rd.read.split("\n")
      rd.close
      Process.wait(pid)

      [ pid, lines ]
    end

    it 'refuses to schedule and to shutdown without a takeover' do

      scheduler = Rufus::Scheduler.new

      _, lines =
        in_child(scheduler) do |wr|

          r0 =
            begin
              scheduler.in('1h') {}
              :scheduled
            rescue Rufus::Scheduler::ForkedError
              :refused
            end

          r1 =
            begin
              scheduler.shutdown
              :shutdown
            rescue Rufus::Scheduler::ForkedError
              :refused
            end

          wr.puts([ r0, r1, scheduler.forked? ].inspect)
        end

      expect(lines).to eq([ [ :refused, :refused, true ].inspect ])

      # the parent scheduler is not affected

      expect(scheduler.up?).to eq(true)

      counter = 0
      scheduler.schedule_in('0.1s') { counter += 1 }
      wait_until { counter > 0 }

      scheduler.shutdown
    end

    it 'triggers a copied job once after takeover and leaves no threads' do

      scheduler = Rufus::Scheduler.new

      parent_pid = Process.pid
      fired = []

      rd, wr = IO.pipe

      scheduler.every('0.3s', :times => 1) do
        fired << Process.pid
        wr.puts("triggered:#{Process.pid}") if Process.pid != parent_pid
      end

      child_pid =
        fork do

          rd.close

          scheduler.fork_child(:copy => true)

          t0 = monow
          sleep 0.1 while fired.empty? && monow - t0 < 10

          sleep 1.0
            # give a potential second trigger an opportunity to happen

          scheduler.shutdown(:wait)

          wr.puts([
            fired.size,
            scheduler.threads.size,
            Thread.list.count { |t| t[:rufus_scheduler_work_thread] },
            scheduler.jobs.size
          ].inspect)
          wr.close

          exit!(0)
        end

      wr.close
      lines = rd.read.split("\n")
      rd.close
      Process.wait(child_pid)

      # the copied job triggered exactly once, in the child

      expect(lines.grep(/\Atriggered:/)).to eq([ "triggered:#{child_pid}" ])

      # one trigger, no leftover scheduler/work threads, no jobs left

      status = lines.find { |l| l =~ /\A\[/ }
      expect(status).to eq([ 1, 0, 0, 0 ].inspect)

      # the parent scheduler kept running its own copy of the job

      wait_until { fired.include?(parent_pid) }
      expect(scheduler.up?).to eq(true)

      scheduler.shutdown
    end

    it 'starts with an empty schedule after takeover without :copy' do

      scheduler = Rufus::Scheduler.new
      scheduler.every('1h') {}

      _, lines =
        in_child(scheduler) do |wr|

          scheduler.fork_child

          wr.puts([ scheduler.up?, scheduler.jobs.size ].inspect)

          scheduler.shutdown
        end

      expect(lines).to eq([ [ true, 0 ].inspect ])

      expect(scheduler.jobs.size).to eq(1)

      scheduler.shutdown
    end

    it 'does not release the parent file lock when the child shuts down' do

      path = '.fork_spec.lock'

      scheduler = Rufus::Scheduler.new(:lockfile => path)

      _, lines =
        in_child(scheduler) do |wr|

          r0 =
            begin
              scheduler.shutdown
              :shutdown
            rescue Rufus::Scheduler::ForkedError
              :refused
            end

          # the takeover cannot grab the lock while the parent holds it

          scheduler.fork_child
          r1 = scheduler.up?

          scheduler.shutdown
            # must not unlock the lockfile of the parent

          wr.puts([ r0, r1 ].inspect)
        end

      expect(lines).to eq([ [ :refused, false ].inspect ])

      # the parent still holds the lock

      f = File.new(path, File::RDWR)
      expect(f.flock(File::LOCK_NB | File::LOCK_EX)).to eq(false)
      f.close

      expect(scheduler.up?).to eq(true)

      scheduler.shutdown

      # once the parent scheduler is down, the lock is free

      f = File.new(path, File::RDWR)
      expect(f.flock(File::LOCK_NB | File::LOCK_EX)).not_to eq(false)
      f.close

      FileUtils.rm_f(path)
    end
  end
  end
end
