# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "thread"
require "timeout"

class TestRakeMultiTask < Rake::TestCase # :nodoc:
  include Rake

  def setup
    super

    Task.clear
    @runs = Array.new
    @mutex = Mutex.new
  end

  def teardown
    Rake.application.thread_pool.join

    super
  end

  def add_run(obj)
    @mutex.synchronize do
      @runs << obj
    end
  end

  def test_running_multitasks
    task :a do 3.times do |i| add_run("A#{i}"); sleep 0.01; end end
    task :b do 3.times do |i| add_run("B#{i}"); sleep 0.01;  end end
    multitask both: [:a, :b]
    Task[:both].invoke
    assert_equal 6, @runs.size
    assert @runs.index("A0") < @runs.index("A1")
    assert @runs.index("A1") < @runs.index("A2")
    assert @runs.index("B0") < @runs.index("B1")
    assert @runs.index("B1") < @runs.index("B2")
  end

  def test_all_multitasks_wait_on_slow_prerequisites
    task :slow do 3.times do |i| add_run("S#{i}"); sleep 0.05 end end
    task a: [:slow] do 3.times do |i| add_run("A#{i}"); sleep 0.01 end end
    task b: [:slow] do 3.times do |i| add_run("B#{i}"); sleep 0.01 end end
    multitask both: [:a, :b]
    Task[:both].invoke
    assert_equal 9, @runs.size
    assert @runs.index("S0") < @runs.index("S1")
    assert @runs.index("S1") < @runs.index("S2")
    assert @runs.index("S2") < @runs.index("A0")
    assert @runs.index("S2") < @runs.index("B0")
    assert @runs.index("A0") < @runs.index("A1")
    assert @runs.index("A1") < @runs.index("A2")
    assert @runs.index("B0") < @runs.index("B1")
    assert @runs.index("B1") < @runs.index("B2")
  end

  def test_multitasks_with_parameters
    task :a, [:arg] do |t, args| add_run(args[:arg]) end
    multitask :b, [:arg] => [:a] do |t, args| add_run(args[:arg] + "mt") end
    Task[:b].invoke "b"
    assert @runs[0] == "b"
    assert @runs[1] == "bmt"
  end

  def test_single_jobserver_slot_allows_nested_multitask_dependencies
    read_io, write_io = IO.pipe
    job_server = Rake::JobServerClient.new(read_io, write_io, 1)
    Rake.application.instance_variable_set(:@job_server, job_server)
    Rake.application.instance_variable_set(:@thread_pool, nil)
    order = []

    task :leaf do
      order << :leaf
    end
    task :child do
      Task[:leaf].invoke
      order << :child
    end
    multitask parent: [:child] do
      order << :parent
    end

    Timeout.timeout(1) do
      Task[:parent].invoke
    end

    assert_equal [:leaf, :child, :parent], order
  ensure
    write_io&.close
    read_io&.close
  end

  def test_tasks_waiting_on_prerequisites_do_not_hold_the_only_slot
    read_io, write_io = IO.pipe
    write_io.write("+")
    job_server = Rake::JobServerClient.new(read_io, write_io, 2)
    Rake.application.instance_variable_set(:@job_server, job_server)
    Rake.application.instance_variable_set(:@thread_pool, nil)
    implicit_token = job_server.acquire
    task :child
    parent = task :parent
    parent.enhance([:child])

    invocation = Thread.new { parent.invoke }
    invocation.join
    job_server.release(implicit_token)
    assert_equal "+", read_io.read_nonblock(1)
  ensure
    write_io&.close
    read_io&.close
  end

  def test_parallel_action_releases_slot_when_subcommand_fails_to_start
    read_io, write_io = IO.pipe
    job_server = Rake::JobServerClient.new(read_io, write_io, 1)
    Rake.application.instance_variable_set(:@job_server, job_server)
    Rake.application.instance_variable_set(:@thread_pool, nil)
    multitask :failing do
      sh("this-command-does-not-exist-#{object_id}")
      raise RuntimeError, "command failed"
    end

    error = assert_raises(RuntimeError) { Task[:failing].invoke }
    assert_match(/Command failed/, error.message)
    assert_equal :implicit, job_server.acquire.kind
  ensure
    write_io&.close
    read_io&.close
  end

  def test_parallel_action_releases_borrowed_slot_on_application_exit
    read_io, write_io = IO.pipe
    write_io.write("Z")
    script_dir = File.join(@orig_pwd, "tmp-jobserver-test")
    FileUtils.mkdir_p(script_dir)
    script = File.join(script_dir, "rake_exit.rb")
    File.write(script, <<~RUBY)
      require "rake"
      include Rake::DSL
      multitask :exiting do
        exit
      end
      Rake.application.job_server.acquire
      Thread.new { Rake::Task[:exiting].invoke }.join
    RUBY
    env = {
      "MAKEFLAGS" => "--jobserver-auth=#{read_io.fileno},#{write_io.fileno} -j2"
    }
    pid = spawn(env, RUBY, "-I#{@rake_lib}", script,
      read_io.fileno => read_io.fileno,
      write_io.fileno => write_io.fileno,
      close_others: false)

    _pid, status = Process.wait2(pid)
    assert status.success?, "rake subprocess failed"
    read_io.wait_readable
    assert_equal "Z", read_io.read_nonblock(1)
  ensure
    FileUtils.rm_rf(script_dir) if defined?(script_dir)
    write_io&.close
    read_io&.close
  end

  def test_cross_thread_prerequisite_failures
    failed = false

    multitask :fail_once do
      fail_now = !failed
      failed = true
      raise "failing once" if fail_now
    end

    task a: :fail_once
    task b: :fail_once

    assert_raises RuntimeError do
      Rake::Task[:a].invoke
    end

    assert_raises RuntimeError do
      Rake::Task[:b].invoke
    end
  end

  def test_task_not_executed_if_dependant_task_failed_concurrently
    multitask default: [:one, :two]

    task :one do
      raise
    end

    task_two_was_executed = false
    task two: :one do
      task_two_was_executed = true
    end

    begin
      Rake::Task[:default].invoke
    rescue RuntimeError
    ensure
      sleep 0.5
      refute task_two_was_executed
    end
  end
end
