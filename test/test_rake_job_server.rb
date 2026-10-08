# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "rake/job_server"

class TestRakeJobServer < Rake::TestCase # :nodoc:
  include Rake

  def teardown
    (@pipes || []).flatten.uniq.each do |io|
      io.close unless io.closed?
    end

    super
  end

  def test_open_pipe_authorization
    pipe do |read_parent, _, read_child, write_child, write_parent|
      write_parent.syswrite("Q")
      env = {
        "MAKEFLAGS" => "-j2 --jobserver-auth=#{read_child.fileno},#{write_child.fileno}"
      }

      server = JobServer.open_from_env(env)
      assert_kind_of JobServer, server
      assert_equal 2, server.jobs

      implicit = server.acquire
      borrowed = server.acquire
      assert_equal :implicit, implicit.type
      assert_equal "Q", borrowed.byte

      server.release(borrowed)
      assert_equal "Q", read_parent.sysread(1)
      server.release(implicit)
      server.shutdown
      assert_equal :wait_readable, read_parent.read_nonblock(1, exception: false)
    end
  end

  def test_open_fifo_authorization
    Dir.mktmpdir do |dir|
      path = File.join(dir, "jobserver")
      File.mkfifo(path)
      parent = File.open(path, File::RDWR)
      parent.syswrite("F")
      env = { "MAKEFLAGS" => "--jobserver-auth=fifo:#{path} -j2" }

      server = JobServer.open_from_env(env)
      assert_kind_of JobServer, server
      implicit = server.acquire
      borrowed = server.acquire
      assert_equal :implicit, implicit.type
      assert_equal "F", borrowed.byte
      server.release(borrowed)
      assert_equal "F", parent.sysread(1)
      server.release(implicit)
      server.shutdown
      parent.close
    end
  end

  def test_legacy_fds_authorization
    pipe do |_, _, read_child, write_child, _|
      env = {
        "MAKEFLAGS" => "--jobserver-fds=#{read_child.fileno},#{write_child.fileno} j2"
      }

      server = JobServer.open_from_env(env)
      assert_kind_of JobServer, server
      server.shutdown
    end
  end

  def test_unusable_authorization_falls_back_to_one_job
    env = { "MAKEFLAGS" => "-j2 --jobserver-auth=9999,9998" }
    result = nil
    output = capture_output { result = JobServer.open_from_env(env) }.last

    assert_equal :unavailable, result
    assert_match(/jobserver is unavailable/, output)
  end

  def test_application_uses_one_thread_for_unusable_authorization
    ENV["MAKEFLAGS"] = "-j4 --jobserver-auth=9999,9998"
    app = Application.new
    output = capture_output { app.init("rake", []) }.last

    assert_nil app.job_server
    assert_equal 0, app.options.thread_pool_size
    assert_match(/running with one job/, output)
  end

  def test_action_exception_returns_borrowed_token
    pipe do |read_parent, _, read_child, write_child, write_parent|
      write_parent.syswrite("X")
      server = JobServer.new(read_child, write_child)
      server.acquire

      error = nil
      thread = Thread.new do
        begin
          server.around_action { raise "boom" }
        rescue RuntimeError => thread_error
          error = thread_error
        end
      end
      thread.join
      assert_kind_of RuntimeError, error

      assert_equal "X", read_parent.sysread(1)
      server.shutdown
    end
  end

  def test_command_launch_error_returns_borrowed_token
    pipe do |read_parent, _, read_child, write_child, write_parent|
      write_parent.syswrite("S")
      server = JobServer.new(read_child, write_child)
      server.acquire

      error = nil
      thread = Thread.new do
        begin
          server.around_action do
            raise Errno::ENOENT, "rake jobserver command"
          end
        rescue Errno::ENOENT => thread_error
          error = thread_error
        end
      end
      thread.join
      assert_kind_of Errno::ENOENT, error

      assert_equal "S", read_parent.sysread(1)
      server.shutdown
    end
  end

  def test_single_implicit_slot_nested_dependencies_do_not_deadlock
    with_jobserver("-j1", false) do |app|
      events = []

      MultiTask.define_task(:top => [:parent]) do
        events << :top
      end
      MultiTask.define_task(:parent => [:child]) do
        events << :parent
      end
      MultiTask.define_task(:child) do
        events << :child
      end

      app["top"].invoke

      assert_equal [:child, :parent, :top], events
      assert_equal 0, app.options.thread_pool_size
    end
  end

  def test_implicit_slot_and_borrowed_token_run_together
    with_jobserver("-j2", true) do |app, read_parent, write_parent|
      events = Queue.new
      mutex = Mutex.new
      ready = ConditionVariable.new
      active = 0

      task = Task
      task.define_task(:implicit) do
        mutex.synchronize do
          active += 1
          ready.broadcast
          ready.wait(mutex, 0.1) { active == 2 }
          assert_equal 2, active
        end
        events << :implicit
      end
      task.define_task(:borrowed) do
        mutex.synchronize do
          active += 1
          ready.broadcast
          ready.wait(mutex, 0.1) { active == 2 }
          assert_equal 2, active
        end
        events << :borrowed
      end

      write_parent.syswrite("Z")
      thread = Thread.new { app["borrowed"].invoke }
      mutex.synchronize do
        ready.wait(mutex, 0.1) { active == 1 }
      end
      app["implicit"].invoke
      thread.join

      finished = [events.pop, events.pop].sort
      assert_equal [:borrowed, :implicit], finished
      assert_equal "Z", read_parent.sysread(1)
    end
  end

  def test_shutdown_returns_unreleased_borrowed_token
    pipe do |read_parent, _, read_child, write_child, write_parent|
      read_child.autoclose = false
      write_child.autoclose = false
      read_child.close_on_exec = false
      write_child.close_on_exec = false
      write_parent.syswrite("E")

      server = JobServer.new(read_child, write_child)
      server.acquire
      server.acquire
      server.shutdown

      assert_equal "E", read_parent.sysread(1)
    end
  end

  def test_application_exit_keeps_authorization_descriptor_open
    Dir.mktmpdir(nil, @rake_root) do |workdir|
      pipe do |_, _, read_child, write_child, write_parent|
        read_child.autoclose = false
        write_child.autoclose = false
        read_child.close_on_exec = false
        write_child.close_on_exec = false
        write_parent.syswrite("E")

        File.write(File.join(workdir, "Rakefile"), "task :top do\nend\n")
        env = {
          "MAKEFLAGS" => "-j2 --jobserver-auth=#{read_child.fileno},#{write_child.fileno}"
        }

        system(
          env,
          RUBY, "-I#{@rake_lib}", File.expand_path(@rake_exec),
          "--multitask", "--rakelib=", "-f", "Rakefile", "top",
          chdir: workdir
        )

        assert_predicate $?, :success?
        assert_equal "E", read_child.sysread(1)
      end
    end
  end

  private

  def pipe
    read_parent, write_child = IO.pipe
    read_child, write_parent = IO.pipe
    (@pipes ||= []) << [read_parent, write_child, read_child, write_child, write_parent]
    yield read_parent, write_child, read_child, write_child, write_parent
  ensure
    write_parent.close unless write_parent.closed?
  end

  def with_jobserver(flags, include_pipes=false)
    pipe do |read_parent, _, read_child, write_child, write_parent|
      ENV["MAKEFLAGS"] =
        "#{flags} --jobserver-auth=#{read_child.fileno},#{write_child.fileno}"
      app = Application.new
      app.init("rake", ["--multitask"])
      Rake.application = app
      begin
        if include_pipes
          yield app, read_parent, write_parent
        else
          yield app
        end
      ensure
        app.run_with_threads {}
      end
    end
  ensure
    Rake.application = Rake::Application.new
  end
end
