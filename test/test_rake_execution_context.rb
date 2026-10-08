# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)

class TestRakeExecutionContext < Rake::TestCase # :nodoc:
  def setup
    super

    Rake::Task.clear
    RakeFileUtils.verbose_flag = false

    # Two tiny reporter subprocesses: one records the environment it
    # actually received, the other records its working directory.
    @env_reporter = File.join(@rake_root, "test", "support", "report_env.rb")
    @pwd_reporter = File.join(@rake_root, "test", "support", "report_pwd.rb")

    @saved_env = ENV.to_h
  end

  def teardown
    Rake.application.thread_pool.join
    ENV.replace(@saved_env)

    super
  end

  def test_derive_merges_env_and_removes_with_nil
    parent = Rake::ExecutionContext.new(chdir: "build", env: { "A" => "1", "B" => "2" })
    child = parent.derive(env: { "B" => nil, "C" => "3" })

    assert_equal "build", child.chdir
    assert_equal({ "A" => "1", "B" => nil, "C" => "3" }, child.env)
    assert_equal({ "A" => "1", "B" => "2" }, parent.env)
  end

  def test_with_restores_previous_context_on_error
    context = Rake::ExecutionContext.new(chdir: "build")

    assert_raise(RuntimeError) do
      Rake::ExecutionContext.with(context) { raise "boom" }
    end

    assert_same Rake::ExecutionContext::ROOT, Rake::ExecutionContext.current
  end

  def test_task_context_applies_to_ruby_helper
    FileUtils.mkdir_p "sub"
    task(:work) { ruby @pwd_reporter, File.expand_path("out.txt") }.
      set_execution_context(chdir: "sub", env: { "CTX_A" => "one" })

    Rake::Task[:work].invoke

    assert_equal File.expand_path("sub"), File.read("out.txt")
  end

  def test_task_context_env_reaches_subprocess
    task(:work) { ruby @env_reporter, File.expand_path("out.txt"), "CTX_A", "CTX_B" }.
      set_execution_context(env: { "CTX_A" => "one" })

    Rake::Task[:work].invoke

    assert_equal "CTX_A=\"one\"\nCTX_B=nil", File.read("out.txt")
  end

  def test_nil_env_removes_inherited_variable
    ENV["CTX_LEAK"] = "outer"
    task(:work) { ruby @env_reporter, File.expand_path("out.txt"), "CTX_LEAK" }.
      set_execution_context(env: { "CTX_LEAK" => nil })

    Rake::Task[:work].invoke

    assert_equal "CTX_LEAK=nil", File.read("out.txt")
  end

  def test_child_task_derives_context_from_parent
    task(:child) { ruby @env_reporter, File.expand_path("out.txt"), "CTX_A", "CTX_B" }.
      set_execution_context(env: { "CTX_B" => "child" })
    task parent: [:child]
    Rake::Task[:parent].set_execution_context(env: { "CTX_A" => "parent" })

    Rake::Task[:parent].invoke

    assert_equal "CTX_A=\"parent\"\nCTX_B=\"child\"", File.read("out.txt")
  end

  def test_explicit_options_beat_context
    FileUtils.mkdir_p "ctx_dir"
    FileUtils.mkdir_p "explicit_dir"
    task(:work) do
      ruby @pwd_reporter, File.expand_path("pwd.txt"), chdir: "explicit_dir"
      sh({ "CTX_A" => "explicit" }, RbConfig.ruby, @env_reporter,
         File.expand_path("env.txt"), "CTX_A")
    end.set_execution_context(chdir: "ctx_dir", env: { "CTX_A" => "context" })

    Rake::Task[:work].invoke

    assert_equal File.expand_path("explicit_dir"), File.read("pwd.txt")
    assert_equal "CTX_A=\"explicit\"", File.read("env.txt")
  end

  def test_nested_failure_restores_context
    task(:inner) { raise "inner boom" }.
      set_execution_context(chdir: "nowhere")
    task(:outer) do
      assert_raise(RuntimeError) { Rake::Task[:inner].invoke }
      # still inside outer's context after the nested failure
      assert_equal "outer", Rake::ExecutionContext.current.env["CTX_A"]
    end.set_execution_context(env: { "CTX_A" => "outer" })

    Rake::Task[:outer].invoke

    assert_same Rake::ExecutionContext::ROOT, Rake::ExecutionContext.current
  end

  def test_failed_invocation_propagates_and_is_memoized
    task(:bad) { raise "bad boom" }

    ex = assert_raise(RuntimeError) { Rake::Task[:bad].invoke }
    assert_equal "bad boom", ex.message
    assert_same Rake::ExecutionContext::ROOT, Rake::ExecutionContext.current
    assert_raise(RuntimeError) { Rake::Task[:bad].invoke }
  end

  def test_shared_prerequisite_runs_once
    runs = 0
    task(:shared) { runs += 1 }
    task(:left => [:shared]) { }
    task(:right => [:shared]) { }
    Rake::Task[:left].set_execution_context(env: { "CTX_A" => "left" })
    Rake::Task[:right].set_execution_context(env: { "CTX_A" => "right" })
    task all: [:left, :right]

    Rake::Task[:all].invoke

    assert_equal 1, runs
  end

  def test_parallel_tasks_have_isolated_contexts
    %w[one two].each do |name|
      task(name) do
        sleep 0.2
        ruby @env_reporter, File.expand_path("out_#{name}.txt"), "CTX_A"
      end.set_execution_context(env: { "CTX_A" => name })
    end
    multitask all: %w[one two]

    Rake::Task[:all].invoke

    assert_equal "CTX_A=\"one\"", File.read("out_one.txt")
    assert_equal "CTX_A=\"two\"", File.read("out_two.txt")
  end
end
