# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)

class TestRakeExecutionContext < Rake::TestCase # :nodoc:
  include Rake

  # A tiny Ruby subprocess that reports the directory and environment it
  # was actually spawned with.
  REPORTER = <<~'RUBY'
    puts Dir.pwd
    %w[CTX_A CTX_B CTX_KILL].each { |k| puts "#{k}=#{ENV[k] || "<unset>"}" }
  RUBY

  def setup
    super

    Task.clear
    Thread.current[:rake_execution_context] = nil
    ENV.delete("CTX_A")
    ENV.delete("CTX_B")
    ENV["CTX_KILL"] = "alive"
    @report_count = 0
  end

  def teardown
    Rake.application.thread_pool.join
    ENV.delete("CTX_KILL")
    Thread.current[:rake_execution_context] = nil

    super
  end

  def mkdir(name)
    File.join(@tempdir, name).tap { |d| FileUtils.mkdir_p d }
  end

  def report_file
    @report_count += 1
    File.join(@tempdir, "report#{@report_count}.txt")
  end

  def read_report(file)
    lines = File.read(file).split("\n")
    env = lines[1..].map { |line| line.split("=", 2) }.to_h
    { pwd: lines[0], env: env }
  end

  def test_derive_merges_and_removes
    base = Rake::ExecutionContext.new(dir: "a", env: { "X" => "1", "Y" => "2" })
    derived = base.derive(env: { "Y" => nil, "Z" => "3" })

    assert_equal "a", derived.dir
    assert_equal({ "X" => "1", "Y" => nil, "Z" => "3" }, derived.env)
    assert_equal "b", base.derive(dir: "b").dir
    assert_equal "a", base.dir
    assert Rake::ExecutionContext::EMPTY.empty?
    refute base.empty?
  end

  def test_task_context_applies_to_ruby_helper
    dir = mkdir "ctx_a"
    file = report_file

    task(:build) { ruby "-e", REPORTER, out: file }.derive_execution_context(
      dir: dir, env: { "CTX_A" => "from_context" })
    Task[:build].invoke

    report = read_report(file)
    assert_equal dir, report[:pwd]
    assert_equal "from_context", report[:env]["CTX_A"]
  end

  def test_explicit_options_take_precedence_over_context
    ctx_dir = mkdir "ctx_dir"
    opt_dir = mkdir "opt_dir"
    file = report_file

    task(:build) do
      sh({ "CTX_A" => "explicit" }, RUBY, "-e", REPORTER,
         chdir: opt_dir, out: file)
    end.derive_execution_context(
      dir: ctx_dir, env: { "CTX_A" => "context", "CTX_B" => "kept" })
    Task[:build].invoke

    report = read_report(file)
    assert_equal opt_dir, report[:pwd]
    assert_equal "explicit", report[:env]["CTX_A"]
    assert_equal "kept", report[:env]["CTX_B"]
  end

  def test_context_removes_inherited_environment_variable
    file = report_file

    task(:scrub) { ruby "-e", REPORTER, out: file }.derive_execution_context(
      env: { "CTX_KILL" => nil })
    Task[:scrub].invoke

    assert_equal "<unset>", read_report(file)[:env]["CTX_KILL"]
  end

  def test_nested_tasks_derive_context_from_parent
    dir = mkdir "parent_dir"
    child_report = report_file
    grandchild_report = report_file

    task(:grandchild) {
      ruby "-e", REPORTER, out: grandchild_report
    }.derive_execution_context(env: { "CTX_B" => "grandchild" })
    task(:child) do
      ruby "-e", REPORTER, out: child_report
      Task[:grandchild].invoke
    end
    task(:parent) {
      Task[:child].invoke
    }.derive_execution_context(dir: dir, env: { "CTX_A" => "parent" })
    Task[:parent].invoke

    child = read_report(child_report)
    assert_equal dir, child[:pwd]
    assert_equal "parent", child[:env]["CTX_A"]

    grandchild = read_report(grandchild_report)
    assert_equal dir, grandchild[:pwd]
    assert_equal "parent", grandchild[:env]["CTX_A"]
    assert_equal "grandchild", grandchild[:env]["CTX_B"]
  end

  def test_context_does_not_change_process_dir_or_env
    dir = mkdir "no_leak"
    observed = nil

    task(:observe) {
      observed = [Dir.pwd, ENV["CTX_A"]]
    }.derive_execution_context(dir: dir, env: { "CTX_A" => "x" })
    Task[:observe].invoke

    assert_equal [Dir.pwd, nil], observed
  end

  def test_nested_failure_is_recorded_and_sibling_keeps_parent_context
    dir = mkdir "fail_dir"
    after_report = report_file

    task(:failing) { ruby "-e", "exit 3" }
    task(:after) { ruby "-e", REPORTER, out: after_report }
    task(:parent) do
      begin
        Task[:failing].invoke
      rescue RuntimeError
        # keep going to invoke the sibling
      end
      Task[:after].invoke
    end.derive_execution_context(dir: dir, env: { "CTX_A" => "parent" })
    Task[:parent].invoke

    assert_raises(RuntimeError) { Task[:failing].invoke }

    report = read_report(after_report)
    assert_equal dir, report[:pwd]
    assert_equal "parent", report[:env]["CTX_A"]
    assert_same Rake::ExecutionContext::EMPTY, Rake::ExecutionContext.current
  end

  def test_unrescued_nested_failure_propagates_without_leaking_context
    task(:failing) { ruby "-e", "exit 3" }
    task(:parent) {
      Task[:failing].invoke
    }.derive_execution_context(dir: @tempdir, env: { "CTX_A" => "parent" })

    assert_raises(RuntimeError) { Task[:parent].invoke }
    assert_same Rake::ExecutionContext::EMPTY, Rake::ExecutionContext.current
  end

  def test_parallel_tasks_keep_separate_contexts
    dir_a = mkdir "par_a"
    dir_b = mkdir "par_b"
    report_a = report_file
    report_b = report_file

    task(:pa) do
      sleep 0.05
      ruby "-e", REPORTER, out: report_a
    end.derive_execution_context(dir: dir_a, env: { "CTX_A" => "a" })
    task(:pb) do
      sleep 0.05
      ruby "-e", REPORTER, out: report_b
    end.derive_execution_context(dir: dir_b, env: { "CTX_A" => "b" })
    multitask all: [:pa, :pb]
    Task[:all].invoke

    a = read_report(report_a)
    assert_equal dir_a, a[:pwd]
    assert_equal "a", a[:env]["CTX_A"]

    b = read_report(report_b)
    assert_equal dir_b, b[:pwd]
    assert_equal "b", b[:env]["CTX_A"]
  end

  def test_shared_prerequisite_runs_once_under_parallel_parents
    shared_report = report_file
    count_file = File.join(@tempdir, "count")

    task(:shared) do
      ruby "-e", REPORTER, out: shared_report
      File.open(count_file, "a") { |f| f.puts "ran" }
    end
    task pa: [:shared]
    task pb: [:shared]
    multitask all: [:pa, :pb]
    Task[:all].invoke

    assert_equal 1, File.read(count_file).scan(/^ran$/).size
    assert_equal Dir.pwd, read_report(shared_report)[:pwd]
  end
end
