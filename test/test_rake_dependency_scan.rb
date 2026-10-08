# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "fileutils"

class TestRakeDependencyScan < Rake::TestCase # :nodoc:
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

  def test_scanner_runs_after_declared_prerequisites_and_before_actions
    task(:declared) { add_run(:declared) }
    task(:discovered) { add_run(:discovered) }
    task(codegen: [:declared]) { add_run(:codegen) }.
      enhance_with_scanner { |t| ["discovered"] }

    Task[:codegen].invoke

    assert_equal [:declared, :discovered, :codegen], @runs
    assert_equal ["declared", "discovered"], Task[:codegen].prerequisites
  end

  def test_task_without_scanner_is_unaffected
    task(codegen: [:declared]) { add_run(:codegen) }
    task(:declared) { add_run(:declared) }

    Task[:codegen].invoke

    assert_equal [:declared, :codegen], @runs
    assert_nil Task[:codegen].scanner
  end

  # A code generation task reads a first level index (produced by a
  # declared prerequisite) to learn it depends on gen_a.  gen_a in turn
  # generates a second level index that reveals gen_b.  The scan phase
  # must keep discovering until the graph is stable, and only then run
  # the main action.
  def test_two_level_generated_index
    task(:index1) do
      add_run(:index1)
      File.write("index1.txt", "gen_a\n")
    end
    task(:gen_a) do
      add_run(:gen_a)
      File.write("index2.txt", "gen_b\n")
    end
    task(:gen_b) { add_run(:gen_b) }

    scan_count = 0
    task(codegen: [:index1]) { add_run(:codegen) }.
      enhance_with_scanner do |t|
        scan_count += 1
        found = []
        ["index1.txt", "index2.txt"].each do |index|
          found.concat(File.readlines(index).map(&:strip)) if File.exist?(index)
        end
        found
      end

    Task[:codegen].invoke

    assert_equal [:index1, :gen_a, :gen_b, :codegen], @runs
    assert_equal 3, scan_count
    assert_equal ["index1", "gen_a", "gen_b"], Task[:codegen].prerequisites
  end

  def test_duplicate_edges_are_merged
    task(:shared) { add_run(:shared) }
    task(:extra) { add_run(:extra) }
    task(codegen: [:shared]) { add_run(:codegen) }.
      enhance_with_scanner { |t| ["shared", "extra", "extra"] }

    Task[:codegen].invoke

    assert_equal ["shared", "extra"], Task[:codegen].prerequisites
    assert_equal [:shared, :extra, :codegen], @runs
  end

  def test_scan_round_limit
    10.times { |i| task("dep_#{i}") }

    n = 0
    gen = task(:codegen)
    gen.max_scan_rounds = 3
    gen.enhance_with_scanner do |t|
      name = "dep_#{n}"
      n += 1
      [name]
    end

    ex = assert_raise(RuntimeError) { Task[:codegen].invoke }
    assert_match(/did not stabilize after 3 rounds/, ex.message)
    assert_equal [], @runs
  end

  def test_new_edge_back_into_call_chain_reports_concrete_cycle
    task(:b) { add_run(:b) }.
      enhance_with_scanner { |t| ["a"] }
    task(a: [:b]) { add_run(:a) }

    ex = assert_raise(RuntimeError) { Task[:a].invoke }
    assert_match(/dependency scan of b/, ex.message)
    assert_match(/TOP => a => b => a/, ex.message)
    assert_equal [], @runs
  end

  def test_self_edge_reports_concrete_cycle
    task(:a) { add_run(:a) }.
      enhance_with_scanner { |t| ["a"] }

    ex = assert_raise(RuntimeError) { Task[:a].invoke }
    assert_match(/TOP => a => a/, ex.message)
    assert_equal [], @runs
  end

  def test_parallel_invocations_share_single_scan_and_execution
    task(:dep) do
      sleep 0.01
      add_run(:dep)
    end

    scan_count = 0
    count_mutex = Mutex.new
    task(:gen) { add_run(:gen) }.
      enhance_with_scanner do |t|
        count_mutex.synchronize { scan_count += 1 }
        ["dep"]
      end

    threads = 8.times.map do
      Thread.new { Task[:gen].invoke }
    end
    threads.each(&:join)

    assert_equal [:dep, :gen], @runs
    assert_equal 2, scan_count
  end
end
