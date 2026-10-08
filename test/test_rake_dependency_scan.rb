# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)

class TestRakeDependencyScan < Rake::TestCase # :nodoc:
  include Rake

  def setup
    super
    Task.clear
  end

  def teardown
    Rake.application.thread_pool.join
    super
  end

  def test_scanner_discovers_dependencies_before_action
    runlist = []
    task(:declared) { |t| runlist << t.name }
    task(:found) { |t| runlist << t.name }
    t = task(main: [:declared]) { |t| runlist << t.name }
    t.scan_with { ["found"] }

    t.invoke

    assert_equal ["declared", "found", "main"], runlist
    assert_equal ["declared", "found"], t.prerequisites
  end

  def test_scanner_is_independent_of_actions
    t = task(:main) { }
    t.scan_with { [] }

    assert_equal 1, t.dependency_scanners.size
    assert_equal 1, t.actions.size
  end

  def test_two_level_generated_index
    runlist = []

    # level 1: "index1" generates an index read by the scanner of "build"
    task(:index1) { |t|
      runlist << t.name
      File.write("index1.txt", "gen1\ngen2\n")
    }

    # level 2: "gen1" has its own generated index naming its sources
    task(:index2) { |t|
      runlist << t.name
      File.write("index2.txt", "src1\nsrc2\n")
    }
    task(:src1) { |t| runlist << t.name }
    task(:src2) { |t| runlist << t.name }
    gen1 = task(gen1: [:index2]) { |t| runlist << t.name }
    gen1.scan_with { File.read("index2.txt").split }

    task(:gen2) { |t| runlist << t.name }

    build = task(build: [:index1]) { |t| runlist << t.name }
    build.scan_with { File.read("index1.txt").split }

    build.invoke

    assert_equal %w[index1 index2 src1 src2 gen1 gen2 build], runlist
    assert_equal ["index1", "gen1", "gen2"], build.prerequisites
    assert_equal ["index2", "src1", "src2"], gen1.prerequisites
  end

  def test_discovery_expands_after_new_dependencies_complete
    runlist = []
    scans = 0

    task(:index) { |t|
      runlist << t.name
      File.write("index.txt", "gen1\n")
    }
    # completing gen1 extends the index, so a later round finds gen2
    task(:gen1) { |t|
      runlist << t.name
      File.open("index.txt", "a") { |f| f.puts "gen2" }
    }
    task(:gen2) { |t| runlist << t.name }

    build = task(build: [:index]) { |t| runlist << t.name }
    build.scan_with do
      scans += 1
      File.read("index.txt").split
    end

    build.invoke

    assert_equal %w[index gen1 gen2 build], runlist
    assert_equal ["index", "gen1", "gen2"], build.prerequisites
    assert_equal 3, scans # gen1, then gen2, then a stable round
  end

  def test_duplicate_edges_are_merged
    runs = 0
    task(:dep) { runs += 1 }
    t = task(main: [:dep]) { }
    t.scan_with { [:dep, "dep", :dep] }

    t.invoke

    assert_equal 1, runs
    assert_equal ["dep"], t.prerequisites
  end

  def test_discovery_round_limit
    n = 0
    5.times { |i| task("dep#{i + 1}") { } }
    t = task(:main) { }
    t.discovery_round_limit = 3
    t.scan_with { n += 1; ["dep#{n}"] }

    ex = assert_raises(RuntimeError) { t.invoke }
    assert_match(/did not settle within 3 rounds/, ex.message)
  end

  def test_new_edge_back_into_call_chain_reports_cycle
    a = task(:a) { }
    b = task(:b) { }
    a.enhance(["b"])
    b.scan_with { ["a"] }

    ex = assert_raises(RuntimeError) { a.invoke }
    assert_equal "Circular dependency detected: TOP => a => b => a",
      ex.message
  end

  def test_new_edge_to_self_reports_cycle
    t = task(:selfish) { }
    t.scan_with { ["selfish"] }

    ex = assert_raises(RuntimeError) { t.invoke }
    assert_equal "Circular dependency detected: TOP => selfish => selfish",
      ex.message
  end

  def test_parallel_invocation_shares_single_discovery
    scans = 0
    runs = 0
    dep_runs = 0
    task(:dep) { dep_runs += 1 }
    t = task(:main) { runs += 1 }
    t.scan_with do
      scans += 1
      sleep 0.05 # widen the race window
      ["dep"]
    end

    threads = 2.times.map { Thread.new { t.invoke } }
    threads.each(&:join)

    # one discovery round plus one stability-check round, shared by both
    # callers rather than run once per caller
    assert_equal 2, scans
    assert_equal 1, runs
    assert_equal 1, dep_runs
  end

  def test_clear_removes_dependency_scanners
    t = task(:main) { }
    t.scan_with { ["dep"] }

    t.clear

    assert_equal [], t.dependency_scanners
  end
end
