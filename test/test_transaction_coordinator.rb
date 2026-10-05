# frozen_string_literal: true
require 'test/unit'
require 'pstore'
require 'tmpdir'
require 'fileutils'
require 'timeout'
require 'rbconfig'

class TransactionCoordinatorTest < Test::Unit::TestCase
  CRASH_ENV = "PSTORE_P2PC_CRASH"

  def setup
    @dir = Dir.mktmpdir("pstore-p2pc")
    @path_a = File.join(@dir, "a.store")
    @path_b = File.join(@dir, "b.store")
    seed(@path_a, @path_b, initial: true)
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  def test_commits_all_stores_together
    coordinated_update(@path_a, @path_b, 10, 20)

    assert_equal(10, read(@path_a, :x))
    assert_equal(20, read(@path_b, :y))
    assert_equal([], artifacts)
  end

  def test_block_runs_exactly_once_across_recovery
    run_crashing_child("after_prepare", 10, 20)

    assert_equal(1, File.read(counter_path).length)
    assert_equal(1, read(@path_a, :x))
    assert_equal(2, read(@path_b, :y))
    assert_equal([], artifacts)

    coordinated_update(@path_a, @path_b, 30, 40)
    assert_equal(2, File.read(counter_path).length)
    assert_equal(30, read(@path_a, :x))
    assert_equal(40, read(@path_b, :y))
  end

  def test_abort_leaves_both_files_untouched
    store_a = PStore.new(@path_a)
    store_b = PStore.new(@path_b)
    PStore::TransactionCoordinator.transaction(store_a, store_b) do |a, b|
      a[:x] = 10
      b.abort
    end

    assert_equal(1, read(@path_a, :x))
    assert_equal(2, read(@path_b, :y))
    assert_equal([], artifacts)
  end

  def test_exception_in_block_leaves_both_files_untouched
    store_a = PStore.new(@path_a)
    store_b = PStore.new(@path_b)
    assert_raise(RuntimeError) do
      PStore::TransactionCoordinator.transaction(store_a, store_b) do |a, b|
        a[:x] = 10
        raise "boom"
      end
    end

    assert_equal(1, read(@path_a, :x))
    assert_equal(2, read(@path_b, :y))
    assert_equal([], artifacts)
  end

  {after_journal_prepared: [1, 2, 1, 2],
   after_prepare:          [1, 2, 1, 2]}.each do |hook, (a_before, b_before, a_after, b_after)|
    define_method("test_crash_#{hook}_rolls_back_on_reopen") do
      midpoint = run_crashing_child(hook.to_s, 10, 20)

      assert_equal(a_before, midpoint[:a], "a.store must be unchanged before recovery")
      assert_equal(b_before, midpoint[:b], "b.store must be unchanged before recovery")
      recovered = reopen_values
      assert_equal(a_after, recovered[:a], "a.store must roll back to its old value")
      assert_equal(b_after, recovered[:b], "b.store must roll back to its old value")
      assert_equal([], artifacts)
    end
  end

  def test_crash_after_decision_rolls_forward
    midpoint = run_crashing_child("after_decision", 10, 20)

    assert_equal(1, midpoint[:a])
    assert_equal(2, midpoint[:b])
    recovered = reopen_values
    assert_equal(10, recovered[:a])
    assert_equal(20, recovered[:b])
    assert_equal([], artifacts)
  end

  def test_crash_between_file_publishes_rolls_forward
    midpoint = run_crashing_child("after_publish_0", 10, 20)

    assert_equal(10, midpoint[:a], "first file must already carry the new value")
    assert_equal(2, midpoint[:b], "second file must still carry the old value")
    recovered = reopen_values
    assert_equal(10, recovered[:a])
    assert_equal(20, recovered[:b])
    assert_equal([], artifacts)
  end

  def test_crash_after_last_publish_cleans_up_on_reopen
    midpoint = run_crashing_child("after_publish_1", 10, 20)

    assert_equal(10, midpoint[:a])
    assert_equal(20, midpoint[:b])
    recovered = reopen_values
    assert_equal(10, recovered[:a])
    assert_equal(20, recovered[:b])
    assert_equal([], artifacts)
  end

  def test_missing_coordination_record_is_a_hard_failure
    run_crashing_child("after_prepare", 10, 20)
    journals.each { |path| File.unlink(path) }

    error = assert_raise(PStore::Error) { read(@path_a, :x) }
    assert_match(/transaction journal/, error.message)
  end

  def test_corrupted_coordination_record_is_a_hard_failure
    run_crashing_child("after_decision", 10, 20)
    path = journals.first
    File.binwrite(path, "not a journal")

    error = assert_raise(PStore::Error) { read(@path_b, :y) }
    assert_match(/transaction journal/, error.message)
  end

  def test_corrupted_marker_is_a_hard_failure
    run_crashing_child("after_decision", 10, 20)
    marker = File.join(@dir, Dir.children(@dir).grep(/\.ready\z/).first)
    File.binwrite(marker, "broken")

    error = assert_raise(PStore::Error) { read(@path_a, :x) }
    assert_match(/transaction marker/, error.message)
  end

  def test_recovery_spans_participants_in_different_directories
    dir_one = File.join(@dir, "one")
    dir_two = File.join(@dir, "two")
    FileUtils.mkdir_p(dir_one)
    FileUtils.mkdir_p(dir_two)
    path_one = File.join(dir_one, "a.store")
    path_two = File.join(dir_two, "b.store")

    PStore.new(path_one).transaction { |store| store[:x] = 1 }
    PStore.new(path_two).transaction { |store| store[:y] = 2 }
    run_ruby(child_script(path_one, path_two, "after_publish_0", 10, 20), env: {CRASH_ENV => "after_publish_0"})
    assert_equal(10, raw_value(path_one, :x))
    assert_equal(2, raw_value(path_two, :y))

    assert_equal(10, read(path_one, :x))
    assert_equal(20, read(path_two, :y))
    assert_equal([], Dir.children(dir_one).reject { |name| name == "a.store" })
    assert_equal([], Dir.children(dir_two).reject { |name| name == "b.store" })
  end

  def test_opposite_argument_orders_still_lock_without_deadlock
    threads = 2.times.map do |index|
      Thread.new do
        10.times do |iteration|
          a = PStore.new(@path_a)
          b = PStore.new(@path_b)
          stores = index.zero? ? [a, b] : [b, a]
          PStore::TransactionCoordinator.transaction(*stores) do |first, second|
            first[:x] = iteration
            second[:y] = iteration
          end
        end
      end
    end

    assert_nothing_raised(Timeout::Error) do
      Timeout.timeout(10) { threads.each(&:join) }
    end
    assert_equal(9, read(@path_a, :x))
    assert_equal(9, read(@path_b, :y))
    assert_equal([], artifacts)
  end

  def test_requires_two_distinct_stores
    assert_raise(PStore::Error) do
      PStore::TransactionCoordinator.transaction(PStore.new(@path_a)) { }
    end
    assert_raise(PStore::Error) do
      store = PStore.new(@path_a)
      PStore::TransactionCoordinator.transaction(store, store) { }
    end
  end

  private

  def seed(path_a, path_b, initial:)
    return unless initial
    PStore.new(path_a).transaction { |store| store[:x] = 1 }
    PStore.new(path_b).transaction { |store| store[:y] = 2 }
  end

  def coordinated_update(path_a, path_b, value_a, value_b)
    a = PStore.new(path_a)
    b = PStore.new(path_b)
    PStore::TransactionCoordinator.transaction(a, b) do |store_a, store_b|
      bump_counter
      store_a[:x] = value_a
      store_b[:y] = value_b
    end
  end

  def bump_counter
    File.open(counter_path, "a") { |file| file.write("x") }
  end

  def counter_path
    File.join(@dir, "block-count")
  end

  def run_crashing_child(hook, value_a, value_b)
    run_ruby(child_script(@path_a, @path_b, hook, value_a, value_b),
             env: {CRASH_ENV => hook})
    midpoint_values
  end

  def midpoint_values
    {a: raw_value(@path_a, :x), b: raw_value(@path_b, :y)}
  end

  def reopen_values
    {a: read(@path_a, :x), b: read(@path_b, :y)}
  end

  def read(path, key)
    # Opening any participating file completes the unfinished transaction.
    PStore.new(path).transaction { |store| store[key] }
  end

  # Read the file directly with Marshal; never trigger recovery.
  def raw_value(path, key)
    data = File.binread(path)
    return nil if data.empty?
    Marshal.load(data)[key]
  end

  def artifacts
    names = Dir.children(@dir).reject do |name|
      name == File.basename(@path_a) || name == File.basename(@path_b) ||
        name == "block-count"
    end
    names.reject { |name| name.end_with?(".journal.lock") }
  end

  def journals
    Dir.children(@dir).select { |name| name.start_with?(".pstore-p2pc.") && name.end_with?(".journal") }
       .map { |name| File.join(@dir, name) }
  end

  def run_ruby(script, env:)
    lib_dir = File.expand_path("../lib", __dir__)
    environment = {"RUBYOPT" => nil, "BUNDLE_GEMFILE" => nil,
                   "BUNDLE_APP_CONFIG" => nil,
                   CRASH_ENV => env[CRASH_ENV]}
    io = IO.popen(environment,
                  [RbConfig.ruby, "-I#{lib_dir}", "-rpstore", "-"],
                  "r+b")
    io.write(script)
    io.close_write
    output = io.read
    io.close
    output
  end

  def child_script(path_a, path_b, hook, value_a, value_b)
    <<~RUBY
      a = PStore.new(#{path_a.inspect})
      b = PStore.new(#{path_b.inspect})
      PStore::TransactionCoordinator.transaction(a, b) do |store_a, store_b|
        File.open(#{counter_path.inspect}, "a") { |file| file.write("x") }
        store_a[:x] = #{value_a}
        store_b[:y] = #{value_b}
      end
    RUBY
  end
end
