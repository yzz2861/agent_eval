# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "fileutils"
require "thread"

class TestRakeMultiFileTask < Rake::TestCase # :nodoc:
  include Rake

  def setup
    super

    Task.clear
    @runs = []
    @mutex = Mutex.new
  end

  def teardown
    Rake.application.thread_pool.join

    super
  end

  def test_creates_all_declared_outputs_from_one_action
    group = multifile ["a.rb", "a_interface.rb"] do |task|
      record(task.name)
      task.outputs.each { |name| File.write(name, name) }
    end

    assert_equal ["a.rb", "a_interface.rb"], group.outputs

    Task["a_interface.rb"].invoke

    assert_equal ["a.rb, a_interface.rb"], @runs
    assert File.exist?("a.rb")
    assert File.exist?("a_interface.rb")
  end

  def test_any_output_can_be_a_prerequisite
    multifile ["a.rb", "a_interface.rb"] => :generator do |task|
      record(task.name)
      task.outputs.each { |name| File.write(name, name) }
    end

    task :generator do
      record("generator")
    end

    task consumer: "a.rb" do
      record("consumer")
    end

    Task[:consumer].invoke

    assert_equal ["generator", "a.rb, a_interface.rb", "consumer"], @runs
  end

  def test_group_is_rebuilt_when_an_output_is_missing
    multifile [OLDFILE, NEWFILE] do |task|
      record(task.name)
      task.outputs.each { |name| FileUtils.touch(name) }
    end

    Task[NEWFILE].invoke
    File.delete(NEWFILE)
    Task[NEWFILE].multi_file_task.reenable
    Task[NEWFILE].invoke

    assert_equal ["#{OLDFILE}, #{NEWFILE}"] * 2, @runs
  end

  def test_group_is_rebuilt_when_common_input_is_newer
    create_timed_files(OLDFILE, NEWFILE)
    FileUtils.touch ["a.rb", "a_interface.rb"], mtime: Time.now - 120

    multifile ["a.rb", "a_interface.rb"] => OLDFILE do |task|
      record(task.name)
      task.outputs.each do |name|
        FileUtils.touch name, mtime: File.mtime(NEWFILE)
      end
    end

    Task["a.rb"].invoke

    assert_equal ["a.rb, a_interface.rb"], @runs
  end

  def test_group_is_not_rebuilt_when_common_input_is_older_than_every_output
    create_file("input.rb", Time.now - 60)
    FileUtils.touch ["a.rb", "a_interface.rb"], mtime: Time.now

    multifile ["a.rb", "a_interface.rb"] => "input.rb" do |task|
      record(task.name)
    end

    Task["a_interface.rb"].invoke

    assert_empty @runs
  end

  def test_each_output_has_its_own_timestamp_for_downstream_tasks
    multifile ["a.rb", "a_interface.rb"] do |task|
      now = Time.now
      FileUtils.touch "a.rb", mtime: now - 30
      FileUtils.touch "a_interface.rb", mtime: now - 15
    end

    Task["a.rb"].invoke
    create_file("consumer.rb", Time.now)

    file "consumer.rb" => "a_interface.rb"

    refute Task["consumer.rb"].needed?
  end

  def test_arguments_are_available_to_the_shared_action
    observed = nil
    multifile ["a.rb", "a_interface.rb"], [:mode] do |task, args|
      observed = args[:mode]
      task.outputs.each { |name| File.write(name, name) }
    end

    Task["a.rb"].invoke("docs")

    assert_equal "docs", observed
  end

  def test_group_accepts_another_multi_file_output_as_a_common_input
    input_runs = 0
    output_runs = 0

    multifile ["input.rb", "input_interface.rb"] do |task|
      input_runs += 1
      now = Time.now
      task.outputs.each { |name| FileUtils.touch(name, mtime: now) }
    end

    multifile ["output.rb", "output_interface.rb"] => "input_interface.rb" do |task|
      output_runs += 1
      now = Time.now - 60
      task.outputs.each { |name| FileUtils.touch(name, mtime: now) }
    end

    Task["output.rb"].invoke
    Task["input_interface.rb"].multi_file_task.reenable
    FileUtils.touch ["input.rb", "input_interface.rb"], mtime: Time.now
    Task["output_interface.rb"].multi_file_task.reenable
    Task["output_interface.rb"].invoke

    assert_equal 1, input_runs
    assert_equal 2, output_runs
  end

  def test_concurrent_requests_for_different_outputs_run_action_once
    inside_action = Queue.new
    release_action = Queue.new

    multifile ["a.rb", "a_interface.rb"] do |task|
      record(task.name)
      inside_action << true
      release_action.pop
      task.outputs.each { |name| File.write(name, name) }
    end

    threads = [
      Thread.new { Task["a.rb"].invoke },
      Thread.new { Task["a_interface.rb"].invoke }
    ]

    assert inside_action.pop
    sleep 0.01
    release_action << true
    threads.each(&:join)

    assert_equal ["a.rb, a_interface.rb"], @runs
  end

  def test_concurrent_requests_share_one_failed_action_and_can_retry
    attempts = 0
    inside_action = Queue.new
    release_action = Queue.new

    multifile ["a.rb", "a_interface.rb"] do |task|
      attempts += 1
      inside_action << true
      release_action.pop
      File.write("a.rb", "a") if attempts > 1
      File.write("a_interface.rb", "interface") if attempts > 1
      fail "first attempt failed" if attempts == 1
    end

    errors = []
    threads = [
      Thread.new { Task["a.rb"].invoke rescue errors << $! },
      Thread.new { Task["a_interface.rb"].invoke rescue errors << $! }
    ]

    assert inside_action.pop
    sleep 0.01
    release_action << true
    threads.each(&:join)

    assert_equal 1, attempts
    assert_equal 2, errors.size

    release_action << true
    Task["a.rb"].invoke

    assert_equal 2, attempts
  end

  def test_failed_action_does_not_leave_completed_group_state
    attempts = 0

    multifile ["a.rb", "a_interface.rb"] do |task|
      attempts += 1
      File.write("a.rb", "a") if attempts > 1
      File.write("a_interface.rb", "interface") if attempts > 1
      fail "first attempt failed" if attempts == 1
    end

    assert_raises(RuntimeError) { Task["a.rb"].invoke }
    refute Task["a.rb"].multi_file_task.already_invoked

    Task["a_interface.rb"].invoke

    assert_equal 2, attempts
  end

  def test_missing_output_after_action_is_a_failure_and_group_can_rebuild
    attempts = 0

    multifile ["a.rb", "a_interface.rb"] do |task|
      attempts += 1
      File.write("a.rb", "a")
      File.write("a_interface.rb", "interface") if attempts > 1
    end

    error = assert_raises(RuntimeError) { Task["a.rb"].invoke }
    assert_match(/did not create a_interface\.rb/, error.message)
    refute Task["a.rb"].multi_file_task.already_invoked

    Task["a_interface.rb"].invoke
    assert_equal 2, attempts
  end

  def test_regular_file_task_cannot_claim_multi_file_output
    file "a.rb"

    error = assert_raises(RuntimeError) do
      multifile ["a.rb", "a_interface.rb"] do
      end
    end

    assert_match(/already declared as a FileTask/, error.message)
  end

  def test_multi_file_output_cannot_be_claimed_by_regular_file_task
    multifile ["a.rb", "a_interface.rb"] do |task|
      task.outputs.each { |name| File.write(name, name) }
    end

    error = assert_raises(RuntimeError) do
      file "a.rb"
    end

    assert_match(/already declared as an output of multi-file task/, error.message)
  end

  def test_outputs_must_be_unique
    error = assert_raises(ArgumentError) do
      multifile ["a.rb", "a.rb"]
    end

    assert_match(/outputs must be unique/, error.message)
  end

  def test_redeclaring_the_same_group_merges_dependencies_and_actions
    first = multifile ["a.rb", "a_interface.rb"] => :input do
      record("first")
      File.write("a.rb", "a")
      File.write("a_interface.rb", "interface")
    end

    second = multifile ["a.rb", "a_interface.rb"] => :other_input do
      record("second")
      File.write("a.rb", "a")
      File.write("a_interface.rb", "interface")
    end

    task :input do
      record("input")
    end

    task :other_input do
      record("other input")
    end

    assert_same first, second
    assert_equal ["input", "other_input"], second.prerequisites

    Task["a.rb"].needed?
    second.execute

    assert_equal ["first", "second"], @runs
  end

  def test_outputs_cannot_belong_to_different_groups
    multifile ["a.rb", "a_interface.rb"]

    error = assert_raises(RuntimeError) do
      multifile ["a.rb", "other_interface.rb"]
    end

    assert_match(/already declared with outputs/, error.message)
  end

  private

  def record(name)
    @mutex.synchronize { @runs << name }
  end
end
