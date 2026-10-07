# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "fileutils"

class TestRakeMultiFileTask < Rake::TestCase # :nodoc:
  include Rake

  PRODUCT_A = "gen_a.rb"
  PRODUCT_B = "gen_b.rb"
  PRODUCTS  = [PRODUCT_A, PRODUCT_B].freeze
  SOURCE    = "gen.src"

  def setup
    super

    Task.clear
    @runs = Array.new
    (PRODUCTS + [SOURCE]).each { |f| FileUtils.rm_f f }
  end

  def teardown
    (PRODUCTS + [SOURCE]).each { |f| FileUtils.rm_f f }
    super
  end

  def multifile_task(deps=[SOURCE], &block)
    FileUtils.touch(SOURCE) unless File.exist?(SOURCE)
    block ||= proc { |t|
      @runs << t.name
      PRODUCTS.each { |p| FileUtils.touch p }
    }
    multifile PRODUCTS => deps, &block
  end

  def test_defines_one_task_per_product
    tasks = multifile_task

    assert_equal PRODUCTS, tasks.map(&:name)
    PRODUCTS.each do |product|
      assert_instance_of Rake::MultiFileTask, Task[product]
      assert_equal [SOURCE], Task[product].prerequisites
    end
  end

  def test_products_share_a_single_group
    multifile_task

    assert_same Task[PRODUCT_A].group, Task[PRODUCT_B].group
    assert_equal PRODUCTS, Task[PRODUCT_A].group.names
  end

  def test_any_product_triggers_a_single_action_building_all
    multifile_task

    Task[PRODUCT_A].invoke

    assert_equal 1, @runs.size
    PRODUCTS.each { |p| assert File.exist?(p), "#{p} should exist" }
  end

  def test_not_needed_when_products_are_newer_than_sources
    create_timed_files(SOURCE, *PRODUCTS)
    multifile_task

    PRODUCTS.each do |product|
      assert ! Task[product].needed?, "#{product} should not be needed"
    end

    Task[PRODUCT_A].invoke
    assert_empty @runs
  end

  def test_missing_product_rebuilds_the_whole_group
    create_timed_files(SOURCE, *PRODUCTS)
    FileUtils.rm PRODUCT_B
    multifile_task

    assert Task[PRODUCT_A].needed?, "group should be needed"

    Task[PRODUCT_A].invoke

    assert_equal 1, @runs.size
    assert File.exist?(PRODUCT_B)
  end

  def test_source_newer_than_any_product_rebuilds_the_group
    now = Time.now
    create_file(PRODUCT_A, now)
    create_file(PRODUCT_B, now - 60)
    create_file(SOURCE, now - 30) # newer than PRODUCT_B only
    multifile_task

    assert Task[PRODUCT_A].needed?, "group should be needed"

    Task[PRODUCT_A].invoke
    assert_equal 1, @runs.size
  end

  def test_invoking_every_product_runs_the_action_once
    multifile_task

    PRODUCTS.each { |p| Task[p].invoke }

    assert_equal 1, @runs.size
  end

  def test_concurrent_invocation_of_products_runs_the_action_once
    multifile_task([]) do |t|
      sleep 0.05
      @runs << t.name
      PRODUCTS.each { |p| FileUtils.touch p }
    end

    threads = PRODUCTS.map { |p| Thread.new { Task[p].invoke } }
    threads.each(&:join)

    assert_equal 1, @runs.size
    PRODUCTS.each { |p| assert File.exist?(p), "#{p} should exist" }
  end

  def test_missing_declared_product_after_action_is_an_error
    multifile_task([]) do |t|
      @runs << t.name
      FileUtils.touch PRODUCT_A # forgets PRODUCT_B
    end

    ex = assert_raise(RuntimeError) { Task[PRODUCT_A].invoke }
    assert_match(/did not create/, ex.message)
    assert_match(/#{PRODUCT_B}/, ex.message)
    assert ! Task[PRODUCT_A].already_invoked,
      "failed group must not be left in a completed state"
  end

  def test_failure_does_not_leave_a_completed_group_state
    attempts = 0
    multifile_task([]) do |t|
      attempts += 1
      fail "boom" if attempts == 1
      PRODUCTS.each { |p| FileUtils.touch p }
    end

    assert_raise(RuntimeError) { Task[PRODUCT_A].invoke }
    assert ! Task[PRODUCT_A].already_invoked,
      "failed group must not be left in a completed state"

    Task[PRODUCT_B].invoke
    assert_equal 2, attempts
    PRODUCTS.each { |p| assert File.exist?(p), "#{p} should exist" }
  end

  def test_reenable_allows_the_group_to_run_again
    create_timed_files(SOURCE, *PRODUCTS)
    FileUtils.rm PRODUCT_B
    multifile_task

    Task[PRODUCT_A].invoke
    assert_equal 1, @runs.size

    Task[PRODUCT_A].reenable
    assert !Task[PRODUCT_B].already_invoked

    FileUtils.rm PRODUCT_B
    Task[PRODUCT_B].invoke
    assert_equal 2, @runs.size
  end

  def test_product_usable_as_prerequisite_of_other_tasks
    multifile_task
    file "final.out" => [PRODUCT_B] do |t|
      @runs << t.name
      FileUtils.touch "final.out"
    end

    Task["final.out"].invoke

    assert_equal [PRODUCT_B, "final.out"].sort, @runs.sort
    PRODUCTS.each { |p| assert File.exist?(p), "#{p} should exist" }
    assert File.exist?("final.out")
  ensure
    FileUtils.rm_f "final.out"
  end

  def test_file_task_conflicting_with_a_product_is_an_error
    multifile_task

    ex = assert_raise(RuntimeError) { file PRODUCT_A }
    assert_match(/already a product of the multi-output task/, ex.message)
  end

  def test_plain_task_conflicting_with_a_product_is_an_error
    multifile_task

    ex = assert_raise(RuntimeError) { task PRODUCT_A.to_sym }
    assert_match(/already a product of the multi-output task/, ex.message)
  end

  def test_multifile_conflicting_with_an_existing_file_task_is_an_error
    file PRODUCT_A

    ex = assert_raise(RuntimeError) { multifile_task }
    assert_match(/already defined as a Rake::FileTask/, ex.message)
  end

  def test_multifile_conflicting_with_another_multifile_is_an_error
    multifile_task

    ex = assert_raise(RuntimeError) {
      multifile [PRODUCT_B, "other.rb"] => [SOURCE] do
        FileUtils.touch "other.rb"
      end
    }
    assert_match(/already a product of the multi-output task/, ex.message)
  ensure
    FileUtils.rm_f "other.rb"
  end

  def test_empty_product_list_is_an_error
    assert_raise(Rake::TaskArgumentError) { multifile [] => [SOURCE] }
  end
end
