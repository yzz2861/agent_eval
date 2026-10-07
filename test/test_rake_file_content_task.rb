# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "fileutils"

class TestRakeFileContentTask < Rake::TestCase # :nodoc:
  include Rake

  def setup
    super
    Task.clear
    @runs = 0
  end

  def test_builds_and_reuses_without_mtime_dependencies
    File.write("input", "a")

    task = define_task("output", "input")
    task.invoke
    assert_equal 1, @runs
    assert File.file?(".rake/file-content-signatures/#{signature_name("output")}")

    task.reenable
    future = Time.now + 10
    FileUtils.touch("input")
    File.utime(future, future, "input")
    FileUtils.touch("output")
    File.utime(future, future, "output")

    refute task.needed?, "unchanged content must remain valid when mtime changes"
    task.invoke
    assert_equal 1, @runs
  end

  def test_content_change_with_same_mtime_rebuilds
    File.write("input", "a")
    task = define_task("output", "input")
    task.invoke

    original_mtime = File.mtime("input")
    File.write("input", "b")
    File.utime(File.atime("input"), original_mtime, "input")

    assert_equal original_mtime.nsec, File.mtime("input").nsec
    task.reenable
    assert task.needed?, "changed content must invalidate an unchanged mtime"
    task.invoke
    assert_equal 2, @runs
  end

  def test_externally_rewritten_output_rebuilds_with_same_mtime
    File.write("input", "a")
    task = define_task("output", "input")
    task.invoke

    original_mtime = File.mtime("output")
    File.write("output", "external change")
    File.utime(File.atime("output"), original_mtime, "output")

    task.reenable
    assert task.needed?
    task.invoke
    assert_equal 2, @runs
  end

  def test_missing_input_has_a_distinct_typed_signature
    File.write("input", "a")
    task = define_task("output", "input")
    task.invoke

    File.delete("input")
    task.reenable

    assert task.needed?
  end

  def test_symlink_target_change_rebuilds_even_for_equal_content
    File.write("target_a", "same")
    File.write("target_b", "same")
    File.symlink("target_a", "input")

    task = define_task("output", "input")
    task.invoke

    File.delete("input")
    File.symlink("target_b", "input")
    task.reenable

    assert task.needed?
  end

  def test_environment_missing_empty_and_present_have_distinct_signatures
    File.write("input", "a")
    task = define_task("output", "input", env: ["MODE"])

    ENV.delete("MODE")
    missing_signature = task.current_signature

    ENV["MODE"] = ""
    empty_signature = task.current_signature

    ENV["MODE"] = "production"
    present_signature = task.current_signature

    refute_equal missing_signature, empty_signature
    refute_equal empty_signature, present_signature
  ensure
    ENV.delete("MODE")
  end

  def test_missing_nil_and_empty_parameters_have_distinct_signatures
    task = file_content("output", inputs: [], action_version: 1)
    missing_params_signature = task.current_signature

    task.configure_content_signature(inputs: [], action_version: 1, params: nil)
    nil_params_signature = task.current_signature

    task.configure_content_signature(inputs: [], action_version: 1, params: {})
    missing_key_signature = task.current_signature

    task.configure_content_signature(
      inputs: [], action_version: 1, params: {mode: nil}
    )
    nil_signature = task.current_signature

    task.configure_content_signature(
      inputs: [], action_version: 1, params: {mode: ""}
    )
    empty_signature = task.current_signature

    refute_equal missing_params_signature, nil_params_signature
    refute_equal nil_params_signature, missing_key_signature
    refute_equal missing_key_signature, nil_signature
    refute_equal nil_signature, empty_signature
  end

  def test_symlink_loop_has_a_typed_signature
    File.symlink("loop", "loop")
    task = file_content("output", inputs: ["loop"], action_version: 1)

    assert task.current_signature
  end

  def test_action_version_change_rebuilds
    File.write("input", "a")
    task = define_task("output", "input")
    task.invoke

    task.configure_content_signature(
      inputs: ["input"],
      env: [],
      params: {format: "txt"},
      action_version: 2
    )
    task.reenable

    assert task.needed?
  end

  def test_action_version_is_required
    error = assert_raises(ArgumentError) do
      file_content("output", inputs: []) {}
    end

    assert_match(/action_version/, error.message)
  end

  def test_failed_action_does_not_record_signature
    File.write("failed", "old")

    task = file_content("failed", inputs: [], env: [], params: {},
                         action_version: 1, signature_dir: "signatures") do
      @runs += 1
      raise "action failed"
    end

    assert_raises(RuntimeError) { task.invoke }
    refute File.exist?("signatures/#{signature_name("failed")}")
  end

  def test_invalid_output_does_not_record_signature
    FileUtils.mkdir_p("directory")
    task = file_content("directory", inputs: [], env: [], params: {},
                         action_version: 1, signature_dir: "signatures")

    assert_raises(Rake::FileContentOutputError) { task.invoke }
    refute File.exist?("signatures/#{signature_name("directory")}")
  end

  def test_dry_run_does_not_record_signature
    task = define_task("output", "input")
    Rake.application.options.dryrun = true
    task.invoke

    refute File.exist?(".rake/file-content-signatures/#{signature_name("output")}")
  ensure
    Rake.application.options.dryrun = false
  end

  def test_signature_options_coexist_with_prerequisites
    events = []
    task :prepare do
      events << :prepare
      File.write("input", "a")
    end

    output_task = file_content(
      "output" => [:prepare],
      inputs: ["input"],
      action_version: 1
    ) do
      events << :output
      File.write("output", "generated")
    end

    output_task.invoke

    assert_equal [:prepare, :output], events
    assert_kind_of Rake::FileContentTask, output_task
    assert_includes output_task.prerequisites, "prepare"
  end

  def test_redefinition_preserves_signature_configuration
    task = file_content(
      "output",
      inputs: ["input"],
      params: {format: "txt"},
      action_version: 1,
      signature_dir: "custom-signatures"
    )
    file_content("output") do
      File.write("output", "generated")
    end

    file_content("output", inputs: ["later-input"])

    assert_equal ["later-input"], task.content_inputs
    assert_equal({format: "txt"}, task.content_params)
    assert_equal 1, task.action_version
    assert_equal "custom-signatures", task.signature_dir
  end

  private

  def define_task(target, input, env: [], params: {format: "txt"}, action_version: 1)
    file_content(target, inputs: [input], env: env, params: params,
                 action_version: action_version) do
      @runs += 1
      File.write(target, "generated #{@runs}")
    end
  end

  def signature_name(target)
    Digest::SHA256.hexdigest(File.expand_path(target)) + ".json"
  end
end
