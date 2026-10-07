# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "fileutils"

class TestRakeContentFileTask < Rake::TestCase # :nodoc:
  include Rake

  ENVIRONMENT_NAME = "RAKE_TEST_CONTENT_FILE_MODE"

  def setup
    super
    Task.clear
    @runs = 0
    ENV.delete(ENVIRONMENT_NAME)
  end

  def teardown
    ENV.delete(ENVIRONMENT_NAME)
    super
  end

  def test_content_and_mtime_are_checked_independently
    in_temp_directory do
      old_time = Time.at(1_000_000_000)
      File.write("config", "one")
      File.utime(old_time, old_time, "config")

      task = define_build_task
      task.invoke

      assert_equal 1, @runs
      refute task.needed?

      File.utime(Time.now, Time.now, "config")
      task.reenable
      task.invoke

      assert_equal 1, @runs
      assert_nil task.outdated_reason

      File.write("config", "two")
      File.utime(old_time, old_time, "config")

      assert task.needed?
      assert_equal(
        "input #{File.expand_path("config")} changed",
        task.outdated_reason
      )

      task.reenable
      task.invoke

      assert_equal 2, @runs
      assert_equal "two", File.read("output")
    end
  end

  def test_missing_input_has_explanatory_reason
    in_temp_directory do
      File.write("config", "one")
      task = define_build_task
      task.invoke

      File.delete("config")

      assert task.needed?
      assert_equal "input #{File.expand_path("config")} is missing",
                   task.outdated_reason
    end
  end

  def test_missing_input_on_first_invocation_runs_action
    in_temp_directory do
      task = content_file "output", inputs: %w[config], action_version: 1 do |t|
        File.write(t.name, "")
        @runs += 1
      end

      task.invoke

      assert_equal 1, @runs
      assert_equal "", File.read("output")
      refute task.needed?
      assert_nil task.outdated_reason
    end
  end

  def test_symlink_target_change_is_detected
    in_temp_directory do
      File.write("target-a", "one")
      File.write("target-b", "two")
      File.symlink("target-a", "config")

      task = define_build_task
      task.invoke
      assert_equal "one", File.read("output")

      File.delete("config")
      File.symlink("target-b", "config")

      assert task.needed?
      assert_equal(
        "input #{File.expand_path("config")} changed symlink target from target-a to target-b",
        task.outdated_reason
      )

      task.reenable
      task.invoke
      assert_equal "two", File.read("output")
    end
  end

  def test_symlink_target_content_change_is_detected
    in_temp_directory do
      File.write("target", "one")
      File.symlink("target", "config")

      task = define_build_task
      task.invoke

      File.write("target", "two")

      assert task.needed?
      assert_match(/input .*target changed/, task.outdated_reason)
    end
  end

  def test_missing_and_empty_environment_variables_are_distinguished
    in_temp_directory do
      task = content_file "output", inputs: [], env: [ENVIRONMENT_NAME],
                                action_version: 1 do |t|
        File.write(t.name, ENV.fetch(ENVIRONMENT_NAME, "<missing>"))
        @runs += 1
      end

      task.invoke
      assert_equal 1, @runs

      ENV[ENVIRONMENT_NAME] = ""
      assert task.needed?
      assert_equal(
        %(environment #{ENVIRONMENT_NAME} state changed from "missing" to "present"),
        task.outdated_reason
      )

      task.reenable
      task.invoke
      assert_equal 2, @runs

      ENV.delete(ENVIRONMENT_NAME)
      assert task.needed?
      assert_equal(
        %(environment #{ENVIRONMENT_NAME} state changed from "present" to "missing"),
        task.outdated_reason
      )
    end
  end

  def test_missing_null_and_empty_task_parameters_are_distinguished
    in_temp_directory do
      reasons = []
      task = content_file "output", [:mode], inputs: [],
                                action_version: 1 do |t, args|
        reasons << t.outdated_reason if @runs > 0
        File.write(t.name, args.mode.nil? ? "nil-or-missing" : args.mode)
        @runs += 1
      end

      task.invoke
      assert_equal 1, @runs

      task.reenable
      task.invoke(nil)
      assert_equal 2, @runs
      assert_match(/parameter mode state changed from "missing" to "null"/,
                   reasons.first)

      task.reenable
      task.invoke("")
      assert_equal 3, @runs
      assert_match(/parameter mode state changed from "null" to "present"/,
                   reasons.last)

      task.reenable
      task.invoke("")
      assert_equal 3, @runs
    end
  end

  def test_missing_null_and_empty_static_parameters_change_signature
    in_temp_directory do
      task = content_file "output", inputs: [],
                                action_version: 1 do |t|
        File.write(t.name, "initial")
      end
      task.invoke

      task.reenable
      task.configure(action_version: 1, params: { mode: nil })
      assert_match(/parameter mode was added/, task.outdated_reason)
      task.invoke

      task.reenable
      task.configure(action_version: 1, params: { mode: "" })
      assert task.needed?
      task.invoke

      task.reenable
      task.configure(action_version: 1, params: { mode: "" })
      refute task.needed?
    end
  end

  def test_action_version_change_rebuilds
    in_temp_directory do
      File.write("config", "one")
      task = define_build_task
      task.invoke

      task.configure(action_version: 2, inputs: %w[config])

      assert task.needed?
      assert_equal %(action version changed from 1 to 2), task.outdated_reason
    end
  end

  def test_externally_rewritten_artifact_rebuilds
    in_temp_directory do
      File.write("config", "one")
      old_time = Time.at(1_000_000_000)
      task = define_build_task
      task.invoke

      File.write("output", "tampered")
      File.utime(old_time, old_time, "output")

      assert task.needed?
      assert_equal "target #{File.expand_path("output")} changed",
                   task.outdated_reason
    end
  end

  def test_malformed_signature_rebuilds
    in_temp_directory do
      File.write("config", "one")
      task = define_build_task
      task.invoke

      File.write("output.rake-content-signature", "{")

      assert task.needed?
      assert_match(/signature file is malformed/, task.outdated_reason)

      task.reenable
      task.invoke
      assert_equal 2, @runs
    end
  end

  def test_signature_is_recorded_only_after_successful_verified_action
    in_temp_directory do
      File.write("config", "one")
      task = content_file "output", inputs: %w[config], action_version: 1,
                                verify: ->(t) { File.read(t.name) == "one" } do |t|
        File.write(t.name, "bad")
        @runs += 1
      end

      error = assert_raise(Rake::ContentFileTask::InvalidArtifact) do
        task.invoke
      end
      assert_equal "artifact failed validation: output", error.message
      assert_equal 1, @runs
      refute File.exist?("output.rake-content-signature")

      task.reenable
      task.configure(action_version: 1, inputs: %w[config])
      task.enhance do
        File.write("output", "one")
      end
      task.invoke

      assert File.exist?("output.rake-content-signature")
    end
  end

  def test_failed_action_does_not_record_signature
    in_temp_directory do
      File.write("config", "one")
      task = content_file "output", inputs: %w[config], action_version: 1 do
        File.write("output", "partial")
        raise "action failed"
      end

      assert_raise(RuntimeError) { task.invoke }
      refute File.exist?("output.rake-content-signature")
    end
  end

  def test_inputs_are_prerequisites
    in_temp_directory do
      file "config" do
        File.write("config", "from prerequisite")
      end
      task = define_build_task
      task.invoke

      assert_equal "from prerequisite", File.read("output")
    end
  end

  def test_content_change_rebuilds_dependent_file_task
    in_temp_directory do
      old_time = Time.at(1_000_000_000)
      File.write("config", "one")
      content = define_build_task
      file "derived" => ["output"] do
        File.write("derived", "derived:#{File.read("output")}")
      end
      derived = Task["derived"]

      derived.invoke
      assert_equal "derived:one", File.read("derived")

      File.write("config", "two")
      File.utime(old_time, old_time, "config", "derived")
      content.reenable
      derived.reenable
      derived.invoke

      assert_equal "derived:two", File.read("derived")
    end
  end

  def test_signature_includes_path_and_type
    in_temp_directory do
      File.write("config", "one")
      task = define_build_task
      task.invoke

      signature = JSON.parse(File.read("output.rake-content-signature"))

      assert_equal File.expand_path("output"), signature.dig("target", "path")
      assert_equal "file", signature.dig("target", "type")
      assert_equal File.expand_path("config"),
                   signature.dig("inputs", 0, "path")
      assert_equal "file", signature.dig("inputs", 0, "type")
    end
  end

  private

  def define_build_task
    content_file "output", inputs: %w[config], action_version: 1 do |t|
      File.write(t.name, File.read("config"))
      @runs += 1
    end
  end

  def in_temp_directory
    Dir.mktmpdir do |directory|
      Dir.chdir(directory) do
        yield
      end
    end
  end
end
