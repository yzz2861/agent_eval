# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "json"

class TestRakeArgumentFile < Rake::TestCase # :nodoc:

  def test_expands_quoted_values_using_published_rules
    write_file "args", <<~ARGS
      --trace
      "hello world"
      'value with spaces'
      "empty:" ""
      "literal" "@not-a-file"
      "backslash \\\\"
    ARGS

    expanded = Rake::ArgumentFileExpander.expand(["@args"])

    assert_equal [
      "--trace",
      "hello world",
      "value with spaces",
      "empty:",
      "",
      "literal",
      "@not-a-file",
      "backslash \\"
    ], expanded
  end

  def test_references_another_file_relative_to_referrer
    FileUtils.mkdir_p "config/nested"
    write_file "config/nested/inner.args", "--trace\n"
    write_file "config/main.args", "@nested/inner.args\n"
    write_file "root.args", "@config/main.args\n"

    assert_equal ["--trace"],
      Rake::ArgumentFileExpander.expand(["@root.args"])
  end

  def test_quoted_reference_path_allows_spaces
    FileUtils.mkdir_p "config"
    write_file "config/inner file.args", "--trace\n"
    write_file "root.args", "@\"config/inner file.args\"\n"

    assert_equal ["--trace"],
      Rake::ArgumentFileExpander.expand(["@root.args"])
  end

  def test_escaped_reference_path_allows_spaces
    FileUtils.mkdir_p "config"
    write_file "config/inner file.args", "--trace\n"
    write_file "root.args", "@config/inner\\ file.args\n"

    assert_equal ["--trace"],
      Rake::ArgumentFileExpander.expand(["@root.args"])
  end

  def test_literal_at_sign_can_be_quoted
    write_file "args", <<~ARGS
      "@keep"
      task["@value"]
    ARGS

    expanded = Rake::ArgumentFileExpander.expand(["@args"])
    name, arguments = Rake::Application.new.parse_task_string(expanded.last)

    assert_equal ["@keep", 'task["@value"]'], expanded
    assert_equal "task", name
    assert_equal ["@value"], arguments
  end

  def test_literal_at_sign_can_be_part_of_a_quoted_value
    write_file "args", "'prefix @literal suffix'\n"

    assert_equal ["prefix @literal suffix"],
      Rake::ArgumentFileExpander.expand(["@args"])
  end

  def test_quoted_commas_and_brackets_remain_task_arguments
    write_file "args", "'task[\"a,b\", \"x[y]\", x[y], \"tail]\"]'\n"

    expanded = Rake::ArgumentFileExpander.expand(["@args"])
    name, arguments = Rake::Application.new.parse_task_string(expanded.first)

    assert_equal "task", name
    assert_equal ["a,b", "x[y]", "x[y]", "tail]"], arguments
  end

  def test_quoted_task_name_supports_spaces_and_namespaces
    write_file "args", %q('build:release ["v1.2", "beta 1"]') + "\n"

    expanded = Rake::ArgumentFileExpander.expand(["@args"])
    name, arguments = Rake::Application.new.parse_task_string(expanded.first)

    assert_equal "build:release ", name
    assert_equal ["v1.2", "beta 1"], arguments
  end

  def test_does_not_perform_command_or_variable_expansion
    write_file "args", <<~ARGS
      "$HOME"
      "${HOME}"
      "`date`"
      "$(date)"
    ARGS

    assert_equal ["$HOME", "${HOME}", "`date`", "$(date)"],
      Rake::ArgumentFileExpander.expand(["@args"])
  end

  def test_leaves_option_and_environment_values_unchanged
    write_file "args", <<~ARGS
      --execute=[1,2]
      KEY=[a,b]
    ARGS

    assert_equal ["--execute=[1,2]", "KEY=[a,b]"],
      Rake::ArgumentFileExpander.expand(["@args"])
  end

  def test_reads_files_as_utf8
    write_file "args", "'日本語 🌏'\n".dup.force_encoding(Encoding::BINARY)

    assert_equal ["日本語 🌏"],
      Rake::ArgumentFileExpander.expand(["@args"])
  end

  def test_rejects_invalid_utf8
    File.binwrite("args", "\xff\xfe")

    error = assert_raises(Rake::ArgumentFileError) do
      Rake::ArgumentFileExpander.expand(["@args"])
    end
    assert_match(/not valid UTF-8/, error.message)
  end

  def test_limits_nesting_depth
    FileUtils.mkdir_p "nested"
    (0..Rake::ArgumentFileExpander::MAX_NESTING + 1).each do |depth|
      target = depth.zero? ? "root.args" : "nested/#{depth}.args"
      next_file = depth.zero? ? "nested/1.args" : "#{depth + 1}.args"
      write_file target, depth <= 8 ? "@#{next_file}\n" : "--trace\n"
    end

    error = assert_raises(Rake::ArgumentFileError) do
      Rake::ArgumentFileExpander.expand(["@root.args"])
    end
    assert_match(/nesting exceeds/, error.message)
  end

  def test_limits_total_bytes
    File.write("large.args", "x" * (Rake::ArgumentFileExpander::MAX_TOTAL_BYTES + 1))

    error = assert_raises(Rake::ArgumentFileError) do
      Rake::ArgumentFileExpander.expand(["@large.args"])
    end
    assert_match(/total parameter file size exceeds/, error.message)
  end

  def test_lexical_error_reports_file_position_and_task_argument
    write_file "args", <<~ARGS
      'task["one", "two
    ARGS

    error = assert_raises(Rake::ArgumentFileError) do
      Rake::ArgumentFileExpander.expand(["@args"])
    end
    path = Regexp.escape(File.expand_path("args"))
    assert_match(/\A#{path}:1:1: unterminated quote in task argument 2\z/,
      error.message)
  end

  def test_task_parse_error_reports_file_position_and_argument
    write_file "args", <<~'ARGS'
      "task['one', 'two"
    ARGS

    error = assert_raises(Rake::CommandLineOptionError) do
      app = Rake::Application.new
      expanded = Rake::ArgumentFileExpander.expand(["@args"])
      app.parse_task_string(expanded.first)
    end
    path = Regexp.escape(File.expand_path("args"))
    assert_match(/\A#{path}:1:14: task argument 2: unterminated quote\z/,
      error.message)
  end

  def test_direct_and_file_arguments_reach_task_identically
    arguments = [
      "task[\"a,b\", \"c d\", \"x[y]\", \"\", \"@literal\", \"tail]\"]"
    ]
    write_file "args", "'#{arguments.first}'\n"

    app = Rake::Application.new
    Rake.application = app
    app.define_task(Rake::Task, :task, :first, :second, :third,
      :fourth, :fifth, :sixth)

    direct_values = invoke_task_values(app, arguments.first)
    file_values = invoke_task_values(
      app, Rake::ArgumentFileExpander.expand(["@args"]).first
    )

    expected = ["a,b", "c d", "x[y]", "", "@literal", "tail]"]
    assert_equal expected, direct_values
    assert_equal expected, file_values
  end

  private

  def write_file(name, contents)
    File.binwrite(name, contents)
  end

  def invoke_task_values(app, task_string)
    name, arguments = app.parse_task_string(task_string)
    task = app[name]
    received = nil
    task.enhance do |t, args|
      received = args.to_a
    end
    task.reenable
    task.invoke(*arguments)
    received
  end
end
