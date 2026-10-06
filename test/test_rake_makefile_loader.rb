# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
require "fileutils"
require "rake/loaders/makefile"

class TestRakeMakefileLoader < Rake::TestCase  # :nodoc:
  include Rake

  def test_parse
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      # Comments
      a: a1 a2 a3 a4
      b: b1 b2 b3 \
         b4 b5 b6\
      b7

      # Mid: Comment

       a : a5 a6 a7
      c: c1
      d: d1 d2 \

      e f : e1 f1

      g\ 0: g1 g\ 2 g\ 3 g4
    SAMPLE_MF

    Task.clear
    loader = Rake::MakefileLoader.new
    loader.load "sample.mf"
    %w(a b c d).each do |t|
      assert Task.task_defined?(t), "#{t} should be a defined task"
    end
    assert_equal %w(a1 a2 a3 a4 a5 a6 a7).sort, Task["a"].prerequisites.sort
    assert_equal %w(b1 b2 b3 b4 b5 b6 b7).sort, Task["b"].prerequisites.sort
    assert_equal %w(c1).sort, Task["c"].prerequisites.sort
    assert_equal %w(d1 d2).sort, Task["d"].prerequisites.sort
    assert_equal %w(e1 f1).sort, Task["e"].prerequisites.sort
    assert_equal %w(e1 f1).sort, Task["f"].prerequisites.sort
    assert_equal(
      ["g1", "g 2", "g 3", "g4"].sort,
      Task["g 0"].prerequisites.sort)
    assert_equal 7, Task.tasks.size
  end

  def test_parse_escaped_names_continuations_and_order_only_prerequisites
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      my\ file.o\#x: header\#name.h my\:header.h $$dollar.h \
        C\:\\path\\header.h | generated\ dir

      one two: shared normal | order

      empty:
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    target = Task["my file.o#x"]
    assert_equal [
      "C:\\path\\header.h",
      "$dollar.h",
      "header#name.h",
      "my:header.h",
    ].sort, target.prerequisites.sort
    assert_equal ["generated dir"], target.order_only_prerequisites

    ["one", "two"].each do |name|
      assert_equal ["normal", "shared"], Task[name].prerequisites.sort
      assert_equal ["order"], Task[name].order_only_prerequisites
    end
    assert_empty Task["empty"].prerequisites
    assert_equal ["empty", "my file.o#x", "one", "two"],
      Task.tasks.map(&:name).sort
  end

  def test_parse_consecutive_backslashes
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      literal\\ target: literal\\ dependency
      continued\ target: first \\\
        second
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal ["literal dependency"],
      Task["literal target"].prerequisites
    assert_equal ["first", "second"],
      Task["continued target"].prerequisites
  end

  def test_parse_without_final_newline
    Dir.chdir @tempdir
    File.write "sample.mf", "target: dependency"

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal ["dependency"], Task["target"].prerequisites
  end

  def test_recipe_lines_are_rejected_with_line_number
    Dir.chdir @tempdir
    File.write "sample.mf", "target: dependency\n\tcommand\n"

    Task.clear
    error = assert_raises(Rake::MakefileLoader::ParseError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end

    assert_equal "sample.mf:2: recipes are not supported", error.message
  end

  def test_recipe_lines_after_continuations_are_rejected_with_line_number
    Dir.chdir @tempdir
    File.write "sample.mf", "target: dependency \\
\tcommand\n"

    Task.clear
    error = assert_raises(Rake::MakefileLoader::ParseError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end

    assert_equal "sample.mf:2: recipes are not supported", error.message
  end

  def test_even_backslashes_do_not_continue_into_recipe_lines
    Dir.chdir @tempdir
    File.binwrite "sample.mf", "target: dependency \\\\\n\trun\n"

    Task.clear
    error = assert_raises(Rake::MakefileLoader::ParseError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end

    assert_equal "sample.mf:2: recipes are not supported", error.message
  end

  def test_variables_are_rejected_with_line_number
    Dir.chdir @tempdir
    File.write "sample.mf", "target: $(VARIABLE)\n"

    Task.clear
    error = assert_raises(Rake::MakefileLoader::ParseError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end

    assert_equal "sample.mf:1: variables are not supported", error.message
  end

  def test_variables_after_continuation_are_rejected_with_physical_line_number
    Dir.chdir @tempdir
    File.write "sample.mf", "target: dependency \\
$(VARIABLE)\n"

    Task.clear
    error = assert_raises(Rake::MakefileLoader::ParseError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end

    assert_equal "sample.mf:2: variables are not supported", error.message
    refute Task.task_defined?("target")
  end

  def test_dangling_line_continuation_is_rejected_with_line_number
    Dir.chdir @tempdir
    File.write "sample.mf", "target: dependency\\"

    Task.clear
    error = assert_raises(Rake::MakefileLoader::ParseError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end

    assert_equal(
      "sample.mf:1: unexpected end of file in line continuation",
      error.message)
  end

  def test_order_only_prerequisites_do_not_force_rebuilds
    Dir.chdir @tempdir

    FileUtils.touch ["target", "normal", "order"]
    File.utime(Time.now - 10, Time.now - 10, "target")
    File.utime(Time.now - 30, Time.now - 30, "normal")
    File.utime(Time.now, Time.now, "order")

    File.write "sample.mf", "target: normal | order"

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    refute Task["target"].needed?

    now = Time.now
    File.utime(now, now, "normal")
    assert Task["target"].needed?
  end
end
