# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)
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
      # Mid: Comment
      b7

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

  def test_escaped_hash_colon_dollar_and_pipe
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      my\ file.o: header\#1.h weird\:name.h a\|b.h $$HOME/keep$$.c
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert Task.task_defined?("my file.o")
    assert_equal(
      ["header#1.h", "weird:name.h", "a|b.h", "$HOME/keep$.c"].sort,
      Task["my file.o"].prerequisites.sort)
  end

  def test_unescaped_hash_starts_a_comment
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      a.o: a.h # trailing comment with a\ file.h
      b.o: b.h #a comment
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal ["a.h"], Task["a.o"].prerequisites
    assert_equal ["b.h"], Task["b.o"].prerequisites
  end

  def test_multiple_targets_share_prerequisites
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      x.o y.o z.o: common.h
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    %w[x.o y.o z.o].each do |target|
      assert Task.task_defined?(target)
      assert_equal ["common.h"], Task[target].prerequisites
    end
  end

  def test_order_only_prerequisites
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      out.o: src.h | build/dir other\ order.h
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    task = Task["out.o"]
    assert_equal ["src.h"], task.prerequisites
    assert_equal ["build/dir", "other order.h"],
      task.order_only_prerequisites
  end

  def test_order_only_prerequisites_are_invoked_but_do_not_rebuild
    Dir.chdir @tempdir
    now = Time.now
    create_file("normal.h", now - 60)
    create_file("target.o", now - 30)  # up to date vs normal.h only
    File.write "sample.mf", <<~'SAMPLE_MF'
      target.o: normal.h | order.h
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    invoked = []
    # The Rakefile provides the order-only prerequisite (e.g. a directory
    # task); its action runs but its timestamp must not rebuild target.o.
    task "order.h"
    Task["order.h"].enhance { invoked << "order.h" }
    Task["target.o"].enhance { invoked << "target.o" }

    Task["target.o"].invoke

    assert invoked.include?("order.h"),
      "order-only prerequisite should be invoked"
    assert !invoked.include?("target.o"),
      "target must not rebuild due to an order-only prerequisite"
  end

  def test_normal_prerequisite_change_rebuilds
    Dir.chdir @tempdir
    now = Time.now
    create_file("target.o", now - 60)
    create_file("normal.h", now)
    File.write "sample.mf", <<~'SAMPLE_MF'
      target.o: normal.h
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    rebuilt = false
    Task["target.o"].enhance { rebuilt = true }
    Task["target.o"].invoke

    assert rebuilt
  end

  def test_consecutive_backslashes
    Dir.chdir @tempdir

    bs = "\\"
    # First physical line:
    #   a.o: a.h dir\ b\
    # "dir\\" (two backslashes) is a literal backslash; the single
    # backslash before the newline continues the logical line, which is
    # joined with a single space onto "c.h d.h".
    File.write "sample.mf",
      ["a.o: a.h dir#{bs * 2} b#{bs}", "c.h d.h"].join("\n")

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal ["a.h", "dir#{bs}", "b", "c.h", "d.h"],
      Task["a.o"].prerequisites
  end

  def test_empty_rules_are_allowed
    Dir.chdir @tempdir

    File.write "sample.mf", <<~'SAMPLE_MF'
      empty1:
      empty2 :
      withpre: pre.h
    SAMPLE_MF

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal [], Task["empty1"].prerequisites
    assert_equal [], Task["empty2"].prerequisites
    assert_equal ["pre.h"], Task["withpre"].prerequisites
  end

  def test_missing_final_newline
    Dir.chdir @tempdir

    File.write "sample.mf", "last.o: last.h"

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal ["last.h"], Task["last.o"].prerequisites
  end

  def test_line_continuation_without_final_newline
    Dir.chdir @tempdir

    File.write "sample.mf", "a.o: a.h b.h#{'\\'}\nc.h"

    Task.clear
    Rake::MakefileLoader.new.load "sample.mf"

    assert_equal %w[a.h b.h c.h], Task["a.o"].prerequisites
  end

  def test_dangling_continuation_reports_line_number
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: a.h#{'\\'}"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_recipe_lines_are_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: a.h\n\techo recipe\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:2:/, error.message)
  end

  def test_recipe_after_continuation_is_rejected_with_line_number
    Dir.chdir @tempdir
    File.write "sample.mf",
      "a.o: a.h#{'\\'}\nb.h#{'\\'}\n\trecipe\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:3:/, error.message)
  end

  def test_variable_assignment_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "CFLAGS = -O2\na.o: a.h\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_make_variable_reference_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: $(SRCS)/a.h\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_lone_dollar_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: a.h b$".dup << "\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_unterminated_escape_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: a.h b\\.h\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
    assert_match(/escape/, error.message)
  end

  def test_garbage_line_without_colon_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "this is not a rule\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_double_colon_rule_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o:: a.h\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_multiple_order_only_separators_are_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: a.h | b.h | c.h\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end

  def test_unescaped_colon_in_prerequisite_is_rejected
    Dir.chdir @tempdir
    File.write "sample.mf", "a.o: a.h :b.h\n"
    Task.clear

    error = assert_raise(ArgumentError) do
      Rake::MakefileLoader.new.load "sample.mf"
    end
    assert_match(/\Asample\.mf:1:/, error.message)
  end
end
