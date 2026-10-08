# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)

class TestRakeResponseFile < Rake::TestCase # :nodoc:
  E = Rake::ResponseFile

  def write_response(path, content)
    FileUtils.mkdir_p(File.dirname(path))
    File.binwrite(path, content)
  end

  def expand(*argv, **options)
    E.expand(argv, base_dir: Dir.pwd, **options)
  end

  def expand_array(argv, **options)
    E.expand(argv, base_dir: Dir.pwd, **options)
  end

  def test_passes_arguments_without_references_through
    assert_equal %w[task --trace VAR=value],
      expand("task", "--trace", "VAR=value")
  end

  def test_a_bare_at_is_a_literal_argument
    assert_equal ["@"], expand("@")
    write_response("args", "@\n")
    assert_equal ["@"], expand("@args")
  end

  def test_a_quoted_at_is_not_a_reference
    write_response("args", "'@path'\n")
    assert_equal ["@path"], expand("@args")
  end

  def test_an_escaped_at_is_not_a_reference
    write_response("args", "\\@path\n")
    assert_equal ["@path"], expand("@args")
  end

  def test_reference_path_may_join_quoted_and_unquoted_sections
    write_response("my args", "value\n")
    write_response("one", "@my' args'\n")
    assert_equal ["value"], expand("@one")
  end

  def test_reads_file_as_utf8
    write_response("args", "caf\xC3\xA9 task[\xE3\x81\x82]\n")
    assert_equal ["caf\u00e9", "task[\u3042]"], expand("@args")
  end

  def test_reports_invalid_utf8_with_line_and_column
    write_response("args", "good \xFF bad\n")
    ex = assert_raises(E::Error) { expand("@args") }
    assert_equal 0, ex.argument_index
    assert_match(/not valid UTF-8/, ex.message)
    assert_match(/args:1:6/, ex.message)
    assert_match(/command-line argument 1/, ex.message)
  end

  def test_empty_string_argument_from_quotes
    write_response("args", "''\n\"\"\n")
    assert_equal ["", ""], expand("@args")
  end

  def test_values_with_spaces
    write_response("args", "'hello world'\n\"a b c\"\nplain\n")
    assert_equal ["hello world", "a b c", "plain"], expand("@args")
  end

  def test_single_quotes_are_literal
    write_response("args", "'$HOME `date` \\n \"x\"'\n")
    assert_equal ["$HOME `date` \\n \"x\""], expand("@args")
  end

  def test_double_quotes_keep_backslash_when_not_escaping
    write_response("args", '"a\\b c$d c`e c\"f"' + "\n")
    assert_equal ["a\\b c$d c`e c\"f"], expand("@args")
  end

  def test_no_variable_or_command_substitution
    write_response("args", "$VAR $(echo hi) `echo hi\n")
    assert_equal ["$VAR", "$(echo", "hi)", "`echo", "hi"],
      expand("@args")
  end

  def test_unquoted_backslash_escapes_next_character
    write_response("args", "a\\ b\\@c\\,d\\\\e\n")
    assert_equal ["a b@c,d\\e"], expand("@args")
  end

  def test_backslash_newline_is_a_line_continuation
    write_response("args", "abc\\\ndef\n")
    assert_equal ["abcdef"], expand("@args")
  end

  def test_dangling_backslash_is_an_error
    write_response("args", "abc\\")
    ex = assert_raises(E::Error) { expand("@args") }
    assert_match(/dangling backslash/, ex.message)
    assert_match(/args:1:4/, ex.message)
    assert_equal 1, ex.token_number
  end

  def test_unterminated_quote_is_an_error
    write_response("args", "'never closed\n")
    ex = assert_raises(E::Error) { expand("@args") }
    assert_match(/unterminated single quote/, ex.message)
    assert_match(/args:1:1/, ex.message)
  end

  def test_missing_file_is_an_error
    ex = assert_raises(E::Error) { expand("@does-not-exist") }
    assert_match(/cannot read response file/, ex.message)
    assert_match(/command-line argument 1/, ex.message)
    assert_equal 0, ex.argument_index
  end

  def test_error_reports_argument_position
    ex = assert_raises(E::Error) do
      expand_array(["fine", "@does-not-exist", "later"])
    end
    assert_equal 1, ex.argument_index
    assert_match(/command-line argument 2/, ex.message)
  end

  def test_nested_file_relative_to_referrer
    write_response("one", "@sub/two\n")
    write_response("sub/two", "deep\n@three\n")
    write_response("sub/three", "deeper\n")
    assert_equal ["deep", "deeper"], expand("@one")
  end

  def test_nested_error_reports_chain_in_inclusion_order
    write_response("one", "@sub/two\n")
    write_response("sub/two", "'oops\n")
    ex = assert_raises(E::Error) { expand("@one") }
    message = ex.message
    assert_operator message.index("sub/two:1:1"), :<,
                    message.index("one:1:1")
    assert_match(/at .*sub\/two:1:1, included from .*one:1:1/, message)
  end

  def test_quoted_section_in_reference_path
    write_response("my args", "value\n")
    write_response("one", "@my\\ args\n@'my args'\n")
    assert_equal ["value", "value"], expand("@one")
  end

  def test_cyclic_inclusion_is_an_error
    write_response("a", "@b\n")
    write_response("b", "@a\n")
    ex = assert_raises(E::Error) { expand("@a") }
    assert_match(/cyclic response file inclusion/, ex.message)
    assert_match(/a:1:1/, ex.message)
  end

  def test_depth_is_limited
    (0..12).each do |n|
      write_response("f#{n}", "@f#{n + 1}\n")
    end
    write_response("f13", "done\n")
    ex = assert_raises(E::Error) { expand("@f0") }
    assert_match(/inclusion too deep/, ex.message)
  end

  def test_custom_depth_limit
    write_response("a", "@b\n")
    write_response("b", "done\n")
    ex = assert_raises(E::Error) do
      expand("@a", max_depth: 1)
    end
    assert_match(/inclusion too deep/, ex.message)
  end

  def test_total_bytes_is_limited
    write_response("args", "x" * 100)
    ex = assert_raises(E::Error) do
      expand("@args", max_total_bytes: 50)
    end
    assert_match(/byte limit/, ex.message)
  end

  def test_total_bytes_accumulates_across_files
    write_response("a", "@b\n")
    write_response("b", "x" * 60)
    assert_raises(E::Error) do
      expand("@a", max_total_bytes: 50)
    end
  end

  def test_quoted_commas_and_brackets_become_task_arguments
    write_response("args",
                   "task['a b', 'x,y', '[z]', '', a\\,b, q\\[q]\n")
    expanded = expand("@args")
    assert_equal 1, expanded.size

    name, args = Rake::Application.new.parse_task_string(expanded.first)
    assert_equal "task", name
    assert_equal ["a b", "x,y", "[z]", "", "a,b", "q[q"], args
  end

  def test_unquoted_commas_still_split_task_arguments
    write_response("args", "task[a, b]\n")
    name, args = Rake::Application.new.parse_task_string(expand("@args").first)
    assert_equal "task", name
    assert_equal %w[a b], args
  end

  def test_spaces_inside_brackets_keep_one_argument
    write_response("args", "task[a b, c d]\n")
    assert_equal ["task[a b, c d]"], expand("@args")
  end

  def test_options_inside_files_are_plain_arguments
    write_response("args", "--trace --jobs=4 greet['x,y']\n")
    assert_equal ["--trace", "--jobs=4", "greet[x\\,y]"],
      expand("@args")
  end

  def test_brackets_in_environment_values_are_not_task_escaped
    write_response("args", "X=task['a,b']\n")
    assert_equal ["X=task[a,b]"], expand("@args")
  end

  def test_brackets_in_option_values_are_not_task_escaped
    write_response("args", "--pattern=task['a,b']\n")
    assert_equal ["--pattern=task[a,b]"], expand("@args")
  end

  def test_expanded_options_are_parsed_by_application
    write_response("args", "--quiet task['x,y']\n")
    app = Rake::Application.new
    app.options.rakelib = []
    app.init("rake", ["--response-files", "@args"])
    assert Rake::FileUtilsExt.verbose_flag == false
    assert_equal ["task[x\\,y]"], app.top_level_tasks
  end

  def test_response_files_disabled_by_default
    write_response("args", "task\n")
    app = Rake::Application.new
    app.options.rakelib = []
    app.init("rake", ["@args"])
    assert_equal ["@args"], app.top_level_tasks
  end

  def test_same_values_directly_and_from_file
    complex = [
      "greet[hello world, a\\,b, \\[x\\], , @, $HOME, `echo hi`, " \
        "path with space]"
    ]
    write_response("args",
                   "greet['hello world', 'a,b', '[x]', '', '@', $HOME, " \
                     "`echo hi`, path\\ with\\ space]\n")

    from_direct = complex.map { |task|
      Rake::Application.new.parse_task_string(task)
    }
    from_file = expand("@args").map { |task|
      Rake::Application.new.parse_task_string(task)
    }

    assert_equal from_direct, from_file
  end
end
