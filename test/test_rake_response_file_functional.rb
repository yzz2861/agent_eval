# frozen_string_literal: true
require File.expand_path("../helper", __FILE__)

class TestRakeResponseFileFunctional < Rake::TestCase # :nodoc:
  include RubyRunner

  RAKEFILE = <<~RAKEFILE
    task :echo, :a, :b, :c do |_, args|
      [args.a, args.b, args.c].each { |value| puts value.inspect }
    end
  RAKEFILE

  # The same complex arguments, written once directly (shell quoting) and
  # once inside a response file (published response-file quoting).
  DIRECT_TASK = <<~TASK.chomp
    echo[hello\ world,a\\,b,\\[x\\]]
  TASK
  FILE_BODY = <<~FILE
    echo['hello world','a,b','[x]']
  FILE

  def setup
    super
    File.binwrite("Rakefile", RAKEFILE)
  end

  def test_direct_and_file_invocations_receive_identical_values
    File.binwrite("args.rsp", FILE_BODY)

    rake DIRECT_TASK
    direct_output = @out
    assert_success

    rake "--response-files", "@args.rsp"
    file_output = @out
    assert_success

    refute_empty direct_output
    assert_equal direct_output, file_output
    assert_equal [
      "\"hello world\"",
      "\"a,b\"",
      "\"[x]\""
    ], file_output.lines.map(&:chomp)
  end

  def test_file_can_mix_options_tasks_and_environment
    File.binwrite("args.rsp", "GREETING=hey echo['v,x']")
    rakefile = <<~RAKEFILE
      task :echo, :v do |_, args|
        puts ENV["GREETING"] + ":" + args.v
      end
    RAKEFILE
    File.binwrite("Rakefile", rakefile)

    rake "--response-files", "@args.rsp"
    assert_success
    assert_equal "hey:v,x\n", @out
  end

  def test_nested_file_resolves_relative_to_referrer
    FileUtils.mkdir_p("conf")
    File.binwrite("conf/args.rsp", "echo['[x]']")
    File.binwrite("main.rsp", "@conf/args.rsp\n")

    rake "--response-files", "@main.rsp"
    assert_success
    assert_include @out, "\"[x]\""
  end

  def test_without_flag_at_argument_is_a_task_name
    rake "@args.rsp"
    assert_match(/Don't know how to build task '@args.rsp'/, @err)
  end

  def test_missing_file_error_shows_argument_position
    rake "echo[x]", "--response-files", "@nope.rsp"
    refute @exit.success?
    assert_match(/cannot read response file/, @err)
    assert_match(/command-line argument 3/, @err)
  end

  def test_unterminated_quote_error_shows_file_position
    File.binwrite("args.rsp", "'oops\n")
    rake "--response-files", "@args.rsp"
    refute @exit.success?
    assert_match(/unterminated single quote/, @err)
    assert_match(/args\.rsp:1:1/, @err)
    assert_match(/command-line argument 2/, @err)
  end

  private

  def assert_success
    assert @exit.success?, "rake failed:\n#{@err}"
  end
end
