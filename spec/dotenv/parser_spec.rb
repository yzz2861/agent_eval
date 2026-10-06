require "spec_helper"

describe Dotenv::Parser do
  def env(...)
    Dotenv::Parser.call(...)
  end

  it "parses unquoted values" do
    expect(env("FOO=bar")).to eql("FOO" => "bar")
  end

  it "parses unquoted values with spaces after seperator" do
    expect(env("FOO= bar")).to eql("FOO" => "bar")
  end

  it "parses unquoted escape characters correctly" do
    expect(env("FOO=bar\\ bar")).to eql("FOO" => "bar bar")
  end

  it "parses values with spaces around equal sign" do
    expect(env("FOO =bar")).to eql("FOO" => "bar")
    expect(env("FOO= bar")).to eql("FOO" => "bar")
  end

  it "parses values with leading spaces" do
    expect(env("  FOO=bar")).to eql("FOO" => "bar")
  end

  it "parses values with following spaces" do
    expect(env("FOO=bar  ")).to eql("FOO" => "bar")
  end

  it "parses double quoted values" do
    expect(env('FOO="bar"')).to eql("FOO" => "bar")
  end

  it "parses double quoted values with following spaces" do
    expect(env('FOO="bar"  ')).to eql("FOO" => "bar")
  end

  it "parses single quoted values" do
    expect(env("FOO='bar'")).to eql("FOO" => "bar")
  end

  it "parses single quoted values with following spaces" do
    expect(env("FOO='bar'  ")).to eql("FOO" => "bar")
  end

  it "parses escaped double quotes" do
    expect(env('FOO="escaped\"bar"')).to eql("FOO" => 'escaped"bar')
  end

  it "parses empty values" do
    expect(env("FOO=")).to eql("FOO" => "")
  end

  it "expands variables found in values" do
    expect(env("FOO=test\nBAR=$FOO")).to eql("FOO" => "test", "BAR" => "test")
  end

  it "parses variables wrapped in brackets" do
    expect(env("FOO=test\nBAR=${FOO}bar"))
      .to eql("FOO" => "test", "BAR" => "testbar")
  end

  it "expands variables from ENV if not found in .env" do
    ENV["FOO"] = "test"
    expect(env("BAR=$FOO")).to eql("BAR" => "test")
  end

  it "expands variables from ENV if found in .env during load" do
    ENV["FOO"] = "test"
    expect(env("FOO=development\nBAR=${FOO}")["BAR"])
      .to eql("test")
  end

  it "doesn't expand variables from ENV if in local env in overwrite" do
    ENV["FOO"] = "test"
    expect(env("FOO=development\nBAR=${FOO}")["BAR"])
      .to eql("test")
  end

  it "expands undefined variables to an empty string" do
    expect(env("BAR=$FOO")).to eql("BAR" => "")
  end

  it "expands variables in double quoted strings" do
    expect(env("FOO=test\nBAR=\"quote $FOO\""))
      .to eql("FOO" => "test", "BAR" => "quote test")
  end

  it "does not expand variables in single quoted strings" do
    expect(env("BAR='quote $FOO'")).to eql("BAR" => "quote $FOO")
  end

  it "does not expand escaped variables" do
    expect(env('FOO="foo\$BAR"')).to eql("FOO" => "foo$BAR")
    expect(env('FOO="foo\${BAR}"')).to eql("FOO" => "foo${BAR}")
    expect(env("FOO=test\nBAR=\"foo\\${FOO} ${FOO}\""))
      .to eql("FOO" => "test", "BAR" => "foo${FOO} test")
  end

  it "parses yaml style options" do
    expect(env("OPTION_A: 1")).to eql("OPTION_A" => "1")
  end

  it "parses export keyword" do
    expect(env("export OPTION_A=2")).to eql("OPTION_A" => "2")
  end

  it "allows export line if you want to do it that way" do
    expect(env('OPTION_A=2
export OPTION_A')).to eql("OPTION_A" => "2")
  end

  it "allows export line if you want to do it that way and checks for unset variables" do
    expect do
      env('OPTION_A=2
export OH_NO_NOT_SET')
    end.to raise_error(Dotenv::FormatError, 'Line "export OH_NO_NOT_SET" has an unset variable')
  end

  it 'escapes \n in quoted strings' do
    expect(env('FOO="bar\nbaz"')).to eql("FOO" => "bar\\nbaz")
    expect(env('FOO="bar\\nbaz"')).to eql("FOO" => "bar\\nbaz")
  end

  it 'expands \n and \r in quoted strings with DOTENV_LINEBREAK_MODE=legacy in current file' do
    ENV["DOTENV_LINEBREAK_MODE"] = "strict"

    contents = [
      "DOTENV_LINEBREAK_MODE=legacy",
      'FOO="bar\nbaz\rfizz"'
    ].join("\n")
    expect(env(contents)).to eql("DOTENV_LINEBREAK_MODE" => "legacy", "FOO" => "bar\nbaz\rfizz")
  end

  it 'expands \n and \r in quoted strings with DOTENV_LINEBREAK_MODE=legacy in ENV' do
    ENV["DOTENV_LINEBREAK_MODE"] = "legacy"
    contents = 'FOO="bar\nbaz\rfizz"'
    expect(env(contents)).to eql("FOO" => "bar\nbaz\rfizz")
  end

  it 'parses variables with "." in the name' do
    expect(env("FOO.BAR=foobar")).to eql("FOO.BAR" => "foobar")
  end

  it "strips unquoted values" do
    expect(env("foo=bar ")).to eql("foo" => "bar") # not 'bar '
  end

  it "ignores lines that are not variable assignments" do
    expect(env("lol$wut")).to eql({})
  end

  it "ignores empty lines" do
    expect(env("\n \t  \nfoo=bar\n \nfizz=buzz"))
      .to eql("foo" => "bar", "fizz" => "buzz")
  end

  it "does not ignore empty lines in quoted string" do
    value = "a\n\nb\n\nc"
    expect(env("FOO=\"#{value}\"")).to eql("FOO" => value)
  end

  it "ignores inline comments" do
    expect(env("foo=bar # this is foo")).to eql("foo" => "bar")
  end

  it "allows # in quoted value" do
    expect(env('foo="bar#baz" # comment')).to eql("foo" => "bar#baz")
  end

  it "allows # in quoted value with spaces after seperator" do
    expect(env('foo= "bar#baz" # comment')).to eql("foo" => "bar#baz")
  end

  it "ignores comment lines" do
    expect(env("\n\n\n # HERE GOES FOO \nfoo=bar")).to eql("foo" => "bar")
  end

  it "ignores commented out variables" do
    expect(env("# HELLO=world\n")).to eql({})
  end

  it "ignores comment" do
    expect(env("# Uncomment to activate:\n")).to eql({})
  end

  it "includes variables without values" do
    input = 'DATABASE_PASSWORD=
DATABASE_USERNAME=root
DATABASE_HOST=/tmp/mysql.sock'

    output = {
      "DATABASE_PASSWORD" => "",
      "DATABASE_USERNAME" => "root",
      "DATABASE_HOST" => "/tmp/mysql.sock"
    }

    expect(env(input)).to eql(output)
  end

  it "parses # in quoted values" do
    expect(env('foo="ba#r"')).to eql("foo" => "ba#r")
    expect(env("foo='ba#r'")).to eql("foo" => "ba#r")
  end

  it "parses # in quoted values with following spaces" do
    expect(env('foo="ba#r"  ')).to eql("foo" => "ba#r")
    expect(env("foo='ba#r'  ")).to eql("foo" => "ba#r")
  end

  it "parses empty values" do
    expect(env("foo=")).to eql("foo" => "")
  end

  it "allows multi-line values in single quotes" do
    env_file = %(OPTION_A=first line
export OPTION_B='line 1
line 2
line 3'
OPTION_C="last line"
OPTION_ESCAPED='line one
this is \\'quoted\\'
one more line')

    expected_result = {
      "OPTION_A" => "first line",
      "OPTION_B" => "line 1\nline 2\nline 3",
      "OPTION_C" => "last line",
      "OPTION_ESCAPED" => "line one\nthis is \\'quoted\\'\none more line"
    }
    expect(env(env_file)).to eql(expected_result)
  end

  it "allows multi-line values in double quotes" do
    env_file = %(OPTION_A=first line
export OPTION_B="line 1
line 2
line 3"
OPTION_C="last line"
OPTION_ESCAPED="line one
this is \\"quoted\\"
one more line")

    expected_result = {
      "OPTION_A" => "first line",
      "OPTION_B" => "line 1\nline 2\nline 3",
      "OPTION_C" => "last line",
      "OPTION_ESCAPED" => "line one\nthis is \"quoted\"\none more line"
    }
    expect(env(env_file)).to eql(expected_result)
  end

  if RUBY_VERSION > "1.8.7"
    it "parses shell commands interpolated in $()" do
      expect(env("echo=$(echo hello)", command_policy: :shell)).to eql("echo" => "hello")
    end

    it "allows balanced parentheses within interpolated shell commands" do
      expect(env('echo=$(echo "$(echo "$(echo "$(echo hello)")")")', command_policy: :shell))
        .to eql("echo" => "hello")
    end

    it "doesn't interpolate shell commands when escape says not to" do
      expect(env('echo=escaped-\$(echo hello)'))
        .to eql("echo" => "escaped-$(echo hello)")
    end

    it "is not thrown off by quotes in interpolated shell commands" do
      expect(env('interp=$(echo "Quotes won\'t be a problem")', command_policy: :shell)["interp"])
        .to eql("Quotes won't be a problem")
    end

    it "handles parentheses in variables in commands" do
      expect(env("FOO='passwo(rd'\nBAR=$(echo '$FOO')", command_policy: :shell))
        .to eql("FOO" => "passwo(rd", "BAR" => "passwo(rd")
    end

    it "handles command to variable to command chain" do
      expect(env("FOO=$(echo bar)\nBAR=$(echo $FOO)", command_policy: :shell))
        .to eql("FOO" => "bar", "BAR" => "bar")
    end

    it "supports carriage return" do
      expect(env("FOO=bar\rbaz=fbb")).to eql("FOO" => "bar", "baz" => "fbb")
    end

    it "supports carriage return combine with new line" do
      expect(env("FOO=bar\r\nbaz=fbb")).to eql("FOO" => "bar", "baz" => "fbb")
    end

    it "escapes carriage return in quoted strings" do
      expect(env('FOO="bar\rbaz"')).to eql("FOO" => "bar\\rbaz")
    end

    it "escape $ properly when no alphabets/numbers/_  are followed by it" do
      expect(env("FOO=\"bar\\$ \\$\\$\"")).to eql("FOO" => "bar$ $$")
    end

    # echo bar $ -> prints bar $ in the shell
    it "ignore $ when it is not escaped and no variable is followed by it" do
      expect(env("FOO=\"bar $ \"")).to eql("FOO" => "bar $ ")
    end

    # This functionality is not supported on JRuby or Rubinius
    if (!defined?(RUBY_ENGINE) || RUBY_ENGINE != "jruby") &&
        !defined?(Rubinius)
      it "substitutes shell variables within interpolated shell commands" do
        expect(env(%(VAR1=var1\ninterp=$(echo "VAR1 is $VAR1")), command_policy: :shell)["interp"])
          .to eql("VAR1 is var1")
      end
    end
  end

  it "returns existing value for redefined variable" do
    ENV["FOO"] = "existing"
    expect(env("FOO=bar")).to eql("FOO" => "existing")
  end

  describe "command policies" do
    # Executor that records every invocation: [command, view, location]
    class RecordingExecutor
      attr_reader :calls

      def initialize(results = {})
        @results = results
        @calls = []
      end

      def call(command, view, location)
        raise "view must be frozen" unless view.frozen?
        @calls << [command, view.dup, location]
        if @results.key?(command)
          @results[command]
        else
          Dotenv::CommandResult.success("<#{command}>")
        end
      end
    end

    it "defaults to disabling command substitution" do
      expect { env("FOO=$(echo hi)") }
        .to raise_error(Dotenv::CommandNotAllowedError, /disabled.*\$\(echo hi\)/)
    end

    it "explicit :disabled policy raises and never invokes a command" do
      executor = RecordingExecutor.new
      expect do
        env("FOO=$(echo hi)", command_policy: executor) # sanity: callable works
      end.not_to raise_error
      expect(executor.calls.length).to eq(1)

      expect { env("FOO=$(echo hi)", command_policy: :disabled) }
        .to raise_error(Dotenv::CommandNotAllowedError)
    end

    it "keeps command syntax literal with the :literal policy and executes nothing" do
      executor = RecordingExecutor.new
      expect(env('FOO=pre-$(echo hi)-post', command_policy: :literal))
        .to eql("FOO" => "pre-$(echo hi)-post")
      expect(executor.calls).to be_empty
    end

    it "keeps nested commands literal without execution" do
      expect(env('FOO=a$(outer $(inner))b', command_policy: :literal))
        .to eql("FOO" => "a$(outer $(inner))b")
    end

    it "passes command text, a frozen variable view, and source location to the executor" do
      executor = RecordingExecutor.new
      source = "NAME=world\nGREETING=$(hello $NAME)"
      env(source, command_policy: executor, filename: "/path/to/.env")

      expect(executor.calls.length).to eq(1)
      command, view, location = executor.calls.first
      expect(command).to eq("hello $NAME")
      expect(view).to be_a(Hash)
      expect(view).to include("NAME" => "world")
      expect(location).to have_attributes(filename: "/path/to/.env", line: 2)
    end

    it "substitutes the executor result into the value" do
      executor = RecordingExecutor.new("whoami" => "alice")
      expect(env('URL="postgres://$(whoami)@db"', command_policy: executor))
        .to eql("URL" => "postgres://alice@db")
    end

    it "accepts a plain return value from the executor" do
      executor = ->(command, _view, _location) { "got:#{command}" }
      expect(env("FOO=$(x)", command_policy: executor))
        .to eql("FOO" => "got:x")
    end

    it "resolves nested commands inner-most first" do
      order = []
      executor = lambda do |command, _view, _location|
        order << command
        Dotenv::CommandResult.success("[#{command}]")
      end

      result = env("FOO=$(outer $(inner one) $(inner two))", command_policy: executor)["FOO"]

      expect(order).to eq(["inner one", "inner two", "outer [inner one] [inner two]"])
      expect(result).to eq("[outer [inner one] [inner two]]")
    end

    it "does not evaluate commands inside branches that are not reached" do
      executor = RecordingExecutor.new
      # single quoted values are never evaluated
      expect(env("FOO='$(not run)'\nBAR=$(run)", command_policy: executor))
        .to eql("FOO" => "$(not run)", "BAR" => "<run>")

      commands = executor.calls.map(&:first)
      expect(commands).to eq(["run"])
      expect(commands).not_to include("not run")
    end

    it "leaves escaped commands literal and does not execute them" do
      executor = RecordingExecutor.new
      expect(env('FOO=x\$(not run)y', command_policy: executor))
        .to eql("FOO" => "x$(not run)y")
      expect(executor.calls.map(&:first)).to eq([])
    end

    it "handles escaped parens as literal parens in executor command text" do
      executor = RecordingExecutor.new
      env('FOO=$(echo a\(b\)c)', command_policy: executor)

      expect(executor.calls.length).to eq(1)
      expect(executor.calls.first[0]).to eq("echo a(b)c")
    end

    it "keeps escaped parens literal under the :literal policy" do
      source = "FOO=$(echo a\\(b)\\)c)"
      expect(env(source, command_policy: :literal)["FOO"])
        .to eq("$(echo a(b))c)")
    end

    it "raises CommandExecutionError when the executor returns a failure" do
      executor = ->(command, _view, _location) { Dotenv::CommandResult.failure("boom: #{command}") }
      expect { env("FOO=$(boom)", command_policy: executor) }
        .to raise_error(Dotenv::CommandExecutionError, /boom: boom/)
    end

    it "wraps exceptions raised by the executor and never falls back to a shell" do
      executor = ->(_command, _view, _location) { raise "nope" }
      expect { env("FOO=$(x)", command_policy: executor) }
        .to raise_error(Dotenv::CommandExecutionError, /nope/)
    end

    it "rejects invalid policies" do
      expect { env("FOO=x", command_policy: :nope) }
        .to raise_error(ArgumentError, /Unknown command policy/)
      expect { env("FOO=x", command_policy: 123) }
        .to raise_error(ArgumentError, /Invalid command policy/)
    end

    it "reports the line of a command inside a multi-line value" do
      executor = RecordingExecutor.new
      source = "FOO=\"line one\\nline two\"\nBAR=$(later)"
      env(source, command_policy: executor, filename: ".env")

      expect(executor.calls.first[2].line).to eq(2)
    end

    it "treats escaped commands as literal under every non-disabled policy" do
      executor = RecordingExecutor.new

      expect(env('FOO=a\$(x)b', command_policy: :shell)).to eql("FOO" => "a$(x)b")
      expect(env('FOO=a\$(x)b', command_policy: :literal)).to eql("FOO" => "a$(x)b")
      expect(env('FOO=a\$(x)b', command_policy: executor)).to eql("FOO" => "a$(x)b")
      expect(executor.calls).to be_empty
    end
  end
end
