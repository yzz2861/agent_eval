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
      expect(env("echo=$(echo hello)")).to eql("echo" => "hello")
    end

    it "allows balanced parentheses within interpolated shell commands" do
      expect(env('echo=$(echo "$(echo "$(echo "$(echo hello)")")")'))
        .to eql("echo" => "hello")
    end

    it "doesn't interpolate shell commands when escape says not to" do
      expect(env('echo=escaped-\$(echo hello)'))
        .to eql("echo" => "escaped-$(echo hello)")
    end

    it "is not thrown off by quotes in interpolated shell commands" do
      expect(env('interp=$(echo "Quotes won\'t be a problem")')["interp"])
        .to eql("Quotes won't be a problem")
    end

    it "handles parentheses in variables in commands" do
      expect(env("FOO='passwo(rd'\nBAR=$(echo '$FOO')")).to eql("FOO" => "passwo(rd", "BAR" => "passwo(rd")
    end

    it "handles command to variable to command chain" do
      expect(env("FOO=$(echo bar)\nBAR=$(echo $FOO)")).to eql("FOO" => "bar", "BAR" => "bar")
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
        expect(env(%(VAR1=var1\ninterp=$(echo "VAR1 is $VAR1")))["interp"])
          .to eql("VAR1 is var1")
      end
    end
  end

  it "returns existing value for redefined variable" do
    ENV["FOO"] = "existing"
    expect(env("FOO=bar")).to eql("FOO" => "existing")
  end

  describe "parameter expansion" do
    describe "${VAR:-default}" do
      it "uses the default when the variable is undefined" do
        expect(env("BAR=${MISSING:-fallback}")).to eql("BAR" => "fallback")
      end

      it "uses the default when the variable is empty" do
        expect(env("FOO=\nBAR=${FOO:-fallback}"))
          .to eql("FOO" => "", "BAR" => "fallback")
      end

      it "uses the value when the variable is set" do
        expect(env("FOO=bar\nBAR=${FOO:-fallback}"))
          .to eql("FOO" => "bar", "BAR" => "bar")
      end
    end

    describe "${VAR-default}" do
      it "uses the default when the variable is undefined" do
        expect(env("BAR=${MISSING-fallback}")).to eql("BAR" => "fallback")
      end

      it "keeps the empty string when the variable is empty" do
        expect(env("FOO=\nBAR=${FOO-fallback}"))
          .to eql("FOO" => "", "BAR" => "")
      end

      it "uses the value when the variable is set" do
        expect(env("FOO=bar\nBAR=${FOO-fallback}"))
          .to eql("FOO" => "bar", "BAR" => "bar")
      end
    end

    describe "${VAR:+alternate}" do
      it "expands to nothing when the variable is undefined" do
        expect(env("BAR=${MISSING:+alternate}")).to eql("BAR" => "")
      end

      it "expands to nothing when the variable is empty" do
        expect(env("FOO=\nBAR=${FOO:+alternate}"))
          .to eql("FOO" => "", "BAR" => "")
      end

      it "uses the alternate when the variable is set" do
        expect(env("FOO=bar\nBAR=${FOO:+alternate}"))
          .to eql("FOO" => "bar", "BAR" => "alternate")
      end
    end

    describe "${VAR+alternate}" do
      it "expands to nothing when the variable is undefined" do
        expect(env("BAR=${MISSING+alternate}")).to eql("BAR" => "")
      end

      it "uses the alternate when the variable is empty" do
        expect(env("FOO=\nBAR=${FOO+alternate}"))
          .to eql("FOO" => "", "BAR" => "alternate")
      end

      it "uses the alternate when the variable is set" do
        expect(env("FOO=bar\nBAR=${FOO+alternate}"))
          .to eql("FOO" => "bar", "BAR" => "alternate")
      end
    end

    describe "${VAR:?message}" do
      it "raises with the message when the variable is undefined" do
        expect { env("BAR=${MISSING:?must be set}") }
          .to raise_error(Dotenv::Substitutions::Variable::MissingVariableError,
            "MISSING: must be set")
      end

      it "raises when the variable is empty" do
        expect { env("FOO=\nBAR=${FOO:?must be set}") }
          .to raise_error(Dotenv::Substitutions::Variable::MissingVariableError,
            "FOO: must be set")
      end

      it "uses the value when the variable is set" do
        expect(env("FOO=bar\nBAR=${FOO:?must be set}"))
          .to eql("FOO" => "bar", "BAR" => "bar")
      end

      it "uses a default message when none is given" do
        expect { env("BAR=${MISSING:?}") }
          .to raise_error(Dotenv::Substitutions::Variable::MissingVariableError,
            "MISSING: parameter not set or empty")
      end
    end

    describe "${VAR?message}" do
      it "raises with the message when the variable is undefined" do
        expect { env("BAR=${MISSING?must be set}") }
          .to raise_error(Dotenv::Substitutions::Variable::MissingVariableError,
            "MISSING: must be set")
      end

      it "keeps the empty string when the variable is empty" do
        expect(env("FOO=\nBAR=${FOO?must be set}"))
          .to eql("FOO" => "", "BAR" => "")
      end

      it "uses the value when the variable is set" do
        expect(env("FOO=bar\nBAR=${FOO?must be set}"))
          .to eql("FOO" => "bar", "BAR" => "bar")
      end

      it "uses a default message when none is given" do
        expect { env("BAR=${MISSING?}") }
          .to raise_error(Dotenv::Substitutions::Variable::MissingVariableError,
            "MISSING: parameter not set")
      end
    end

    it "expands variables inside defaults" do
      expect(env("FOO=from_var\nBAR=${MISSING:-$FOO}"))
        .to eql("FOO" => "from_var", "BAR" => "from_var")
    end

    it "expands variables inside alternates" do
      expect(env("FOO=bar\nALT=alternate\nBAR=${FOO:+$ALT}"))
        .to eql("FOO" => "bar", "ALT" => "alternate", "BAR" => "alternate")
    end

    it "expands nested parameter expansions in defaults" do
      expect(env("BAR=${MISSING:-${ALSO_MISSING:-nested}}"))
        .to eql("BAR" => "nested")
    end

    it "reads variables from ENV" do
      ENV["HOST"] = "example.com"
      expect(env("URL=${HOST:-localhost}")).to eql("URL" => "example.com")
      expect(env("URL=${MISSING_HOST:-localhost}")).to eql("URL" => "localhost")
    end

    it "does not share variables between parses" do
      env("SHARED=defined")
      expect(env("BAR=${SHARED:-fallback}")).to eql("BAR" => "fallback")
    end

    it "does not expand parameter expressions in single quoted values" do
      expect(env("BAR='${MISSING:-fallback}'"))
        .to eql("BAR" => "${MISSING:-fallback}")
    end

    it "does not expand escaped parameter expressions" do
      expect(env('BAR=\${MISSING:-fallback}'))
        .to eql("BAR" => "${MISSING:-fallback}")
    end

    it "only executes commands from the selected branch" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "executed")
        expect(env("FOO=set\nBAR=${FOO:-$(touch #{path})}"))
          .to eql("FOO" => "set", "BAR" => "set")
        expect(File.exist?(path)).to be(false)

        expect(env("BAR=${MISSING:-$(touch #{path})}")).to eql("BAR" => "")
        expect(File.exist?(path)).to be(true)
      end
    end

    it "executes commands in selected alternates" do
      expect(env("FOO=set\nBAR=${FOO:+$(echo alternate)}"))
        .to eql("FOO" => "set", "BAR" => "alternate")
    end

    it "raises with position diagnostics when nesting exceeds the depth limit" do
      depth = Dotenv::Substitutions::Variable::MAX_DEPTH + 1
      expression = "#{"${NESTED:-" * depth}bottom#{"}" * depth}"
      expect { env("BAR=#{expression}") }
        .to raise_error(Dotenv::Substitutions::Variable::ExpansionDepthError,
          /deeper than 10 levels at offset \d+/)
    end

    it "allows nesting within the depth limit" do
      expect(env("BAR=${A:-${B:-${C:-nested}}}")).to eql("BAR" => "nested")
    end
  end
end
