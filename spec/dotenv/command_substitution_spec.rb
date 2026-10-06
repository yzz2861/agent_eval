require "spec_helper"

# A local, in-process command executor that records every invocation instead
# of ever touching a system shell.
class RecordingExecutor
  attr_reader :calls, :env_views, :sources

  def initialize(responses = {})
    @responses = responses
    @calls = []
    @env_views = []
    @sources = []
  end

  def call_count
    @calls.size
  end

  def call(command, env, source)
    raise "executor received a mutated view" unless env.frozen?

    @calls << command
    @env_views << env
    @sources << source

    raise KeyError, "unknown command: #{command}" unless @responses.key?(command)
    @responses.fetch(command).call
  end

  def fail!(command)
    @responses[command] = -> { raise "boom" }
    self
  end
end

describe "command substitution policy" do
  def parse(content, **options)
    Dotenv::Parser.call(content, **options)
  end

  describe ":disabled policy" do
    it "raises instead of executing an active command" do
      expect do
        parse("FOO=$(whoami)", command_substitution: :disabled)
      end.to raise_error(Dotenv::CommandExecutionError, /disabled/)
    end

    it "reports the command and source location in the message" do
      expect do
        Dotenv::Parser.call(
          "FOO=$(whoami)",
          source: "/tmp/app.env",
          command_substitution: :disabled
        )
      end
        .to raise_error(
          Dotenv::CommandExecutionError,
          %r{disabled .for command "whoami" at /tmp/app\.env:1 in FOO}
        )
    end

    it "does not execute the command to resolve a nested command" do
      executor = RecordingExecutor.new

      expect do
        parse(
          %(OUTER=$(inner $(whoami))),
          command_substitution: :disabled
        )
      end.to raise_error(Dotenv::CommandExecutionError, /disabled/)

      expect(executor.call_count).to eq(0)
    end

    it "leaves escaped substitutions as literals without executing them" do
      # If anything reaches a shell executor it blows up; escaped text must not.
      allow(Dotenv::CommandExecutors::Shell).to receive(:new)
        .and_raise("shell must not be used")
      result = parse('FOO=safe-\$(whoami)', command_substitution: :disabled)
      expect(result).to eq("FOO" => "safe-$(whoami)")
    end

    it "does not evaluate single quoted substitutions" do
      result = parse("FOO='$(whoami)'", command_substitution: :disabled)
      expect(result).to eq("FOO" => "$(whoami)")
    end

    it "does not evaluate substitutions on later lines after a failure" do
      executed = false
      executor = RecordingExecutor.new(
        "echo second" => -> { executed = true; "second" }
      )

      expect do
        parse(
          "FIRST=$(whoami)\nSECOND=$(echo second)",
          command_substitution: :disabled
        )
      end.to raise_error(Dotenv::CommandExecutionError)

      expect(executor.call_count).to eq(0)
      expect(executed).to be(false)
    end
  end

  describe ":literal policy" do
    it "keeps the substitution text verbatim" do
      expect(parse("FOO=$(whoami)", command_substitution: :literal))
        .to eq("FOO" => "$(whoami)")
    end

    it "keeps nested substitution text verbatim" do
      expect(parse('FOO=$(a $(b $(c)))', command_substitution: :literal))
        .to eq("FOO" => "$(a $(b $(c)))")
    end

    it "keeps escaped parentheses literal and never evaluates them" do
      executor = RecordingExecutor.new

      result = parse(
        'FOO=\$(a $(b))',
        command_substitution: executor
      )

      expect(result).to eq("FOO" => "$(a $(b))")
      expect(executor.call_count).to eq(0)
    end

    it "still expands variables around a literal command" do
      content = "GREETING_USER=bob\nFOO=hi-$GREETING_USER-$(whoami)"
      expect(parse(content, command_substitution: :literal))
        .to eq("GREETING_USER" => "bob", "FOO" => "hi-bob-$(whoami)")
    end

    it "does not execute anything to produce a literal" do
      executor = RecordingExecutor.new

      parse("A=$(one)\nB=$(two)", command_substitution: :literal)

      expect(executor.call_count).to eq(0)
    end
  end

  describe "callable executor policy" do
    it "invokes the executor with the command text and uses its result" do
      executor = RecordingExecutor.new("whoami" => -> { "alice" })

      result = parse("FOO=$(whoami)", command_substitution: executor)

      expect(result).to eq("FOO" => "alice")
      expect(executor.calls).to eq(["whoami"])
      expect(executor.call_count).to eq(1)
    end

    it "never falls back to the system shell" do
      executor = RecordingExecutor.new("whoami" => -> { "alice" })
      allow(Kernel).to receive(:`).and_raise("shell must not be used")
      allow(Dotenv::CommandExecutors::Shell).to receive(:new)
        .and_raise("shell must not be used")

      result = parse("FOO=$(whoami)", command_substitution: executor)

      expect(result).to eq("FOO" => "alice")
    end

    it "passes the variable view accumulated so far in the file" do
      executor = RecordingExecutor.new(
        "echo hello" => -> { "heard #{executor.env_views.last['GREETING']}" }
      )

      result = parse("GREETING=hello\nREPLY=$(echo $GREETING)", command_substitution: executor)
      expect(executor.env_views.last).to include("GREETING" => "hello")
      expect(result["REPLY"]).to eq("heard hello")
    end

    it "expands referenced variables before calling the executor" do
      executor = RecordingExecutor.new("echo hello" => -> { "ok" })

      parse("GREETING=hello\nREPLY=$(echo $GREETING)", command_substitution: executor)

      expect(executor.calls).to eq(["echo hello"])
    end

    it "references variables in file declaration order, not later lines" do
      executor = RecordingExecutor.new(
        "echo " => -> { "got=#{executor.env_views.last['ORDER'].inspect}" }
      )

      result = parse(
        "EARLY=$(echo $ORDER)\nORDER=later",
        command_substitution: executor
      )

      expect(result["EARLY"]).to eq("got=nil")
      expect(result["ORDER"]).to eq("later")
    end

    it "resolves nested commands inner-first with the same executor" do
      executor = RecordingExecutor.new(
        "inner" => -> { "INNER" },
        "outer INNER" => -> { "OUTER" }
      )

      result = parse("FOO=$(outer $(inner))", command_substitution: executor)

      expect(result).to eq("FOO" => "OUTER")
      expect(executor.calls).to eq(["inner", "outer INNER"])
      expect(executor.call_count).to eq(2)
    end

    it "handles deeply nested and quoted commands" do
      responses = {
        "echo hello" => "h",
        'echo "h"' => "hh",
        'echo "hh"' => "hhh",
        'echo "hhh"' => "deep"
      }
      executor = RecordingExecutor.new(
        responses.transform_values { |value| -> { value } }
      )

      result = parse(
        'FOO=$(echo "$(echo "$(echo "$(echo hello)")")")',
        command_substitution: executor
      )

      expect(result["FOO"]).to eq("deep")
      expect(executor.call_count).to eq(4)
      expect(executor.calls).to eq(responses.keys)
    end

    it "does not evaluate escaped nested commands" do
      executor = RecordingExecutor.new(
        "a $(b)" => -> { "ran-outer" }
      )

      result = parse('FOO=$(a \$(b))', command_substitution: executor)

      expect(result).to eq("FOO" => "ran-outer")
      expect(executor.calls).to eq(["a $(b)"])
      expect(executor.call_count).to eq(1)
    end

    it "rejects non-string executor results explicitly" do
      executor = Object.new
      executor.define_singleton_method(:call) { |*_args| 123 }

      expect do
        parse("FOO=$(nope)", command_substitution: executor)
      end.to raise_error(Dotenv::CommandExecutionError, /must return a String/)
    end

    it "wraps a raised executor error as a command failure" do
      executor = RecordingExecutor.new.fail!("nope")

      expect do
        parse("FOO=$(nope)", command_substitution: executor)
      end.to raise_error(Dotenv::CommandExecutionError, /boom/)
    end

    it "stops after the first failed command and skips later branches" do
      later = false
      executor = RecordingExecutor.new(
        "bad" => -> { raise "boom" },
        "later" => -> { later = true; "late" }
      )

      expect do
        parse("A=$(bad)\nB=$(later)", command_substitution: executor)
      end.to raise_error(Dotenv::CommandExecutionError)

      expect(executor.calls).to eq(["bad"])
      expect(later).to be(false)
    end

    it "reports the source filename, line and key" do
      executor = RecordingExecutor.new("whoami" => -> { "alice" })

      Dotenv::Parser.call(
        "A=1\nFOO=$(whoami)",
        source: "/tmp/app.env",
        command_substitution: executor
      )

      location = executor.sources.first
      expect(location.filename).to eq("/tmp/app.env")
      expect(location.line).to eq(2)
      expect(location.key).to eq("FOO")
      expect(location.to_s).to eq("/tmp/app.env:2 in FOO")
    end
  end

  it "rejects an unknown policy before reading any commands" do
    expect do
      parse("FOO=$(whoami)", command_substitution: :bogus)
    end.to raise_error(ArgumentError, /Invalid value for command_substitution/)
  end

  describe ":shell default" do
    it "still runs commands through the shell" do
      expect(parse("FOO=$(echo hello)")).to eq("FOO" => "hello")
    end

    it "raises when the shell command fails" do
      expect do
        parse("FOO=$(false)")
      end.to raise_error(Dotenv::CommandExecutionError, /exit status/)
    end
  end
end
