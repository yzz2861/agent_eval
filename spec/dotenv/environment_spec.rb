require "spec_helper"

describe Dotenv::Environment do
  subject { env("OPTION_A=1\nOPTION_B=2") }

  describe "initialize" do
    it "reads the file" do
      expect(subject["OPTION_A"]).to eq("1")
      expect(subject["OPTION_B"]).to eq("2")
    end

    it "fails if file does not exist" do
      expect do
        Dotenv::Environment.new(".does_not_exists")
      end.to raise_error(Errno::ENOENT)
    end
  end

  require "tempfile"
  def env(text, ...)
    file = Tempfile.new("dotenv")
    file.write text
    file.close
    env = Dotenv::Environment.new(file.path, ...)
    file.unlink
    env
  end

  describe "command_substitution" do
    it "passes the source filename and line to a caller executor" do
      received = []
      executor = lambda do |command, _view, source|
        received << [command, source]
        "ok"
      end

      result = env("A=1\nB=$(whoami)", command_substitution: executor)

      expect(result["B"]).to eq("ok")
      command, source = received.first
      expect(command).to eq("whoami")
      expect(source.line).to eq(2)
      expect(source.key).to eq("B")
      expect(source.filename).to include("dotenv")
    end

    it "raises without loading when commands are disabled" do
      expect do
        env("A=1\nB=$(whoami)", command_substitution: :disabled)
      end.to raise_error(Dotenv::CommandExecutionError, /disabled/)
    end
  end
end
