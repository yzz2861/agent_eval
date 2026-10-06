require "spec_helper"

describe Dotenv do
  before do
    Dir.chdir(File.expand_path("../fixtures", __FILE__))
  end

  shared_examples "load" do
    context "with no args" do
      let(:env_files) { [] }

      it "defaults to .env" do
        expect(Dotenv::Environment).to receive(:new).with(expand(".env"), anything).and_call_original
        subject
      end
    end

    context "with a tilde path" do
      let(:env_files) { ["~/.env"] }

      it "expands the path" do
        expected = expand("~/.env")
        allow(File).to receive(:exist?) { |arg| arg == expected }
        expect(Dotenv::Environment).to receive(:new).with(expected, anything)
          .and_return(Dotenv::Environment.new(".env"))
        subject
      end
    end

    context "with multiple files" do
      let(:env_files) { [".env", fixture_path("plain.env")] }

      let(:expected) do
        {"OPTION_A" => "1",
         "OPTION_B" => "2",
         "OPTION_C" => "3",
         "OPTION_D" => "4",
         "OPTION_E" => "5",
         "PLAIN" => "true",
         "DOTENV" => "true"}
      end

      it "loads all files" do
        subject
        expected.each do |key, value|
          expect(ENV[key]).to eq(value)
        end
      end

      it "returns hash of loaded variables" do
        expect(subject).to eq(expected)
      end

      it "does not return unchanged variables" do
        ENV["OPTION_A"] = "1"
        expect(subject).not_to have_key("OPTION_A")
      end
    end
  end

  shared_examples "overwrite" do
    it_behaves_like "load"

    context "with multiple files" do
      let(:env_files) { [fixture_path("important.env"), fixture_path("plain.env")] }

      let(:expected) do
        {
          "OPTION_A" => "abc",
          "OPTION_B" => "2",
          "OPTION_C" => "3",
          "OPTION_D" => "4",
          "OPTION_E" => "5",
          "PLAIN" => "false"
        }
      end

      it "respects the file importance order" do
        subject
        expected.each do |key, value|
          expect(ENV[key]).to eq(value)
        end
      end
    end
  end

  describe "load" do
    let(:env_files) { [] }
    let(:options) { {} }
    subject { Dotenv.load(*env_files, **options) }

    it_behaves_like "load"

    it "initializes the Environment with overwrite: false" do
      expect(Dotenv::Environment).to receive(:new)
        .with(anything, overwrite: false, command_substitution: :shell)
        .and_call_original
      subject
    end

    it "warns about not overwriting when requested" do
      options[:overwrite] = :warn
      ENV["DOTENV"] = "false"

      expect(capture_output { subject }).to eq("Warning: dotenv not overwriting ENV[\"DOTENV\"]\n")

      expect(ENV["DOTENV"]).to eq("false")
    end

    context "when the file does not exist" do
      let(:env_files) { [".env_does_not_exist"] }

      it "fails silently" do
        expect { subject }.not_to raise_error
      end

      it "does not change ENV" do
        expect { subject }.not_to change { ENV.inspect }
      end
    end

    context "when the file is a directory" do
      let(:env_files) { [] }

      around do |example|
        Dir.mktmpdir do |dir|
          env_files.push dir
          example.run
        end
      end

      it "fails silently with ignore: true (default)" do
        expect { subject }.not_to raise_error
      end

      it "raises error with ignore: false" do
        options[:ignore] = false
        expect { subject }.to raise_error(/Is a directory/)
      end
    end
  end

  describe "load!" do
    let(:env_files) { [] }
    subject { Dotenv.load!(*env_files) }

    it_behaves_like "load"

    it "initializes Environment with overwrite: false" do
      expect(Dotenv::Environment).to receive(:new)
        .with(anything, overwrite: false, command_substitution: :shell)
        .and_call_original
      subject
    end

    context "when one file exists and one does not" do
      let(:env_files) { [".env", ".env_does_not_exist"] }

      it "raises an Errno::ENOENT error" do
        expect { subject }.to raise_error(Errno::ENOENT)
      end
    end
  end

  describe "overwrite" do
    let(:env_files) { [fixture_path("plain.env")] }
    subject { Dotenv.overwrite(*env_files) }
    it_behaves_like "load"
    it_behaves_like "overwrite"

    it "initializes the Environment overwrite: true" do
      expect(Dotenv::Environment).to receive(:new)
        .with(anything, overwrite: true, command_substitution: :shell)
        .and_call_original
      subject
    end

    context "when loading a file containing already set variables" do
      let(:env_files) { [fixture_path("plain.env")] }

      it "overwrites any existing ENV variables" do
        ENV["OPTION_A"] = "predefined"

        subject

        expect(ENV["OPTION_A"]).to eq("1")
      end
    end

    context "when the file does not exist" do
      let(:env_files) { [".env_does_not_exist"] }

      it "fails silently" do
        expect { subject }.not_to raise_error
      end

      it "does not change ENV" do
        expect { subject }.not_to change { ENV.inspect }
      end
    end
  end

  describe "overwrite!" do
    let(:env_files) { [fixture_path("plain.env")] }
    subject { Dotenv.overwrite!(*env_files) }
    it_behaves_like "load"
    it_behaves_like "overwrite"

    it "initializes the Environment with overwrite: true" do
      expect(Dotenv::Environment).to receive(:new)
        .with(anything, overwrite: true, command_substitution: :shell)
        .and_call_original
      subject
    end

    context "when loading a file containing already set variables" do
      let(:env_files) { [fixture_path("plain.env")] }

      it "overwrites any existing ENV variables" do
        ENV["OPTION_A"] = "predefined"
        subject
        expect(ENV["OPTION_A"]).to eq("1")
      end
    end

    context "when one file exists and one does not" do
      let(:env_files) { [".env", ".env_does_not_exist"] }

      it "raises an Errno::ENOENT error" do
        expect { subject }.to raise_error(Errno::ENOENT)
      end
    end
  end

  describe "with an instrumenter" do
    let(:instrumenter) { double("instrumenter", instrument: {}) }
    before { Dotenv.instrumenter = instrumenter }
    after { Dotenv.instrumenter = nil }

    describe "load" do
      it "instruments if the file exists" do
        expect(instrumenter).to receive(:instrument) do |name, payload|
          expect(name).to eq("load.dotenv")
          expect(payload[:env]).to be_instance_of(Dotenv::Environment)
          {}
        end
        Dotenv.load
      end

      it "does not instrument if file does not exist" do
        expect(instrumenter).to receive(:instrument).never
        Dotenv.load ".doesnotexist"
      end
    end
  end

  describe "require keys" do
    let(:env_files) { [".env", fixture_path("bom.env")] }

    before { Dotenv.load(*env_files) }

    it "raises exception with not defined mandatory ENV keys" do
      expect { Dotenv.require_keys("BOM", "TEST") }.to raise_error(
        Dotenv::MissingKeys,
        'Missing required configuration key: ["TEST"]'
      )
    end

    it "raises exception when missing multiple mandator keys" do
      expect { Dotenv.require_keys("TEST1", "TEST2") }.to raise_error(
        Dotenv::MissingKeys,
        'Missing required configuration keys: ["TEST1", "TEST2"]'
      )
    end
  end

  describe "parse" do
    let(:env_files) { [] }
    subject { Dotenv.parse(*env_files) }

    context "with no args" do
      let(:env_files) { [] }

      it "defaults to .env" do
        expect(Dotenv::Environment).to receive(:new).with(expand(".env"),
          anything)
        subject
      end
    end

    context "with a tilde path" do
      let(:env_files) { ["~/.env"] }

      it "expands the path" do
        expected = expand("~/.env")
        allow(File).to receive(:exist?) { |arg| arg == expected }
        expect(Dotenv::Environment).to receive(:new).with(expected, anything)
        subject
      end
    end

    context "with multiple files" do
      let(:env_files) { [".env", fixture_path("plain.env")] }

      let(:expected) do
        {"OPTION_A" => "1",
         "OPTION_B" => "2",
         "OPTION_C" => "3",
         "OPTION_D" => "4",
         "OPTION_E" => "5",
         "PLAIN" => "true",
         "DOTENV" => "true"}
      end

      it "does not modify ENV" do
        subject
        expected.each do |key, _value|
          expect(ENV[key]).to be_nil
        end
      end

      it "returns hash of parsed key/value pairs" do
        expect(subject).to eq(expected)
      end
    end

    it "initializes the Environment with overwrite: false" do
      expect(Dotenv::Environment).to receive(:new)
        .with(anything, overwrite: false, command_substitution: :shell)
      subject
    end

    context "when the file does not exist" do
      let(:env_files) { [".env_does_not_exist"] }

      it "fails silently" do
        expect { subject }.not_to raise_error
        expect(subject).to eq({})
      end
    end
  end

  describe "Unicode" do
    subject { fixture_path("bom.env") }

    it "loads a file with a Unicode BOM" do
      expect(Dotenv.load(subject)).to eql("BOM" => "UTF-8")
    end

    it "fixture file has UTF-8 BOM" do
      contents = File.binread(subject).force_encoding("UTF-8")
      expect(contents).to start_with("\xEF\xBB\xBF".force_encoding("UTF-8"))
    end
  end

  describe "restore" do
    it "restores previously saved snapshot" do
      ENV["MODIFIED"] = "true"
      Dotenv.restore # save was already called in setup
      expect(ENV["MODIFIED"]).to be_nil
    end

    it "raises an error in threads" do
      ENV["MODIFIED"] = "true"
      Thread.new do
        expect { Dotenv.restore }.to raise_error(ThreadError, /not thread safe/)
      end.join
      expect(ENV["MODIFIED"]).to eq("true")
    end

    it "is a noop if nil state provided" do
      expect { Dotenv.restore(nil) }.not_to raise_error
    end

    it "is a noop if no previously saved state" do
      # Clear state saved in setup
      expect(Dotenv.instance_variable_get(:@diff)).to be_instance_of(Dotenv::Diff)
      Dotenv.instance_variable_set(:@diff, nil)
      expect { Dotenv.restore }.not_to raise_error
    end

    it "can save and restore stubbed ENV" do
      stub_const("ENV", ENV.to_h.merge("STUBBED" => "1"))
      Dotenv.save
      ENV["MODIFIED"] = "1"
      Dotenv.restore
      expect(ENV["STUBBED"]).to eq("1")
      expect(ENV["MODIFED"]).to be(nil)
    end
  end

  describe "modify" do
    it "sets values for the block" do
      ENV["FOO"] = "initial"

      Dotenv.modify(FOO: "during", BAR: "baz") do
        expect(ENV["FOO"]).to eq("during")
        expect(ENV["BAR"]).to eq("baz")
      end

      expect(ENV["FOO"]).to eq("initial")
      expect(ENV).not_to have_key("BAR")
    end
  end

  describe "update" do
    it "sets new variables" do
      Dotenv.update({"OPTION_A" => "1"})
      expect(ENV["OPTION_A"]).to eq("1")
    end

    it "does not overwrite defined variables" do
      ENV["OPTION_A"] = "original"
      Dotenv.update({"OPTION_A" => "updated"})
      expect(ENV["OPTION_A"]).to eq("original")
    end

    context "with overwrite: true" do
      it "sets new variables" do
        Dotenv.update({"OPTION_A" => "1"}, overwrite: true)
        expect(ENV["OPTION_A"]).to eq("1")
      end

      it "overwrites defined variables" do
        ENV["OPTION_A"] = "original"
        Dotenv.update({"OPTION_A" => "updated"}, overwrite: true)
        expect(ENV["OPTION_A"]).to eq("updated")
      end
    end
  end

  describe "command substitution policy" do
    require "tempfile"

    def write_env(contents)
      file = Tempfile.new(["dotenv-policy", ".env"])
      file.write(contents)
      file.close
      file.path
    end

    class CountingExecutor
      attr_reader :calls

      def initialize(responses = {})
        @responses = responses
        @calls = []
      end

      def call_count
        @calls.size
      end

      def call(command, _env, _source)
        @calls << command
        raise "unexpected command: #{command}" unless @responses.key?(command)
        @responses.fetch(command)
      end
    end

    it "loads command output through the caller provided executor" do
      executor = CountingExecutor.new("whoami" => "alice")
      file = write_env("FOO=$(whoami)")

      result = Dotenv.load(file, command_substitution: executor)

      expect(result).to eq("FOO" => "alice")
      expect(ENV["FOO"]).to eq("alice")
      expect(executor.call_count).to eq(1)
    ensure
      File.unlink(file) if file
    end

    it "does not write the first half of a file when a later command fails" do
      failing = Object.new
      def failing.call(*) = raise("nope")
      file = write_env("FIRST=one\nSECOND=$(bad-command)")

      expect do
        Dotenv.load(file, command_substitution: failing)
      end.to raise_error(Dotenv::CommandExecutionError, /nope/)

      expect(ENV).not_to have_key("FIRST")
      expect(ENV).not_to have_key("SECOND")
    ensure
      File.unlink(file) if file
    end

    it "rolls back earlier files when a command in a later file fails" do
      good = write_env("EARLY=yes")
      bad = write_env("LATE=$(nope)")
      executor = CountingExecutor.new

      expect do
        Dotenv.load(good, bad, command_substitution: executor)
      end.to raise_error(Dotenv::CommandExecutionError)

      expect(ENV).not_to have_key("EARLY")
      expect(ENV).not_to have_key("LATE")
      expect(executor.call_count).to eq(1)
    ensure
      File.unlink(good) if good
      File.unlink(bad) if bad
    end

    it "restores pre-existing values on rollback" do
      ENV["EARLY"] = "original"
      good = write_env("EARLY=changed")
      bad = write_env("LATE=$(nope)")
      executor = CountingExecutor.new

      expect do
        Dotenv.load(good, bad, command_substitution: executor)
      end.to raise_error(Dotenv::CommandExecutionError)

      expect(ENV["EARLY"]).to eq("original")
    ensure
      ENV.delete("EARLY")
      File.unlink(good) if good
      File.unlink(bad) if bad
    end

    it "keeps disabled and literal loads free of any executor behavior" do
      executor = CountingExecutor.new
      disabled = write_env("A=$(one)\nB=\$(two)")
      literal = write_env('C=$(three)')

      expect do
        Dotenv.load(disabled, command_substitution: :disabled)
      end.to raise_error(Dotenv::CommandExecutionError)
      expect(executor.call_count).to eq(0)
      expect(ENV).not_to have_key("A")

      expect(Dotenv.load(literal, command_substitution: :literal))
        .to eq("C" => "$(three)")
      expect(ENV["C"]).to eq("$(three)")
      expect(executor.call_count).to eq(0)
    ensure
      File.unlink(disabled) if disabled
      File.unlink(literal) if literal
    end
  end

  def expand(path)
    File.expand_path path
  end
end
