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
        .with(anything, overwrite: false, command_policy: an_instance_of(Dotenv::CommandPolicy), staged: an_instance_of(Hash))
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
        .with(anything, overwrite: false, command_policy: an_instance_of(Dotenv::CommandPolicy), staged: an_instance_of(Hash))
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
        .with(anything, overwrite: true, command_policy: an_instance_of(Dotenv::CommandPolicy), staged: an_instance_of(Hash))
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
        .with(anything, overwrite: true, command_policy: an_instance_of(Dotenv::CommandPolicy), staged: an_instance_of(Hash))
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
        .with(anything, overwrite: false, command_policy: an_instance_of(Dotenv::CommandPolicy))
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

  describe "command policies" do
    require "tempfile"

    def write_env(contents)
      file = Tempfile.new(["dotenv", ".env"])
      file.write(contents)
      file.close
      file.path
    end

    # Local executor that records calls instead of touching a system shell.
    def counting_executor(fail_on: nil)
      calls = []
      executor = lambda do |command, view, location|
        calls << [command, view, location]
        if fail_on && command.include?(fail_on)
          Dotenv::CommandResult.failure("refused: #{command}")
        else
          Dotenv::CommandResult.success("out:#{command}")
        end
      end
      [executor, calls]
    end

    it "uses the caller executor for load and never the system shell" do
      executor, calls = counting_executor
      path = write_env("GREETING=$(hello world)\nNAME=$(whoami)")

      result = Dotenv.load(path, command_policy: executor)

      expect(calls.map(&:first)).to eq(["hello world", "whoami"])
      expect(ENV["GREETING"]).to eq("out:hello world")
      expect(ENV["NAME"]).to eq("out:whoami")
      expect(result).to eq("GREETING" => "out:hello world", "NAME" => "out:whoami")
    end

    it "passes the file location for every command" do
      executor, calls = counting_executor
      path = write_env("A=$(a)\n# comment\nB=$(b)")

      Dotenv.load(path, command_policy: executor)

      expect(calls.map { |_c, _v, l| [l.filename, l.line] }).to eq([[path, 1], [path, 3]])
    end

    it "does not write any ENV keys when a command is disabled" do
      path = write_env("FIRST=one\nSECOND=$(echo nope)\nTHIRD=three")

      expect { Dotenv.load(path, command_policy: :disabled) }
        .to raise_error(Dotenv::CommandNotAllowedError)

      expect(ENV["FIRST"]).to be_nil
      expect(ENV["SECOND"]).to be_nil
      expect(ENV["THIRD"]).to be_nil
    end

    it "does not write the first half of the file when a later command fails" do
      executor, calls = counting_executor(fail_on: "nope")
      path = write_env("FIRST=$(ok)\nSECOND=$(nope)\nTHIRD=three")

      expect { Dotenv.load(path, command_policy: executor) }
        .to raise_error(Dotenv::CommandExecutionError, /refused/)

      expect(ENV["FIRST"]).to be_nil
      expect(ENV["SECOND"]).to be_nil
      expect(ENV["THIRD"]).to be_nil
      expect(calls.map(&:first)).to eq(["ok", "nope"])
    end

    it "does not write earlier files when a later file fails" do
      executor, _calls = counting_executor(fail_on: "nope")
      good = write_env("EARLY=yes")
      bad = write_env("LATE=$(nope)")

      expect { Dotenv.load(good, bad, command_policy: executor) }
        .to raise_error(Dotenv::CommandExecutionError)

      expect(ENV["EARLY"]).to be_nil
      expect(ENV["LATE"]).to be_nil
    end

    it "keeps commands literal and executes nothing" do
      executor, calls = counting_executor
      path = write_env('X=pre-$(echo hi)-post')

      Dotenv.load(path, command_policy: :literal)

      expect(ENV["X"]).to eq("pre-$(echo hi)-post")
      expect(calls).to be_empty
    end

    it "applies the policy independently per load" do
      literal = write_env("A=$(x)")
      executor, calls = counting_executor
      disabled = write_env("B=$(y)")

      Dotenv.load(literal, command_policy: :literal)
      expect { Dotenv.load(disabled, command_policy: :disabled) }
        .to raise_error(Dotenv::CommandNotAllowedError)
      Dotenv.load(write_env("C=$(z)"), command_policy: executor)

      expect(ENV["A"]).to eq("$(x)")
      expect(ENV["B"]).to be_nil
      expect(ENV["C"]).to eq("out:z")
      expect(calls.map(&:first)).to eq(["z"])
    end

    it "exposes variables from the same load to the executor view" do
      executor, calls = counting_executor
      path = write_env("NAME=world\nGREETING=$(hello $NAME)")

      Dotenv.load(path, command_policy: executor)

      expect(calls.first[1]["NAME"]).to eq("world")
    end

    it "lets the first listed file win with overwrite and still evaluates later files" do
      executor, calls = counting_executor
      first = write_env("KEY=$(low)")
      second = write_env("KEY=$(high)")

      result = Dotenv.overwrite(first, second, command_policy: executor)

      expect(ENV["KEY"]).to eq("out:low")
      expect(result).to eq("KEY" => "out:low")
      expect(calls.map(&:first)).to eq(["high", "low"])
    end

    it "keeps the first file value when not overwriting across files" do
      executor, _calls = counting_executor
      first = write_env("KEY=first")
      second = write_env("KEY=$(ignored)")

      result = Dotenv.load(first, second, command_policy: executor)

      expect(ENV["KEY"]).to eq("first")
      expect(result).to eq("KEY" => "first")
    end

    it "reuses variables staged from an earlier file in a later command view" do
      executor, calls = counting_executor
      first = write_env("SHARED=from-first")
      second = write_env("DERIVED=$(build $SHARED)")

      Dotenv.load(first, second, command_policy: executor)

      expect(calls.first[0]).to eq("build $SHARED")
      expect(calls.first[1]["SHARED"]).to eq("from-first")
      expect(ENV["DERIVED"]).to eq("out:build from-first")
    end

    it "does not execute branches in files that are skipped" do
      executor, calls = counting_executor

      Dotenv.load(".doesnotexist", command_policy: executor, ignore: true)

      expect(calls).to be_empty
    end

    it "honors the policy through Dotenv.parse without touching ENV" do
      executor, calls = counting_executor
      path = write_env("A=$(a)")

      parsed = Dotenv.parse(path, command_policy: executor)

      expect(parsed).to eq("A" => "out:a")
      expect(ENV["A"]).to be_nil
      expect(calls.map(&:first)).to eq(["a"])

      expect { Dotenv.parse(write_env("B=$(b)"), command_policy: :disabled) }
        .to raise_error(Dotenv::CommandNotAllowedError)
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

  def expand(path)
    File.expand_path path
  end
end
