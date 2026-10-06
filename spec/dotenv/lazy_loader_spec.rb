require "spec_helper"
require "fileutils"
require "tempfile"

describe Dotenv::LazyLoader do
  describe "fixture samples" do
    it "resolves a forward reference from a later file" do
      files = [
        fixture_path("lazy_forward_a.env").to_s,
        fixture_path("lazy_forward_b.env").to_s
      ]

      resolved = described_class.new(files).resolve.resolved

      expect(resolved["LAZY_A"]).to eq("resolved")
      expect(resolved["LAZY_COMMAND"]).to eq("from-b")
    end

    it "reports a cycle across two files" do
      files = [
        fixture_path("lazy_cycle_a.env").to_s,
        fixture_path("lazy_cycle_b.env").to_s
      ]

      expect { described_class.new(files).resolve }.to raise_error(
        Dotenv::CircularReferenceError,
        "Circular variable reference detected: CYCLE_A -> CYCLE_B -> CYCLE_A"
      )
    end
  end

  subject(:loader) { described_class.new([first_file.path, second_file.path]) }

  let(:first_file) { Tempfile.new(["first", ".env"]) }
  let(:second_file) { Tempfile.new(["second", ".env"]) }

  after do
    first_file.close!
    second_file.close!
  end

  def write(file, contents)
    file.write(contents)
    file.flush
  end

  describe "#read" do
    it "reads every file before resolving references" do
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=ready")

      expect(loader.read.sources.map(&:filename)).to eq([first_file.path, second_file.path])
      expect(loader.sources.map(&:content)).to eq(["FORWARD=$LATER", "LATER=ready"])
    end
  end

  describe "#parse" do
    it "collects later definitions before parsing earlier references" do
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=ready")

      loader.read.parse

      expect(loader.definitions["FORWARD"].raw_value).to eq("$LATER")
      expect(loader.definitions["LATER"].raw_value).to eq("ready")
    end

    it "keeps later overrides and the definitions they replaced" do
      write(first_file, "VALUE=first")
      write(second_file, "VALUE=second")

      loader.parse

      expect(loader.definitions["VALUE"].raw_value).to eq("second")
      expect(loader.definitions.overrides["VALUE"].map(&:raw_value)).to eq(["first", "second"])
    end
  end

  describe "#resolve" do
    it "resolves forward references using the final definition" do
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=ready")

      expect(loader.resolve.resolved).to include(
        "FORWARD" => "ready",
        "LATER" => "ready"
      )
    end

    it "keeps an empty process value distinct from a missing value" do
      ENV["EXISTING"] = ""
      write(first_file, "EXISTING=file\nMISSING=$EXISTING")

      resolved = loader.resolve.resolved

      expect(resolved["EXISTING"]).to eq("")
      expect(resolved["MISSING"]).to eq("")
    end

    it "does not resolve references to undefined variables" do
      write(first_file, "MISSING=$UNDEFINED")

      expect(loader.resolve.resolved["MISSING"]).to eq("")
    end

    it "preserves escaped newlines by default" do
      write(first_file, 'FOO="bar\\nbaz"')

      expect(loader.resolve.resolved["FOO"]).to eq("bar\\nbaz")
    end

    it "expands newlines when a final file definition selects legacy mode" do
      ENV["DOTENV_LINEBREAK_MODE"] = "strict"
      write(first_file, "DOTENV_LINEBREAK_MODE=legacy")
      write(second_file, 'FOO="bar\\nbaz"')

      expect(loader.resolve.resolved["FOO"]).to eq("bar\nbaz")
    end

    it "reports the complete chain for a self reference" do
      write(first_file, "SELF=$SELF")

      expect { loader.resolve }.to raise_error(
        Dotenv::CircularReferenceError,
        "Circular variable reference detected: SELF -> SELF"
      )
    end

    it "uses the process value for a self reference inside its own command" do
      ENV["SELF_COMMAND"] = "process"
      write(first_file, "SELF_COMMAND=$(echo $SELF_COMMAND)")

      expect(loader.resolve.resolved["SELF_COMMAND"]).to eq("process")
    end

    it "reports a cycle between variables used inside commands" do
      write(first_file, "CYCLE_A=$(echo $CYCLE_B)")
      write(second_file, "CYCLE_B=$(echo $CYCLE_A)")

      expect { loader.resolve }.to raise_error(
        Dotenv::CircularReferenceError,
        "Circular variable reference detected: CYCLE_A -> CYCLE_B -> CYCLE_A"
      )
    end

    it "reports the complete chain across two files" do
      write(first_file, "CYCLE_A=$CYCLE_B")
      write(second_file, "CYCLE_B=$CYCLE_A")

      expect { loader.resolve }.to raise_error(
        Dotenv::CircularReferenceError,
        "Circular variable reference detected: CYCLE_A -> CYCLE_B -> CYCLE_A"
      )
    end

    it "does not execute command substitutions for overridden definitions" do
      marker = File.join(Dir.mktmpdir, "marker")
      write(first_file, "VALUE=$(touch #{marker})")
      write(second_file, "VALUE=second")

      loader.resolve

      expect(File.exist?(marker)).to be(false)
      expect(loader.resolved["VALUE"]).to eq("second")
    ensure
      FileUtils.rm_rf(File.dirname(marker))
    end

    it "does not execute commands when a cycle is detected" do
      marker = File.join(Dir.mktmpdir, "marker")
      write(first_file, "CYCLE_A=$CYCLE_B\nVALUE=$(touch #{marker})")
      write(second_file, "CYCLE_B=$CYCLE_A")

      expect { loader.resolve }.to raise_error(Dotenv::CircularReferenceError)
      expect(File.exist?(marker)).to be(false)
    ensure
      FileUtils.rm_rf(File.dirname(marker))
    end
  end

  describe "#apply" do
    it "instruments source loads before applying resolved values" do
      events = []
      instrumenter = proc do |name, payload = {}, &block|
        events << [name, payload]
        block&.call(payload || {})
      end
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=ready")

      described_class.new(
        [first_file.path, second_file.path],
        instrumenter: instrumenter
      ).apply

      expect(events.map(&:first)).to eq(%i[update load load])
      expect(events[1][1][:env]).to have_attributes(filename: first_file.path)
      expect(events[2][1][:env]).to have_attributes(filename: second_file.path)
    end

    it "applies resolved values to ENV as the final stage" do
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=ready")

      expect(ENV).not_to have_key("FORWARD")
      loader.apply

      expect(ENV["FORWARD"]).to eq("ready")
      expect(ENV["LATER"]).to eq("ready")
    end

    it "does not overwrite existing process values by default" do
      ENV["FORWARD"] = "process"
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=file")

      loader.apply

      expect(ENV["FORWARD"]).to eq("process")
    end

    it "overwrites process values when requested" do
      ENV["FORWARD"] = "process"
      write(first_file, "FORWARD=$LATER")
      write(second_file, "LATER=file")

      described_class.new([first_file.path, second_file.path], overwrite: true).apply

      expect(ENV["FORWARD"]).to eq("file")
    end
  end
end
