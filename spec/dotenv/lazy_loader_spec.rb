require "spec_helper"
require "tempfile"

describe "Dotenv lazy resolution" do
  def env_file(name, contents)
    file = Tempfile.new([name, ".env"])
    file.write(contents)
    file.close
    file.path
  end

  def marker_file
    file = Tempfile.new(["dotenv-command", ".marker"])
    path = file.path
    file.close
    File.delete(path)
    path
  end

  describe "stages" do
    it "reads files without parsing them" do
      file = env_file("plain", "FOO=$(invalid shell\nBAR=$MISSING\n")

      sources = Dotenv.read(file)

      expect(sources).to contain_exactly(an_object_having_attributes(
        filename: File.expand_path(file),
        content: "FOO=$(invalid shell\nBAR=$MISSING\n"
      ))
    end

    it "collects definitions without executing commands" do
      marker = marker_file
      file = env_file("commands", "FOO=$(touch #{marker})\n")

      definitions = Dotenv.definitions(file)

      expect(File).not_to exist(marker)
      expect(definitions.definitions["FOO"].value).to eq("$(touch #{marker})")
      expect(definitions.definitions["FOO"].filename).to eq(File.expand_path(file))
    end

    it "resolves without applying values to ENV" do
      file = env_file("forward", "FOO=$BAR\nBAR=resolved\n")

      values = Dotenv.resolve(file)

      expect(values).to eq("FOO" => "resolved", "BAR" => "resolved")
      expect(ENV["FOO"]).to be_nil
      expect(ENV["BAR"]).to be_nil
    end

    it "applies values as an explicit final stage" do
      file = env_file("apply", "FOO=$BAR\nBAR=applied\n")
      loader = Dotenv.lazy_loader(file)

      expect(loader.read).to be_an(Array)
      expect(loader.parse).to be_a(Dotenv::DefinitionSet)
      expect(loader.resolve).to eq("FOO" => "applied", "BAR" => "applied")
      expect(ENV["FOO"]).to be_nil

      expect(loader.apply).to eq("FOO" => "applied", "BAR" => "applied")
      expect(ENV["FOO"]).to eq("applied")
    end

    it "applies resolved values with load" do
      file = env_file("load", "FOO=$BAR\nBAR=resolved\n")

      result = Dotenv.load(file, lazy: true)

      expect(result).to eq("FOO" => "resolved", "BAR" => "resolved")
      expect(ENV["FOO"]).to eq("resolved")
      expect(ENV["BAR"]).to eq("resolved")
    end
  end

  describe "forward references" do
    it "resolves the provided two-file sample" do
      values = Dotenv.resolve(
        fixture_path("lazy_forward_high.env"),
        fixture_path("lazy_forward_low.env")
      )

      expect(values).to eq(
        "SERVICE" => "https://example.com/api",
        "HOST" => "example.com"
      )
    end

    it "uses the final definition across files" do
      first = env_file("first", "URL=https://$HOST/api\n")
      second = env_file("second", "HOST=example.com\n")

      expect(Dotenv.resolve(first, second)).to eq(
        "URL" => "https://example.com/api",
        "HOST" => "example.com"
      )
    end

    it "uses the highest-priority file when overwriting" do
      high = env_file("high", "HOST=example.com\nURL=https://$HOST/api\n")
      low = env_file("low", "HOST=ignored\n")

      expect(Dotenv.resolve(high, low, overwrite: true)).to eq(
        "HOST" => "example.com",
        "URL" => "https://example.com/api"
      )
    end
  end

  describe "existing ENV" do
    it "keeps an existing empty value distinct from a missing variable" do
      ENV["EMPTY"] = ""
      file = env_file("empty", "EMPTY=file\nPRESENT=$EMPTY\nMISSING=$UNDEFINED\n")

      values = Dotenv.resolve(file)

      expect(values["EMPTY"]).to eq("")
      expect(values["PRESENT"]).to eq("")
      expect(values["MISSING"]).to eq("")
      expect(ENV["EMPTY"]).to eq("")
    end

    it "overwrites empty existing values when requested" do
      ENV["EMPTY"] = ""
      file = env_file("empty-overwrite", "EMPTY=file\n")

      expect(Dotenv.resolve(file, overwrite: true)).to eq("EMPTY" => "file")
    end

    it "warns but keeps existing values when overwrite is :warn" do
      ENV["EXISTING"] = ""
      file = env_file("warn", "EXISTING=file\n")

      result = nil
      output = capture_output { result = Dotenv.load(file, overwrite: :warn, lazy: true) }

      expect(output).to eq(%(Warning: dotenv not overwriting ENV["EXISTING"]\n))
      expect(result).to eq({})
      expect(ENV["EXISTING"]).to eq("")
    end
  end

  describe "circular references" do
    it "reports the provided two-file cycle sample" do
      expect do
        Dotenv.resolve(
          fixture_path("lazy_cycle_a.env"),
          fixture_path("lazy_cycle_b.env")
        )
      end.to raise_error(
        Dotenv::CircularDependencyError,
        "Circular variable reference: A -> B -> A"
      )
    end

    it "reports a two-file cycle with the complete chain" do
      first = env_file("cycle-first", "A=$B\n")
      second = env_file("cycle-second", "B=$A\n")

      expect { Dotenv.resolve(first, second) }.to raise_error(
        Dotenv::CircularDependencyError,
        "Circular variable reference: A -> B -> A"
      )
    end

    it "reports a self-reference" do
      file = env_file("self-cycle", "A=$A\n")

      expect { Dotenv.resolve(file) }.to raise_error(
        Dotenv::CircularDependencyError,
        "Circular variable reference: A -> A"
      )
    end
  end

  describe "overridden definitions" do
    it "keeps earlier definitions from the same file inspectable" do
      file = env_file("same-file", "FOO=first\nFOO=second\n")

      definitions = Dotenv.definitions(file)

      expect(definitions.definitions["FOO"].value).to eq("second")
      expect(definitions.overridden("FOO").map(&:value)).to eq(["first"])
      expect(Dotenv.resolve(file)).to eq("FOO" => "second")
    end

    it "does not execute an earlier command definition replaced later in one file" do
      marker = marker_file
      file = env_file("same-file-command", "FOO=$(touch #{marker}; echo old)\nFOO=new\n")

      expect(Dotenv.resolve(file)).to eq("FOO" => "new")
      expect(File).not_to exist(marker)
    end

    it "does not execute commands in lower-priority files" do
      marker = marker_file
      high = env_file("high", "FOO=high\n")
      low = env_file("low", "FOO=$(touch #{marker}; echo low)\n")

      values = Dotenv.resolve(high, low, overwrite: true)
      overridden = Dotenv.definitions(high, low, overwrite: true).overridden("FOO")

      expect(values).to eq("FOO" => "high")
      expect(overridden.map(&:value)).to eq(["$(touch #{marker}; echo low)"])
      expect(File).not_to exist(marker)
    end

    it "does not execute commands hidden by existing ENV" do
      marker = marker_file
      ENV["FOO"] = "existing"
      file = env_file("existing", "FOO=$(touch #{marker}; echo file)\n")

      values = Dotenv.resolve(file)

      expect(values).to eq("FOO" => "existing")
      expect(File).not_to exist(marker)
    end
  end

  describe "legacy behavior" do
    it "remains sequential unless lazy is enabled" do
      first = env_file("legacy-first", "FOO=$LATER\n")
      second = env_file("legacy-second", "LATER=later\n")

      expect(Dotenv.resolve(first, second)).to eq("FOO" => "later", "LATER" => "later")
      expect(Dotenv.parse(first, second)).to eq("FOO" => "", "LATER" => "later")
    end
  end

  describe "substitution compatibility" do
    {
      "escaped spaces" => "FOO=bar\\ bar",
      "escaped variable" => 'FOO="foo\$BAR"',
      "escaped braces" => 'FOO="foo\${BAR}"',
      "escaped command" => 'echo=escaped-\$(echo hello)',
      "command variables" => "FOO=bar\nBAR=$(echo $FOO)"
    }.each do |name, contents|
      it "matches immediate parsing for #{name}" do
        file = env_file("compat", contents)

        expect(Dotenv.resolve(file)).to eq(Dotenv::Parser.call(contents))
      end
    end
  end
end
