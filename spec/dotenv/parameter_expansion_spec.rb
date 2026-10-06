require "spec_helper"
require "tmpdir"

describe Dotenv::Parser, "parameter expansion" do
  def parse(content, view = {})
    Dotenv::Parser.call(content, env: view.dup)
  end

  ["unset", "empty", "normal"].each_with_index do |state, _index|
    view = case state
           when "unset" then {}
           when "empty" then {"HOST" => ""}
           else {"HOST" => "example.com"}
           end

    describe "with a #{state} parameter" do
      let(:view) { view }

      it "expands ${HOST:-fallback} like shell" do
        expected = case state
                   when "unset", "empty" then "fallback"
                   else "example.com"
                   end
        expect(parse("URL=${HOST:-fallback}", view)).to eql("URL" => expected)
      end

      it "expands ${HOST-fallback} only when unset" do
        expected = case state
                   when "unset" then "fallback"
                   when "empty" then ""
                   else "example.com"
                   end
        expect(parse("URL=${HOST-fallback}", view)).to eql("URL" => expected)
      end

      it "expands ${HOST:+alt} only when set and non-empty" do
        expected = state == "normal" ? "alt" : ""
        expect(parse("URL=${HOST:+alt}", view)).to eql("URL" => expected)
      end

      it "expands ${HOST+alt} when set, including empty" do
        expected = state == "unset" ? "" : "alt"
        expect(parse("URL=${HOST+alt}", view)).to eql("URL" => expected)
      end

      it "requires ${HOST:?message} to be set and non-empty" do
        result = begin
          parse("URL=${HOST:?must be present}", view)
        rescue Dotenv::FormatError => e
          e
        end

        if state == "normal"
          expect(result).to eql("URL" => "example.com")
        else
          expect(result).to be_a(Dotenv::FormatError)
          expect(result.message).to include("must be present")
        end
      end

      it "requires ${HOST?message} only to be set" do
        result = begin
          parse("URL=${HOST?must be present}", view)
        rescue Dotenv::FormatError => e
          e
        end

        if state == "unset"
          expect(result).to be_a(Dotenv::FormatError)
          expect(result.message).to include("must be present")
        else
          expected = state == "empty" ? "" : "example.com"
          expect(result).to eql("URL" => expected)
        end
      end
    end
  end

  it "resolves empty and unset differently within the same value" do
    content = "A=${UNSET-x}\nB=${EMPTY-x}\nC=${UNSET:+y}\nD=${EMPTY:+y}"
    expect(parse(content, {"EMPTY" => ""}))
      .to eql("A" => "x", "B" => "", "C" => "", "D" => "")
  end

  it "expands variables referenced from inside the default branch" do
    content = "DEFAULT=localhost\nURL=${HOST:-$DEFAULT:3000}"
    expect(parse(content)).to eql("DEFAULT" => "localhost", "URL" => "localhost:3000")
  end

  it "expands nested braces inside the selected branch" do
    content = "PRIMARY=a\nFALLBACK=b\nVALUE=${UNSET:-${PRIMARY}-${FALLBACK}}"
    expect(parse(content))
      .to eql("PRIMARY" => "a", "FALLBACK" => "b", "VALUE" => "a-b")
  end

  it "does not expand variables in single quoted values" do
    expect(parse("URL='${HOST:-localhost}'", {}))
      .to eql("URL" => "${HOST:-localhost}")
  end

  it "keeps escaped dollar signs literal inside branches" do
    expect(parse("URL=${HOST:-\\$PRIMARY}", {}))
      .to eql("URL" => "$PRIMARY")
    expect(parse("URL=\\${HOST:-localhost}", {}))
      .to eql("URL" => "${HOST:-localhost}")
  end

  it "does not execute command substitutions in a branch that is not selected" do
    Dir.mktmpdir do |dir|
      marker = File.join(dir, "ran")
      content = "HOST=example.com\nURL=${HOST:-$(touch #{marker})}"
      parse(content, {})
      expect(File.exist?(marker)).to be(false)
    end
  end

  it "executes command substitutions only in the selected branch" do
    Dir.mktmpdir do |dir|
      marker = File.join(dir, "ran")
      content = "URL=${HOST:-$(touch #{marker})}"
      parse(content, {})
      expect(File.exist?(marker)).to be(true)
    end
  end

  it "does not execute the alternate command when the parameter is empty" do
    Dir.mktmpdir do |dir|
      marker = File.join(dir, "ran")
      content = "URL=${HOST:+$(touch #{marker})}"
      parse(content, {"HOST" => ""})
      expect(File.exist?(marker)).to be(false)
    end
  end

  it "expands the error message of a required parameter" do
    expect do
      parse("NAME=database\nURL=${HOST:?$NAME is missing}", {})
    end.to raise_error(Dotenv::FormatError, /database is missing/)
  end

  it "reports a standard error when the required message is empty" do
    expect do
      parse("URL=${HOST:?}", {})
    end.to raise_error(Dotenv::FormatError, /HOST is a required parameter but is not set/)

    expect do
      parse("URL=${HOST:?}", {"HOST" => ""})
    end.to raise_error(Dotenv::FormatError, /HOST is a required parameter but is empty/)
  end

  it "reports the line and column of a failed required parameter" do
    content = "OTHER=1\n# comment\nURL=${MISSING:?nope}"
    expect do
      parse(content, {})
    end.to raise_error(Dotenv::FormatError, /nope \(line 3, column 5\)/)
  end

  it "reports the line and column inside double quoted values" do
    content = "\nURL=\"x-${MISSING:?boom}\""
    expect do
      parse(content, {})
    end.to raise_error(Dotenv::FormatError, /boom \(line 2, column 8\)/)
  end

  it "limits recursive expansion and identifies the location" do
    value = 12.times.reduce("DEEP") { |inner, _| "${UNSET:-#{inner}}" }
    expect do
      parse("V=#{value}", {})
    end.to raise_error(Dotenv::FormatError,
      /parameter expansion exceeds maximum depth of 10 \(line 1, column 3\)/)
  end

  it "uses the supplied environment view without reading or mutating ENV" do
    ENV["HOST"] = "from-env"
    view = {"HOST" => "from-view"}
    expect(parse("URL=${HOST:-fallback}", view)).to eql("URL" => "from-view")
    expect(ENV["URL"]).to be_nil
  end

  it "uses an empty view when requested" do
    ENV["HOST"] = "from-env"
    expect(parse("URL=${HOST:-fallback}", {})).to eql("URL" => "fallback")
  end

  it "keeps repeated parses isolated from previously parsed values" do
    content = "URL=${HOST:-fallback}"
    expect(parse(content, {})).to eql("URL" => "fallback")
    expect(parse(content, {"HOST" => "set"})).to eql("URL" => "set")
  end

  it "rejects an unclosed parameter expansion with a position" do
    expect do
      parse("URL=${HOST:-fallback", {})
    end.to raise_error(Dotenv::FormatError, /unclosed parameter expansion .* \(line 1, column 5\)/)
  end

  it "rejects a parameter expansion without a variable name" do
    expect do
      parse("URL=${:-fallback}", {})
    end.to raise_error(Dotenv::FormatError, /missing variable name in parameter expansion \(line 1, column 5\)/)
  end
end
