# Encoding: UTF-8

require 'spec_helper'

describe Parslet do
  include Parslet

  let(:source) { "漢字 = 42 # コメント\n    値\n" }

  let(:tokens) do
    [
      [:identifier, "漢字", 0...6],
      [:keyword, "=", 7...8],
      [:number, 42, 9...11],
      [:identifier, "値", 31...34]
    ]
  end

  let(:parser) do
    assignment = token(:identifier).as(:name) >>
      token(:keyword) { |value| value == "=" } >>
      token(:number) { |value| value > 0 }.as(:value)
    identifier = token(:identifier).as(:name)

    (assignment | identifier).repeat(1).as(:statements)
  end

  describe "token parsing" do
    it "matches by token type and filters token values" do
      result = parser.parse(tokens, source: source)

      result[:statements].first[:name].value.should == "漢字"
      result[:statements].first[:value].value.should == 42
    end

    it "passes the value and token to a value condition" do
      token_atom = token(:keyword) do |value, token|
        value.should == "="
        token.type.should == :keyword
        token.range.should == (7...8)
        true
      end

      token_atom.parse(tokens[1, 1], source: source).value.should == "="
    end

    it "accepts a one argument lambda as a value condition" do
      result = token(:number, &->(value) { value == 42 }).
        parse(tokens[2, 1], source: source)

      result.value.should == 42
    end

    it "supports sequence, alternative, named, repetition and lookahead atoms" do
    atom = token(:identifier) >>
      token(:keyword).present? >>
      (token(:keyword) | token(:number)) >>
      token(:number) >>
      token(:keyword).absent?

    result = atom.parse(tokens.first(3), source: source)

    result.to_s.should == "漢字 = 42"
    end

    it "keeps line and column anchored to original text" do
      result = parser.parse(tokens, source: source)
      name = result[:statements].first[:name]
      value = result[:statements].first[:value]

      name.line_and_column.should == [1, 1]
      value.line_and_column.should == [1, 6]
      result[:statements].last[:name].line_and_column.should == [2, 5]
    end

    it "includes skipped source text between tokens in combined slices" do
      result = parser.parse(tokens.first(3), source: source)
      slice = [
        result[:statements].first[:name].to_s,
        result[:statements].first[:value].to_s
      ]

      slice.should == ["漢字", "42"]
      (token(:identifier) >> token(:keyword) >> token(:number)).
        parse(tokens.first(3), source: source).to_s.should ==
        "漢字 = 42"
      (token(:identifier) >> token(:keyword) >> token(:number)).
        parse(tokens.first(3), source: source).line_and_column.should == [1, 1]
    end

    it "reports token failures at the original source position" do
      failure = catch_failed_parse do
        token(:number).parse(tokens, source: source)
      end

      failure.to_s.should include("Expected :number")
      failure.to_s.should include("line 1 char 1")
    end

    it "reports premature end of input at the end of the original source" do
      failure = catch_failed_parse do
        (token(:identifier) >> token(:number)).
          parse(tokens.first(1), source: source)
      end

      failure.ascii_tree.should include("Premature end of token input")
      failure.pos.charpos.should == source.size
      failure.source.line_and_column(failure.pos).should == [3, 1]
    end

    it "accepts token objects and duck-typed tokens" do
      token = Parslet::Token.new(:number, 7, 9...11, source)
      duck = Struct.new(:type, :value, :range).new(:identifier, "値", 31...34)

      result = (token(:number) >> token(:identifier)).
        parse([token, duck], source: source)

      result.to_s.should == "42 # コメント\n    値"
    end
  end

  describe "token ranges" do
    it "accepts adjacent non-overlapping ranges" do
      expect {
        Parslet::TokenSource.new(
          [[:identifier, "漢", 0...3], [:identifier, "字", 3..5]],
          source)
      }.not_to raise_error
    end

    it "rejects overlapping ranges" do
      expect {
        Parslet::TokenSource.new(
          tokens + [[:keyword, "重", 32...34]],
          source)
      }.to raise_error(ArgumentError, /overlaps/)
    end

    it "rejects reversed ranges" do
      expect {
        Parslet::TokenSource.new(
          [[:identifier, "x", 27...24]],
          source)
      }.to raise_error(ArgumentError, /reversed or empty/)
    end

    it "rejects ranges that are not in source order" do
      expect {
        Parslet::TokenSource.new(
          [tokens.last, tokens[1]],
          source)
      }.to raise_error(ArgumentError, /not in source order/)
    end

    it "rejects ranges outside the original source" do
      expect {
        Parslet::TokenSource.new(
          [[:identifier, "x", source.bytesize...source.bytesize + 1]],
          source)
      }.to raise_error(ArgumentError, /outside/)
    end
  end
end
