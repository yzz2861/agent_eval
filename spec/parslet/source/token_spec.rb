# Encoding: UTF-8

require 'spec_helper'

describe Parslet::TokenSource do
  include Parslet

  let(:source_text) { "# コメント\n名前 = 42" }

  def byte_range(string, lexeme)
    start = string[0, string.index(lexeme)].bytesize
    start...(start + lexeme.bytesize)
  end

  def tokens
    [
      { type: :identifier, value: :name, range: byte_range(source_text, '名前') },
      { type: :operator, value: '=', range: byte_range(source_text, '=') },
      { type: :number, value: 42, range: byte_range(source_text, '42') }
    ]
  end

  let(:source) { described_class.new(source_text, tokens) }

  describe 'matching with existing combinators' do
    it 'matches by token type and returns the original token text' do
      number_source = described_class.new(source_text, [tokens.last])
      result = token(:number).parse(number_source)

      result.to_s.should == '42'
      result.type.should == :number
      result.value.should == 42
      result.range.should == byte_range(source_text, '42')
    end

    it 'can constrain token values' do
      token_source = described_class.new(source_text, tokens)
      result = token(:identifier) { |candidate| candidate.value == :name }.
        parse(token_source, prefix: true)

      result.to_s.should == '名前'
      result.value.should == :name
    end

    it 'supports sequence, alternative and naming' do
      grammar =
        token(:identifier).as(:name) >>
        (token(:keyword) | token(:operator, '=')).as(:operator) >>
        token(:number).as(:number)

      grammar.parse(source).should == {
        name: '名前',
        operator: '=',
        number: '42'
      }
    end

    it 'supports repetition' do
      repeated_source = described_class.new(
        'あ, い',
        [
          { type: :identifier, value: 'あ', range: byte_range('あ, い', 'あ') },
          { type: :operator, value: ',', range: byte_range('あ, い', ',') },
          { type: :identifier, value: 'い', range: byte_range('あ, い', 'い') }
        ])

      grammar = (token(:identifier) >> token(:operator)).repeat >> token(:identifier)

      grammar.parse(repeated_source).should == 'あ,い'
    end

    it 'supports positive and negative lookahead without consuming tokens' do
      lookahead_source = described_class.new(source_text, tokens)
      grammar = token(:identifier).present? >> token(:identifier).as(:name)

      grammar.parse(lookahead_source, prefix: true).should == { name: '名前' }

      absent_source = described_class.new(source_text, tokens)
      absent_source.bytepos = 1
      token(:identifier).absent?.parse(absent_source, prefix: true).should be_nil
      absent_source.chars_left.should == 2
    end
  end

  describe 'positions in the original source' do
    it 'uses byte offsets while reporting character based line and column' do
      name = source.consume_token
      source.consume_token
      number = source.consume_token

      name.offset.should == 7
      name.line_and_column.should == [2, 1]
      number.offset.should == 12
      number.line_and_column.should == [2, 6]
    end

    it 'does not let skipped comments or whitespace drift token locations' do
      failure = catch_failed_parse do
        token(:operator).parse(source)
      end

      failure.to_s.should =~ /Expected token :operator/
      failure.to_s.should =~ /at line 2 char 1/
      failure.pos.charpos.should == 7
    end

    it 'reports the position of a failed value condition' do
      failure = catch_failed_parse do
        token(:identifier) { |candidate| candidate.value == :other }.parse(source)
      end

      failure.to_s.should =~ /at line 2 char 1/
    end

    it 'reports an error after the last token at the end of the original source' do
      exhausted_source = described_class.new(source_text, tokens)
      exhausted_source.consume_token until exhausted_source.chars_left.zero?
      grammar = token(:identifier) >> token(:operator) >> token(:number) >> token(:number)
      failure = catch_failed_parse { grammar.parse(exhausted_source) }

      failure.ascii_tree.should =~ /Premature end of input.*at line 2 char 8/
    end
  end

  describe 'range validation' do
    def expect_invalid_range(tokens, message)
      expect { described_class.new(source_text, tokens) }.
        to raise_error(ArgumentError, message)
    end

    it 'rejects reversed ranges' do
      invalid = tokens.first.merge(range: 3...1)

      expect_invalid_range([invalid], /Token 0 range .* is empty or reversed/)
    end

    it 'rejects ranges that split a multibyte character' do
      invalid = tokens.first.merge(range: 16...21)

      expect_invalid_range([invalid], /character boundary/)
    end

    it 'accepts inclusive ranges' do
      inclusive_range = byte_range(source_text, '42')
      inclusive = described_class.new(
        source_text,
        [{ type: :number, value: 42,
           range: inclusive_range.begin..(inclusive_range.end - 1) }])

      inclusive.consume_token.to_s.should == '42'
    end

    it 'rejects overlapping ranges' do
      first = { type: :identifier, value: '名前', range: 15...21 }
      second = { type: :identifier, value: '前', range: 18...21 }

      expect_invalid_range([first, second], /overlaps a previous token/)
    end

    it 'rejects ranges that are not ordered' do
      ordered = tokens
      unordered = [ordered[1], ordered[0]]

      expect_invalid_range(unordered, /not ordered/)
    end

    it 'allows gaps for whitespace and comments and adjacent ranges' do
      expect { source }.not_to raise_error

      adjacent = described_class.new(
        'あい',
        [
          { type: :identifier, value: 'あ', range: 0...3 },
          { type: :identifier, value: 'い', range: 3...6 }
        ])

      adjacent.chars_left.should == 2
    end
  end
end
