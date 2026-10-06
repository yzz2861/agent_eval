# Encoding: UTF-8

require 'spec_helper'

describe Parslet::IncrementalSession do
  include Parslet

  def fresh_outcome(parser, input)
    parser.parse(input)
  rescue Parslet::ParseFailed => error
    error
  end

  def session_outcome(session)
    session.parse
  rescue Parslet::ParseFailed => error
    error
  end

  def assert_same_outcome(actual, expected)
    if expected.is_a?(Parslet::ParseFailed)
      actual.should be_a(Parslet::ParseFailed)
      actual.message.should == expected.message
      actual.parse_failure_cause.pos.should == expected.parse_failure_cause.pos
    else
      actual.should == expected
    end
  end

  it 'matches full parsing through fixed insert, delete and replacement edits' do
    word = (str('ab') | str('cd') | str('xy')).as(:word)
    parser = (word >> str("\n").maybe).repeat(1)
    session = described_class.new(parser, "ab\ncd\n")

    edits = [
      [:insert,  5, 'xy'],
      [:delete,  2, 1],
      [:replace, 0, 2, 'cd'],
      [:replace, 2, 1, 'b']
    ]

    expected = fresh_outcome(parser, session.input)
    actual = session_outcome(session)
    assert_same_outcome(actual, expected)
    session.cache_stats.to_h.should == {
      hits: 0,
      misses: session.cache_stats.misses,
      invalidated: 0,
      entries: session.cache_stats.entries
    }

    edits.each do |(operation, position, length, replacement)|
      if operation == :insert
        session.insert(position, length)
      elsif operation == :delete
        session.delete(position, length)
      else
        session.public_send(operation, position, length, replacement)
      end
      session.reset_cache_stats

      expected = fresh_outcome(parser, session.input)
      actual = session_outcome(session)
      assert_same_outcome(actual, expected)

      session.cache_stats.hits.should > 0
    end
  end

  it 'reuses an entry after an insertion past its actual observation end' do
    parser = str('a') >> str('b') >> str('x').maybe
    session = described_class.new(parser, 'ab')

    session.parse.should == 'ab'
    session.insert(2, 'x')
    session.reset_cache_stats

    session.parse.should == 'abx'
    session.cache_stats.hits.should >= 1
    session.cache_stats.invalidated.should == 0
  end

  it 'reuses failed alternatives when a later edit cannot change their answer' do
    parser = str('a') >> str('x')
    session = described_class.new(parser, 'ab')

    expect { session.parse }.to raise_error(Parslet::ParseFailed)
    session.insert(2, 'y')
    session.reset_cache_stats

    expect { session.parse }.to raise_error(Parslet::ParseFailed) do |error|
      fresh = fresh_outcome(parser, session.input)
      error.message.should == fresh.message
      error.parse_failure_cause.pos.should == fresh.parse_failure_cause.pos
    end
    session.cache_stats.hits.should > 0
  end

  it 'invalidates a successful zero-width lookahead that inspected later bytes' do
    parser = str('a') >>
      (str('b') >> str('c')).absent? >>
      str('bx')
    session = described_class.new(parser, 'abx')

    session.parse
    session.insert(2, 'c')
    invalidated = session.cache_stats.invalidated
    session.reset_cache_stats

    expect { session.parse }.to raise_error(Parslet::ParseFailed)
    session.input.should == 'abcx'
    invalidated.should >= 1
  end

  it 'builds reused slices from the current source and line cache' do
    parser = str("\n").maybe >>
      str('ab').as(:value) >> str("\n") >> str('cd').as(:tail)
    session = described_class.new(parser, "ab\ncd")
    original = session.parse
    old_tail_cache = original[:tail].line_cache

    session.insert(0, "\n")
    result = session.parse

    result[:value].line_and_column.should == [2, 1]
    result[:tail].line_and_column.should == [3, 1]
    result[:tail].line_cache.should_not equal(old_tail_cache)
    result[:tail].to_s.should == 'cd'
  end

  it 'removes line endings covered by a deletion' do
    parser = str('ab').as(:value) >> str("\n").maybe >> str('cd').as(:tail)
    session = described_class.new(parser, "ab\ncd")
    session.parse

    session.delete(2, 1)
    result = session.parse

    session.input.should == 'abcd'
    result[:value].line_and_column.should == [1, 1]
    result[:tail].line_and_column.should == [1, 3]
  end

  it 'accepts character positions while shifting byte-based cache entries' do
    parser = str('é').as(:value) >> str('b').as(:tail) >> str('c').maybe
    session = described_class.new(parser, 'éb')

    session.parse
    session.insert(2, 'c')
    session.reset_cache_stats
    result = session.parse

    result[:value].should == 'é'
    result[:tail].offset.should == 1
    result[:tail].line_and_column.should == [1, 3]
    session.cache_stats.hits.should >= 1
  end

  it 'treats generic source matching conservatively when it may look ahead' do
    atom = Class.new(Parslet::Atoms::Base) do
      def try(source, context, consume_all)
        context.succ(source.consume(1)) if source.matches?(Regexp.new('a(?=x)'))
      end
    end.new
    session = described_class.new(atom, 'ax')
    session.parse(:prefix => true)

    session.insert(2, 'z')
    invalidated = session.cache_stats.invalidated
    session.reset_cache_stats
    session.parse(:prefix => true)

    invalidated.should >= 1
  end
end
