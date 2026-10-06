require 'spec_helper'
require 'parslet/accelerator'

describe 'left recursive rules' do
  class LeftRecursiveExpressionParser < Parslet::Parser
    rule(:space) { match('\s').repeat }
    rule(:number) { match('[0-9]').repeat(1).as(:number) >> space }
    rule(:add_op) { match('[+]').as(:op) >> space }
    rule(:mul_op) { match('[*]').as(:op) >> space }
    rule(:lparen) { str('(') >> space }
    rule(:rparen) { str(')') >> space }

    rule(:expr, left_recursive: true) do
      (expr.as(:left) >> add_op >> term.as(:right)).as(:add) | term
    end
    rule(:term, left_recursive: true) do
      (term.as(:left) >> mul_op >> factor.as(:right)).as(:mul) | factor
    end
    rule(:factor) do
      (lparen >> expr >> rparen) | number
    end

    root(:expr)
  end

  let(:parser) { LeftRecursiveExpressionParser.new }

  it 'parses mixed precedence expressions directly' do
    result = parser.parse('1 + 2 * 3')

    expect(result).to eq(
      add: {
        left: { number: '1' },
        op: '+',
        right: {
          mul: {
            left: { number: '2' },
            op: '*',
            right: { number: '3' }
          }
        }
      }
    )
  end

  it 'parses parenthesized expressions' do
    result = parser.parse('(1 + 2) * 3')

    expect(result).to eq(
      mul: {
        left: {
          add: {
            left: { number: '1' },
            op: '+',
            right: { number: '2' }
          }
        },
        op: '*',
        right: { number: '3' }
      }
    )
  end

  it 'keeps slices for named leaves' do
    result = parser.parse('12 + 3')
    left = result.fetch(:add).fetch(:left).fetch(:number)

    expect(left).to be_a(Parslet::Slice)
    expect(left.offset).to eq(0)
    expect(left.str).to eq('12')
  end

  it 'preserves the option when atoms are rebuilt by the accelerator' do
    optimized = Parslet::Accelerator.apply(parser)

    expect(optimized.parse('1 + 2')).to eq(
      add: {
        left: { number: '1' },
        op: '+',
        right: { number: '2' }
      }
    )
  end

  it 'honors ordered alternatives at the same position' do
    grammar = Class.new(Parslet::Parser) do
      root(:expr)
      rule(:base) { str('a').as(:base) }
      rule(:expr, left_recursive: true) do
        (expr.as(:left) >> str('a').as(:tail)).as(:longer) |
          str('a').as(:first) |
          base
      end
    end

    expect(grammar.new.parse('aa')).to eq(
      longer: {
        left: { first: 'a' },
        tail: 'a'
      }
    )
    expect(grammar.new.parse('a')).to eq(first: 'a')
  end

  it 'supports indirect left recursion' do
    grammar = Class.new(Parslet::Parser) do
      root(:expr)
      rule(:space) { match('\s').repeat }
      rule(:number) { match('[0-9]').repeat(1).as(:number) >> space }
      rule(:minus) { str('-').as(:op) >> space }
      rule(:expr, left_recursive: true) { additive }
      rule(:additive) { expression_continuation | number }
      rule(:expression_continuation) do
        (expr.as(:left) >> minus >> number.as(:right)).as(:subtract)
      end
    end

    expect(grammar.new.parse('1 - 2 - 3')).to eq(
      subtract: {
        left: {
          subtract: {
            left: { number: '1' },
            op: '-',
            right: { number: '2' }
          }
        },
        op: '-',
        right: { number: '3' }
      }
    )
  end

  it 'accepts left_recursion as an alias for the explicit option' do
    grammar = Class.new(Parslet::Parser) do
      root(:expr)
      rule(:number) { str('a').as(:number) }
      rule(:expr, left_recursion: true) do
        (expr.as(:left) >> str('a').as(:tail)).as(:pair) | number
      end
    end

    expect(grammar.new.parse('aaa')).to eq(
      pair: {
        left: {
          pair: {
            left: { number: 'a' },
            tail: 'a'
          }
        },
        tail: 'a'
      }
    )
  end

  it 'reports recursive cycles that cannot consume input without looping forever' do
    grammar = Class.new(Parslet::Parser) do
      root(:expr)
      rule(:expr, left_recursive: true) { additive }
      rule(:additive) { expression_continuation }
      rule(:expression_continuation) { expr >> str(';') }
    end

    expect { grammar.new.parse('') }.to raise_error(
      Parslet::ParseFailed,
      /Left recursion in EXPR, ADDITIVE, EXPRESSION_CONTINUATION did not consume input/
    )

    cause = catch_failed_parse { grammar.new.parse('') }
    expect { cause.ascii_tree }.not_to raise_error
  end

  it 'reports left-recursive failures through alternate reporters' do
    grammar = Class.new(Parslet::Parser) do
      root(:expr)
      rule(:space) { match('\s').repeat }
      rule(:number) { match('[0-9]').repeat(1) >> space }
      rule(:plus) { str('+') >> space }
      rule(:expr, left_recursive: true) do
        (expr >> plus >> number) | number
      end
    end

    [
      Parslet::ErrorReporter::Tree.new,
      Parslet::ErrorReporter::Deepest.new,
      Parslet::ErrorReporter::Contextual.new
    ].each do |reporter|
      expect { grammar.new.parse('1 +', reporter: reporter) }.to raise_error(
        Parslet::ParseFailed
      )
    end
  end

  it 'preserves right-recursive parse results without the option' do
    grammar = Class.new(Parslet::Parser) do
      root(:expr)
      rule(:space) { match('\s').repeat }
      rule(:number) { match('[0-9]').repeat(1).as(:number) >> space }
      rule(:expr) { number.as(:head) >> (str('+') >> space >> number.as(:rest)).maybe }
    end

    expect(grammar.new.parse('1 + 2')).to eq(
      head: { number: '1' },
      rest: { number: '2' }
    )
  end
end
