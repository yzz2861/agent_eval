require 'spec_helper'

describe 'left recursive rules' do
  include Parslet

  class LeftRecursiveExpressionParser < Parslet::Parser
    root :expr

    rule(:expr, left_recursive: true) do
      add | term
    end

    rule(:add) do
      expr.as(:left) >> plus.as(:operator) >> term.as(:right)
    end

    rule(:term, left_recursive: true) do
      multiply | factor
    end

    rule(:multiply) do
      term.as(:left) >> star.as(:operator) >> factor.as(:right)
    end

    rule(:factor) do
      parenthesized | number
    end

    rule(:parenthesized) do
      ignored_lparen >> expr.as(:group) >> ignored_rparen
    end

    rule(:number) do
      digit.repeat(1).as(:number)
    end

    rule(:plus) { str('+') }
    rule(:star) { str('*') }
    rule(:ignored_lparen) { str('(').ignore }
    rule(:ignored_rparen) { str(')').ignore }
    rule(:digit) { match('[0-9]') }
  end

  let(:parser) { LeftRecursiveExpressionParser.new }

  def normalize(value)
    case value
    when Parslet::Slice
      value.to_s
    when Hash
      value.transform_values { |child| normalize(child) }
    when Array
      value.map { |child| normalize(child) }
    else
      value
    end
  end

  it 'parses direct left recursion' do
    expect(normalize(parser.parse('1*2'))).to eq(
      left: { number: '1' },
      operator: '*',
      right: { number: '2' }
    )
  end

  it 'keeps growing through indirect left recursion' do
    expect(normalize(parser.parse('1+2'))).to eq(
      left: { number: '1' },
      operator: '+',
      right: { number: '2' }
    )
  end

  it 'mixes precedence and parentheses' do
    expect(normalize(parser.parse('1+2*3'))).to eq(
      left: { number: '1' },
      operator: '+',
      right: {
        left: { number: '2' },
        operator: '*',
        right: { number: '3' }
      }
    )

    expect(normalize(parser.parse('(1+2)*3'))).to eq(
      left: { group: {
        left: { number: '1' },
        operator: '+',
        right: { number: '2' }
      } },
      operator: '*',
      right: { number: '3' }
    )
  end

  it 'preserves slices and named nodes through recursion' do
    result = parser.parse('12+34')

    expect(result[:left][:number].to_s).to eq('12')
    expect(result[:left][:number].offset).to eq(0)
    expect(result[:right][:number].to_s).to eq('34')
    expect(result[:right][:number].offset).to eq(3)
    expect(result.keys).to eq([:left, :operator, :right])
  end

  it 'keeps ordered choice at the same position' do
    grammar = Class.new(Parslet::Parser) do
      root :expression
      rule(:expression, left_recursive: true) { recursive | simple }
      rule(:recursive) do
        expression.as(:left) >> str('+') >> simple.as(:right)
      end
      rule(:simple) { str('a').as(:simple) }
    end

    expect(normalize(grammar.new.parse('a+a'))).to eq(
      left: { simple: 'a' },
      right: { simple: 'a' }
    )
    expect(normalize(grammar.new.parse('a'))).to eq(simple: 'a')
  end

  it 'keeps ordered choice when alternatives consume the same input' do
    grammar = Class.new(Parslet::Parser) do
      root :expression
      rule(:expression, left_recursive: true) { first | second | number }
      rule(:first) do
        expression.as(:left) >> bang >> str('1').as(:first)
      end
      rule(:second) do
        expression.as(:left) >> bang >> str('1').as(:second)
      end
      rule(:number) { match('[0-9]').as(:number) }
      rule(:bang) { str('!') }
    end

    result = normalize(grammar.new.parse('1!1'))

    expect(result).to eq(
      left: { number: '1' },
      first: '1'
    )
    expect(result).not_to include(:second)
  end

  it 'reports all rules in an indirect recursive loop' do
    grammar = Class.new(Parslet::Parser) do
      root :alpha
      rule(:alpha, left_recursive: true) { beta }
      rule(:beta) { gamma }
      rule(:gamma) { alpha }
    end

    cause = catch_failed_parse { grammar.new.parse('x') }

    expect(cause.to_s).to include('alpha', 'beta', 'gamma')
    expect(cause.to_s).to include('no alternative consumed input')
    expect { cause.ascii_tree }.not_to raise_error
  end

  Parslet::ErrorReporter.constants.map do |name|
    Parslet::ErrorReporter.const_get(name)
  end.select do |reporter_class|
    reporter_class.is_a?(Class) && reporter_class.name
  end.each do |reporter_class|
    it "terminates failure reporting with #{reporter_class}" do
      grammar = Class.new(Parslet::Parser) do
        root :expression
        rule(:expression, left_recursive: true) { expression }
      end
      reporter = reporter_class.new

      cause = catch_failed_parse do
        grammar.new.parse('x', reporter: reporter)
      end

      expect(cause.ascii_tree).to include('expression')
    end
  end

  it 'does not change the result when the option is not enabled' do
    grammar = Class.new(Parslet::Parser) do
      root :expression
      rule(:expression) { str('(').ignore >> expression >> str(')').ignore | number }
      rule(:number) { match('[0-9]').repeat(1).as(:number) }
    end

    expect(normalize(grammar.new.parse('((1))'))).to eq(number: '1')
  end

  it 'accepts left_recursion as an option alias' do
    grammar = Class.new(Parslet::Parser) do
      root :expression
      rule(:expression, left_recursion: true) do
        expression.as(:left) >> str('+') >> str('1').as(:right) | str('1')
      end
    end

    expect(normalize(grammar.new.parse('1+1'))).to eq(
      left: '1',
      right: '1'
    )
  end
end
