require 'spec_helper'

describe Parslet::Atoms::Infix do
  # Parses integers surrounded by optional spaces so that assertions on the
  # tree can focus on operator placement rather than whitespace handling.
  class ExpressionParser < Parslet::Parser
    rule(:ws) { str(' ').repeat }
    rule(:integer) { match['0-9'].repeat(1).as(:int) >> ws }

    rule(:pow_op)    { str('**') >> ws }
    rule(:mul_op)    { match['*/'] >> ws }
    rule(:add_op)    { match['+-'] >> ws }
    rule(:prefix_op) { str('-') >> ws }
    rule(:postfix_op){ str('!') }
    rule(:question)  { str('?') >> ws }
    rule(:colon)     { str(':') >> ws }
    rule(:long_question) { str('??') >> ws }

    rule(:expression) { infix_expression(integer,
      [question, colon, 1, :right],
      [long_question, colon, 1, :right],
      [add_op, 2, :left],
      [mul_op, 3, :left],
      [prefix_op, 4, :prefix],
      [pow_op, 5, :right],
      [postfix_op, 6, :postfix]) }
  end

  let(:parser) { ExpressionParser.new }
  subject { parser.expression }

  describe 'prefix operators' do
    it 'wraps a single operand' do
      should parse('-1').as(
        o: '-', r: {int: '1'})
    end

    it 'stacks repeated prefix operators to the right' do
      should parse('--1').as(
        o: '-', r: {o: '-', r: {int: '1'}})
    end

    it 'starts a right hand side of a binary operation' do
      should parse('1*-2').as(
        l: {int: '1'},
        o: '*',
        r: {o: '-', r: {int: '2'}})
    end

    it 'does not match a binary minus in prefix position by context' do
      should parse('1-2').as(
        l: {int: '1'}, o: '-', r: {int: '2'})
    end

    context 'versus exponentiation' do
      class TighterPrefixParser < Parslet::Parser
        rule(:integer) { match['0-9'].repeat(1).as(:int) }
        rule(:pow_op)    { str('**') }
        rule(:prefix_op) { str('-') }
        rule(:expression) { infix_expression(integer,
          [pow_op, 2, :right],
          [prefix_op, 3, :prefix]) }
      end

      class LooserPrefixParser < Parslet::Parser
        rule(:integer) { match['0-9'].repeat(1).as(:int) }
        rule(:pow_op)    { str('**') }
        rule(:prefix_op) { str('-') }
        rule(:expression) { infix_expression(integer,
          [prefix_op, 2, :prefix],
          [pow_op, 3, :right]) }
      end

      it 'groups as (-2)**3 when the prefix binds tighter' do
        TighterPrefixParser.new.expression.parse('-2**3').should == {
          l: {o: '-', r: {int: '2'}},
          o: '**',
          r: {int: '3'}}
      end

      it 'groups as -(2**3) when the power binds tighter' do
        LooserPrefixParser.new.expression.parse('-2**3').should == {
          o: '-',
          r: {l: {int: '2'}, o: '**', r: {int: '3'}}}
      end
    end
  end

  describe 'postfix operators' do
    it 'wraps a single operand' do
      should parse('1!').as(
        l: {int: '1'}, o: '!')
    end

    it 'stacks repeated postfix operators to the left' do
      should parse('1!!').as(
        l: {l: {int: '1'}, o: '!'}, o: '!')
    end

    it 'binds tighter than surrounding binary operations' do
      should parse('1!*2!').as(
        l: {l: {int: '1'}, o: '!'},
        o: '*',
        r: {l: {int: '2'}, o: '!'})
    end

    it 'does not match in prefix position' do
      expect { subject.parse('!1') }.to raise_error(Parslet::ParseFailed)
    end
  end

  describe 'ternary operators' do
    it 'builds a node with condition, middle expression and right expression' do
      should parse('1?2:3').as(
        l: {int: '1'}, o: '?',
        m: {int: '2'}, c: ':', r: {int: '3'})
    end

    it 'parses full expressions in the middle branch' do
      should parse('1?2+3:4').as(
        l: {int: '1'}, o: '?',
        m: {l: {int: '2'}, o: '+', r: {int: '3'}},
        c: ':', r: {int: '4'})
    end

    it 'parses full expressions in the right branch' do
      should parse('1?2:3+4').as(
        l: {int: '1'}, o: '?',
        m: {int: '2'}, c: ':',
        r: {l: {int: '3'}, o: '+', r: {int: '4'}})
    end

    it 'nests to the right for a right associative conditional' do
      should parse('1?2?3:4:5').as(
        l: {int: '1'}, o: '?',
        m: {
          l: {int: '2'}, o: '?',
          m: {int: '3'}, c: ':', r: {int: '4'}},
        c: ':', r: {int: '5'})
    end

    it 'nests a conditional in the right branch to the right' do
      should parse('1?2:3?4:5').as(
        l: {int: '1'}, o: '?',
        m: {int: '2'}, c: ':',
        r: {
          l: {int: '3'}, o: '?',
          m: {int: '4'}, c: ':', r: {int: '5'}})
    end

    it 'keeps binary operations out of the condition at lower precedence' do
      should parse('1+2?3:4').as(
        l: {l: {int: '1'}, o: '+', r: {int: '2'}},
        o: '?',
        m: {int: '3'}, c: ':', r: {int: '4'})
    end

    it 'reports the missing closing atom' do
      cause = catch_failed_parse { subject.parse('1?2') }
      cause.message.should == "COLON was expected"
    end

    context 'declared left associative' do
      class LeftTernaryParser < Parslet::Parser
        rule(:integer) { match['0-9'].repeat(1) }
        rule(:expression) { infix_expression(integer,
          [str('?'), str(':'), 1, :left]) }
      end

      it 'nests the conditional to the left' do
        expected = {
          l: '1', o: '?',
          m: {l: '2', o: '?', m: '3', c: ':', r: '4'},
          c: ':', r: '5'}
        LeftTernaryParser.new.expression.parse('1?2?3:4:5').should == expected
      end
    end
  end

  describe 'operators sharing a prefix' do
    it 'lets the longer ternary opening win over the single question mark' do
      should parse('1??2:3').as(
        l: {int: '1'}, o: '??',
        m: {int: '2'}, c: ':', r: {int: '3'})
    end

    it 'still matches the short opening when only one question mark follows' do
      should parse('1?2:3').as(
        l: {int: '1'}, o: '?',
        m: {int: '2'}, c: ':', r: {int: '3'})
    end
  end

  describe 'mixed fixities' do
    it 'reduces prefix, postfix, binary and ternary into one tree' do
      should parse('-1!?2!:3+4').as(
        l: {o: '-', r: {l: {int: '1'}, o: '!'}},
        o: '?',
        m: {l: {int: '2'}, o: '!'},
        c: ':',
        r: {l: {int: '3'}, o: '+', r: {int: '4'}})
    end
  end

  describe 'reducer compatibility' do
    it 'still calls a three argument block for binary operations' do
      parser_class = Class.new(Parslet::Parser) do
        rule(:integer) { str('a') }
        rule(:top) { infix_expression(integer,
          [str('-'), 1, :right]) { |l, o, r| {and: [l, r]} } }
      end
      parser_class.new.top.parse('a-a-a').should == {
        and: ['a', {and: ['a', 'a']}]}
    end

    it 'does not call a binary-only block for prefix or postfix nodes' do
      parser_class = Class.new(Parslet::Parser) do
        rule(:integer) { match['0-9'].repeat(1) }
        rule(:top) { infix_expression(integer,
          [str('!'), 4, :postfix],
          [str('-'), 3, :prefix],
          [str('+'), 2, :left]) { |l, o, r| {bin: [l, o, r]} } }
      end
      parser_class.new.top.parse('-1!+2').should == {
        bin: [{o: '-', r: {l: '1', o: '!'}}, '+', '2']}
    end

    it 'sends every fixity to a variadic block' do
      calls = []
      parser_class = Class.new(Parslet::Parser) do
        rule(:integer) { match['0-9'].repeat(1) }
        rule(:top) { infix_expression(integer,
          [str('?'), str(':'), 1, :right],
          [str('!'), 5, :postfix],
          [str('-'), 4, :prefix],
          [str('+'), 2, :left]) { |*args| calls << args; {n: args.length} } }
      end
      parser_class.new.top.parse('-1!+2?3!:4')
      # postfix, prefix, binary, postfix (in middle), ternary
      calls.map(&:length).should == [2, 2, 3, 2, 5]
    end
  end

  describe 'table validation' do
    it 'rejects unknown associativity' do
      expect {
        Parslet::Atoms::Infix.new(Parslet.str('a'),
          [[Parslet.str('+'), 1, :sideways]])
      }.to raise_error(ArgumentError, /associativity/)
    end

    it 'rejects non infix associativity for ternary operators' do
      expect {
        Parslet::Atoms::Infix.new(
          Parslet.str('a'),
          [[Parslet.str('?'), Parslet.str(':'), 1, :prefix]])
      }.to raise_error(ArgumentError, /ternary/)
    end
  end

  describe '#inspect' do
    it 'lists all declared operators' do
      inner = subject.parslet
      inner.inspect.should match(/QUESTION\/COLON/)
      inner.inspect.should match(/POSTFIX_OP/)
    end
  end
end
