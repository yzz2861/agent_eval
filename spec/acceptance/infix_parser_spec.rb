require 'spec_helper'

describe 'Infix expression parsing' do
  class InfixExpressionParser < Parslet::Parser
    rule(:space) { match['\s'] }

    def cts atom
      atom >> space.repeat
    end
    def infix *args
      Infix.new(*args)
    end

    rule(:mul_op) { match['*/'] >> str(' ').maybe }
    rule(:add_op) { match['+-'] >> str(' ').maybe }
    rule(:digit) { match['0-9'] }
    rule(:integer) { cts digit.repeat(1) }

    rule(:expression) { infix_expression(integer, 
      [mul_op, 2, :left], 
      [add_op, 1, :right]) }
  end

  let(:p) { InfixExpressionParser.new }
  describe '#integer' do
    let(:i) { p.integer }
    it "parses integers" do
      i.should parse('1')
      i.should parse('123')
    end 
    it "consumes trailing white space" do
      i.should parse('1   ')
      i.should parse('134   ')
    end 
    it "doesn't parse floats" do
      i.should_not parse('1.3')
    end 
  end
  describe '#multiplication' do
    let(:m) { p.expression }
    it "parses simple multiplication" do
      m.should parse('1*2').as(l: '1', o: '*', r: '2')
    end
    it "parses simple multiplication with spaces" do
      m.should parse('1 * 2').as(l: '1 ', o: '* ', r: '2')
    end
    it "parses division" do
      m.should parse('1/2')
    end 
  end
  describe '#addition' do
    let(:a) { p.expression }
    
    it "parses simple addition" do
      a.should parse('1+2')
    end 
    it "parses complex addition" do
      a.should parse('1+2+3-4')
    end
    it "parses a single element" do
      a.should parse('1')
    end
  end

  describe 'mixed operations' do
    let(:mo) { p.expression }

    describe 'inspection' do
      it 'produces useful expressions' do
        p.expression.parslet.inspect.should == 
          "infix_expression(INTEGER, [MUL_OP, ADD_OP])"
      end
    end
    describe 'right associativity' do
      it 'produces trees that lean right' do
        mo.should parse('1+2+3').as(
          l: '1', o: '+', r: {l: '2', o: '+', r: '3'})
      end      
    end
    describe 'left associativity' do
      it 'produces trees that lean left' do
        mo.should parse('1*2*3').as(
          l: {l:'1', o:'*', r:'2'}, o:'*', r:'3')
      end      
    end
    describe 'error handling' do
      describe 'incomplete expression' do
        it 'produces the right error' do
          cause = catch_failed_parse {
            mo.parse('1+') }

          cause.ascii_tree.to_s.should == <<-ERROR
INTEGER was expected at line 1 char 3.
`- Failed to match sequence (DIGIT{1, } SPACE{0, }) at line 1 char 3.
   `- Expected at least 1 of DIGIT at line 1 char 3.
      `- Premature end of input at line 1 char 3.
          ERROR
        end
      end
      describe 'invalid operator' do
        it 'produces the right error' do
          cause = catch_failed_parse {
            mo.parse('1%') }

          cause.ascii_tree.to_s.should == <<-ERROR
Don't know what to do with "%" at line 1 char 2.
          ERROR
        end
      end
    end
  end
  describe "providing a reducer block" do
    class InfixExpressionReducerParser < Parslet::Parser
      rule(:top) { infix_expression(str('a'), [str('-'), 1, :right]) { |l,o,r| {:and=>[l,r]} } }
    end
    
    it "applies the reducer" do
      InfixExpressionReducerParser.new.top.parse("a-a-a").should == {:and=>["a", {:and=>["a", "a"]}]}
    end
  end
end

describe 'Unary and ternary operators' do
  class QueryExpressionParser < Parslet::Parser
    rule(:space) { match['\s'] }

    def cts atom
      atom >> space.repeat
    end

    rule(:integer) { cts match['0-9'].repeat(1) }

    rule(:expression) { infix_expression(integer,
      [cts(str('!=')), 3, :left],
      [cts(str('!')), 5, :postfix],
      [cts(str('-')), 4, :prefix],
      [cts(str('-')), 2, :left],
      [cts(str('+')), 2, :left],
      [cts(str('^')), 6, :right],
      [[cts(str('?')), cts(str(':'))], 1, :right]) }
  end

  let(:p) { QueryExpressionParser.new }
  let(:e) { p.expression }

  describe 'prefix operators' do
    it 'reduce with nil on the missing side' do
      e.should parse('-1').as(l: nil, o: '-', r: '1')
    end
    it 'nest towards the operand' do
      e.should parse('--1').as(
        l: nil, o: '-', r: {l: nil, o: '-', r: '1'})
    end
    it 'mix with binary operators on the same token' do
      e.should parse('1--2').as(
        l: '1', o: '-', r: {l: nil, o: '-', r: '2'})
    end
  end

  describe 'prefix minus versus power' do
    it 'gobbles the power expression when declared looser' do
      e.should parse('-1^2').as(
        l: nil, o: '-', r: {l: '1', o: '^', r: '2'})
    end

    context 'declared tighter than power' do
      class TightPrefixParser < Parslet::Parser
        rule(:expression) { infix_expression(match['0-9'].repeat(1),
          [str('-'), 2, :prefix],
          [str('^'), 1, :right]) }
      end

      it 'binds to the immediate operand only' do
        TightPrefixParser.new.expression.should parse('-1^2').as(
          l: {l: nil, o: '-', r: '1'}, o: '^', r: '2')
      end
    end
  end

  describe 'postfix operators' do
    it 'reduce with nil on the missing side' do
      e.should parse('1!').as(l: '1', o: '!', r: nil)
    end
    it 'chain towards the left' do
      e.should parse('1!!').as(
        l: {l: '1', o: '!', r: nil}, o: '!', r: nil)
    end
    it 'combine with prefix operators' do
      e.should parse('-1!').as(
        l: nil, o: '-', r: {l: '1', o: '!', r: nil})
    end
    it 'respect precedence against tighter binary operators' do
      e.should parse('1^2!').as(
        l: {l: '1', o: '^', r: '2'}, o: '!', r: nil)
    end
  end

  describe 'operators sharing a prefix' do
    it 'prefers the longer operator declared first' do
      e.should parse('1!=2').as(l: '1', o: '!=', r: '2')
    end
    it 'still matches the shorter operator on its own' do
      e.should parse('1!').as(l: '1', o: '!', r: nil)
    end
  end

  describe 'ternary operators' do
    it 'reduce condition, middle and right into a single node' do
      e.should parse('1?2:3').as(
        l: '1', o: '?', m: '2', s: ':', r: '3')
    end
    it 'nest right when declared right associative' do
      e.should parse('1?2:3?4:5').as(
        l: '1', o: '?', m: '2', s: ':',
        r: {l: '3', o: '?', m: '4', s: ':', r: '5'})
    end
    it 'parse the middle as a full expression' do
      e.should parse('1?2+3:4').as(
        l: '1', o: '?', m: {l: '2', o: '+', r: '3'}, s: ':', r: '4')
    end
    it 'allow nested ternaries in the middle' do
      e.should parse('1?2?3:4:5').as(
        l: '1', o: '?',
        m: {l: '2', o: '?', m: '3', s: ':', r: '4'},
        s: ':', r: '5')
    end
    it 'combine with prefix operators' do
      e.should parse('-1?2:3').as(
        l: {l: nil, o: '-', r: '1'}, o: '?', m: '2', s: ':', r: '3')
    end

    context 'with a postfix operator sharing the opening token' do
      class OptionalExpressionParser < Parslet::Parser
        rule(:expression) { infix_expression(match['0-9'].repeat(1),
          [[str('?'), str(':')], 1, :right],
          [str('?'), 2, :postfix]) }
      end
      let(:o) { OptionalExpressionParser.new.expression }

      it 'parses a complete ternary as ternary' do
        o.should parse('1?2:3').as(
          l: '1', o: '?', m: '2', s: ':', r: '3')
      end
      it 'rewinds a ternary without separator and tries the postfix' do
        o.should parse('1?').as(l: '1', o: '?', r: nil)
      end
    end

    describe 'incomplete ternary' do
      it 'does not swallow the opening token' do
        cause = catch_failed_parse {
          e.parse('1?2') }

        cause.ascii_tree.to_s.should == <<-ERROR
Don't know what to do with "?2" at line 1 char 2.
        ERROR
      end
    end
  end

  describe 'reducer block arities' do
    class ShapeReducingParser < Parslet::Parser
      rule(:top) { infix_expression(str('a'),
        [str('!'), 3, :postfix],
        [str('-'), 2, :prefix],
        [[str('?'), str(':')], 1, :right]) { |*args| {:node => args} } }
    end
    let(:r) { ShapeReducingParser.new.top }

    it 'calls prefix reductions with (nil, operator, operand)' do
      r.parse('-a').should == {:node => [nil, '-', 'a']}
    end
    it 'calls postfix reductions with (operand, operator, nil)' do
      r.parse('a!').should == {:node => ['a', '!', nil]}
    end
    it 'calls ternary reductions with all five parts' do
      r.parse('a?a:a').should == {:node => ['a', '?', 'a', ':', 'a']}
    end
  end

  describe 'invalid declarations' do
    it 'rejects unknown associativity or kind markers' do
      expect {
        Parslet.infix_expression(
          Parslet.str('a'), [Parslet.str('+'), 1, :bogus])
      }.to raise_error(ArgumentError, /Unknown operator kind/)
    end
  end
end
