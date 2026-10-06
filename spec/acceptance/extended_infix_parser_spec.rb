require 'spec_helper'

# Models a query expression such as
#   enabled ? -count**2 : total!
# where prefix minus, postfix factorial and the ternary conditional all
# share the single operator table of infix_expression.
describe 'Prefix, postfix and ternary operations in infix_expression' do
  class ExtendedExpressionParser < Parslet::Parser
    rule(:space) { match['\s'].repeat }
    rule(:ws)    { space }
    rule(:digit) { match['0-9'] }
    rule(:integer) { digit.repeat(1).as(:int) >> ws }

    rule(:pow_op)    { str('**') >> ws }
    rule(:mul_op)    { match['*/'] >> ws }
    rule(:add_op)    { match['+-'] >> ws }
    rule(:minus_op)  { str('-') >> ws }
    rule(:factorial) { str('!') }
    rule(:question)  { str('?') >> ws }
    rule(:colon)     { str(':') >> ws }

    rule(:expression) { infix_expression(integer,
      [question, colon, 1, :right],
      [add_op, 2, :left],
      [mul_op, 3, :left],
      [minus_op, 4, :prefix],
      [pow_op, 5, :right],
      [factorial, 6, :postfix]) }
  end

  let(:parser) { ExtendedExpressionParser.new }
  subject { parser.expression }

  it 'parses a complete query expression into one tree' do
    should parse('1 ? -2**3 : 4!').as(
      l: {int: '1'},
      o: '? ',
      m: {o: '-', r: {l: {int: '2'}, o: '**', r: {int: '3'}}},
      c: ': ',
      r: {l: {int: '4'}, o: '!'})
  end

  it 'keeps the ternary in the conditional position at low precedence' do
    should parse('1+2 ? 3 : 4').as(
      l: {l: {int: '1'}, o: '+', r: {int: '2'}},
      o: '? ', m: {int: '3'}, c: ': ', r: {int: '4'})
  end

  it 'evaluates the trees in the declared order through a transform' do
    transform = Class.new(Parslet::Transform) do
      rule(int: simple(:i)) { Integer(i) }
      rule(o: simple(:_), r: simple(:v)) { -v }
      rule(l: simple(:v), o: simple(:_)) { (1..v).inject(:*) }
      rule(l: simple(:l), o: simple(:o), r: simple(:r)) {
        o.to_s.strip == '**' ? l ** r : l.send(o.to_s.strip, r) }
      rule(l: simple(:c), o: simple(:q),
           m: simple(:y), c: simple(:_), r: simple(:n)) { c != 0 ? y : n }
    end.new

    tree = parser.expression.parse('1 ? -2**3 : 4!')
    transform.apply(tree).should == -(2 ** 3)

    tree = parser.expression.parse('0 ? 1 : 3!')
    transform.apply(tree).should == 6
  end
end
