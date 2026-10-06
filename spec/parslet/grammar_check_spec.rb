require 'spec_helper'

describe Parslet::GrammarCheck do
  include Parslet

  def check(parser_class)
    parser_class.grammar_check
  end

  describe 'unbounded repetition of a nullable body' do
    it 'flags a repetition of the empty string' do
      grammar = Class.new(Parslet::Parser) do
        rule(:empty) { str('') }
        rule(:rep)   { empty.repeat }
        root(:rep)
      end

      result = check(grammar)
      result.should_not be_ok
      result.errors.size.should == 1
      result.report.should =~ /Unbounded repetition/
      # The chain reaches the user declared rule and the offending atom.
      chain = result.errors.first.chain
      chain.should include('rep')
      chain.should include('empty')
      chain.should include("str('')")
    end

    it 'follows indirect nullability through several rules' do
      grammar = Class.new(Parslet::Parser) do
        rule(:a) { b }
        rule(:b) { c }
        rule(:c) { str('').maybe }
        rule(:r) { c.repeat }
        root(:r)
      end

      result = check(grammar)
      result.should_not be_ok
      chain = result.errors.first.chain
      chain[0..3].should == ['r', 'repeat(0, nil)', 'c', 'maybe']
    end

    it 'flags .maybe applied in the body of another repetition' do
      result = Parslet.grammar_check(str('').maybe.repeat)
      result.should_not be_ok
      result.errors.first.chain.should include('maybe')
    end

    it 'flags a repetition of a lookahead, which never consumes' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { str('a').present?.repeat }
        root(:r)
      end

      check(grammar).should_not be_ok
    end

    it 'accepts a bounded repetition of a nullable body' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { str('').repeat(0, 3) }
        root(:r)
      end

      check(grammar).should be_ok
    end

    it 'accepts a nullable body that is not repeated unboundedly' do
      grammar = Class.new(Parslet::Parser) do
        rule(:optional_ws) { match('[\\s]').repeat }
        rule(:item)       { str('a') }
        rule(:line)       { optional_ws >> item }
        rule(:doc)        { line.repeat }
        root(:doc)
      end

      check(grammar).should be_ok
    end
  end

  describe 'non-consuming cycles between rules' do
    it 'flags a mutual recursion that consumes nothing first' do
      grammar = Class.new(Parslet::Parser) do
        rule(:x) { y }
        rule(:y) { x }
        root(:x)
      end

      result = check(grammar)
      result.should_not be_ok
      message = result.errors.first
      message.message.should =~ /Non-consuming rule loop/
      message.chain.should == ['x', 'y', 'x']
    end

    it 'flags a cycle hidden behind a nullable prefix rule' do
      grammar = Class.new(Parslet::Parser) do
        rule(:lead)    { str('x').maybe }
        rule(:back)    { lead >> around }
        rule(:around)  { back }
        root(:back)
      end

      result = check(grammar)
      result.should_not be_ok
      chain = result.errors.first.chain
      chain.should include('back')
      chain.should include('around')
    end

    it 'does not flag normal parenthesis recursion' do
      grammar = Class.new(Parslet::Parser) do
        rule(:balanced) do
          str('(') >> balanced.maybe >> str(')')
        end
        root(:balanced)
      end

      check(grammar).should be_ok
    end

    it 'does not flag right recursion that consumes a character first' do
      grammar = Class.new(Parslet::Parser) do
        rule(:seq) { str('a') >> seq | str('') }
        root(:seq)
      end

      check(grammar).should be_ok
    end

    it 'does not flag left recursion guarded by a consumed character' do
      grammar = Class.new(Parslet::Parser) do
        rule(:rest) { (str('(') >> rest >> str(')')).maybe }
        root(:rest)
      end

      check(grammar).should be_ok
    end
  end

  describe 'alternatives that consume only on one branch' do
    it 'accepts a repetition over an alternative with one consuming branch' do
      grammar = Class.new(Parslet::Parser) do
        rule(:item) { str('a') | str('b') }
        rule(:list) { item.repeat }
        root(:list)
      end

      check(grammar).should be_ok
    end

    it 'accepts an optional branch in a consuming alternative' do
      grammar = Class.new(Parslet::Parser) do
        rule(:sign) { str('+') | str('-') | str('') }
        rule(:num)  { sign >> match('[0-9]').repeat(1) }
        rule(:doc)  { num.repeat }
        root(:doc)
      end

      check(grammar).should be_ok
    end

    it 'flags the repetition when one branch is the empty alternative' do
      grammar = Class.new(Parslet::Parser) do
        rule(:item) { str('a') | str('') }
        rule(:list) { item.repeat }
        root(:list)
      end

      result = check(grammar)
      result.should_not be_ok
      result.errors.first.chain.should include('item')
    end
  end

  describe 'dynamic atoms' do
    it 'does not execute the dynamic block during the check' do
      executed = false
      grammar = Class.new(Parslet::Parser) do
        rule(:d) do
          dynamic do |_source, _ctx|
            executed = true
            str('a')
          end
        end
        rule(:r) { d.repeat }
        root(:r)
      end

      grammar.grammar_check
      executed.should == false
    end

    it 'warns, rather than guessing, when a repetition body is dynamic' do
      grammar = Class.new(Parslet::Parser) do
        rule(:d) { dynamic { |_s, _c| str('a') } }
        rule(:r) { d.repeat }
        root(:r)
      end

      result = check(grammar)
      result.should be_ok
      result.warnings.size.should >= 1
      result.report.should =~ /dynamic/
      result.report.should =~ /cannot be confirmed statically/
      chain = result.warnings.first.chain
      chain.should include('r')
      chain.should include('d')
    end

    it 'warns about a dynamic atom at the start of a rule' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { dynamic { |_s, _c| str('a') } }
        root(:r)
      end

      result = check(grammar)
      result.errors.should be_empty
      result.warnings.first.message.should =~ /non-consuming prefix/
    end

    it 'does not warn when a dynamic atom follows a consuming prefix' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { str('a') >> dynamic { |_s, _c| str('b') } }
        root(:r)
      end

      result = check(grammar)
      result.warnings.should be_empty
    end

    it 'treats scope blocks like dynamic atoms' do
      grammar = Class.new(Parslet::Parser) do
        rule(:s) { scope { str('a') } }
        rule(:r) { s.repeat }
        root(:r)
      end

      result = check(grammar)
      result.errors.should be_empty
      result.warnings.should_not be_empty
    end
  end

  describe 'entry points' do
    it 'is available on instances as well as classes' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { str('').repeat }
        root(:r)
      end

      grammar.new.grammar_check.should_not be_ok
    end

    it 'raises on demand so the check can gate startup' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { str('').repeat }
        root(:r)
      end

      expect { grammar.grammar_check! }.to \
        raise_error(Parslet::GrammarError, /Unbounded repetition/)
    end

    it 'does not raise when the grammar is fine' do
      grammar = Class.new(Parslet::Parser) do
        rule(:r) { str('a').repeat }
        root(:r)
      end

      grammar.grammar_check!.should be_ok
    end

    it 'checks rules that are not reachable from the root' do
      grammar = Class.new(Parslet::Parser) do
        rule(:good) { str('a').repeat }
        rule(:bad)  { str('').repeat }
        root(:good)
      end

      result = check(grammar)
      result.errors.first.chain.should include('bad')
    end

    it 'reports inherited rules of parser subclasses' do
      parent = Class.new(Parslet::Parser) do
        rule(:bad) { str('').repeat }
        root(:bad)
      end
      child = Class.new(parent) do
        rule(:other) { str('x') }
        root(:bad)
      end

      child.grammar_check.errors.first.chain.should include('bad')
    end
  end
end
