require 'spec_helper'

describe Parslet::ShadowCheck do
  include Parslet

  def check(choice, opts={})
    Parslet::ShadowCheck.check(choice, **{ alphabet: %w[a b i f x], max_length: 2 }.merge(opts))
  end

  describe 'prefix shadowing' do
    it 'finds a witness when a wider branch comes first' do
      report = check(str('a') | str('ab'))

      report.should be_found
      witness = report.witnesses.first
      witness.input.should == 'ab'
      witness.winner.index.should == 0
      witness.winner.consumed.should == 1
      witness.shadowed.map(&:index).should == [1]
      witness.shadowed.first.consumed.should == 2
    end

    it 'changes the witness when branches are swapped' do
      report = check(str('ab') | str('a'))

      witness = report.witnesses.first
      witness.input.should == 'ab'
      witness.winner.index.should == 0
      witness.winner.consumed.should == 2
      witness.shadowed.first.index.should == 1
      witness.shadowed.first.consumed.should == 1
    end
  end

  describe 'keyword vs identifier' do
    let(:identifier) { match('[a-z]').repeat(1) }
    let(:keyword) { str('if') }

    it 'reports the keyword as unreachable when identifier comes first' do
      report = check(identifier | keyword)

      witness = report.witnesses.first
      witness.input.should == 'if'
      witness.winner.consumed.should == 2
      witness.shadowed.first.consumed.should == 2
    end

    it 'reports no shadowing for disjoint branches' do
      report = check(str('a') | str('b'))

      report.should_not be_found
      report.witnesses.should be_empty
    end
  end

  describe 'lookahead handling' do
    let(:identifier) { match('[a-z]').repeat(1) }
    # keyword only counts if not followed by more identifier characters
    let(:guarded_keyword) { str('if') >> match('[a-z]').absent? }

    it 'honours negative lookahead like the real parser does' do
      report = check(guarded_keyword | identifier)

      # 'if' alone: keyword wins, identifier is shadowed (intended priority)
      witness = report.witnesses.first
      witness.input.should == 'if'
      witness.winner.index.should == 0

      # 'ifi' style inputs are not witnesses: the guard fails and the
      # identifier branch legitimately takes over
      report.witnesses.map(&:input).should_not include('ifi', 'ifx', 'ifa')
    end
  end

  describe 'recursion' do
    class ShadowCheckRecursion < Parslet::Parser
      rule(:nested) { (str('a') >> nested.maybe) | str('aa') }
    end

    it 'resolves recursive rules with real choice semantics' do
      report = check(ShadowCheckRecursion.new.nested)

      witness = report.witnesses.first
      witness.input.should == 'aa'
      witness.winner.consumed.should == 2
      witness.shadowed.first.consumed.should == 2
    end
  end

  describe 'left recursion' do
    class ShadowCheckLeftRecursion < Parslet::Parser
      rule(:boom) { (boom >> str('a')) | str('b') }
    end

    it 'reports inputs as unknown instead of blowing the stack' do
      report = check(ShadowCheckLeftRecursion.new.boom, alphabet: %w[a b], max_length: 1)

      report.unknowns.should_not be_empty
      report.unknowns.first.reason.should =~ /recursion/
    end
  end

  describe 'dynamic atoms' do
    it 'stops at the dynamic boundary and marks inputs unknown' do
      report = check(str('a') | dynamic { str('a') })

      report.boundaries.size.should == 1
      report.boundaries.first.should =~ /branch 1/
      report.witnesses.should be_empty
      report.unknowns.should_not be_empty
      report.unknowns.first.reason.should =~ /dynamic/
    end
  end

  describe 'recheck' do
    it 'confirms witnesses against the real parser' do
      report = check(str('a') | str('ab'))
      recheck = report.recheck(report.witnesses.first)

      recheck.should be_consistent
      recheck.choice_consumed.should == 1
    end
  end

  describe 'reporting' do
    it 'states the bounded nature of the search' do
      report = check(str('a') | str('b'))

      report.to_s.should =~ /does not prove the grammar unambiguous/
      report.to_s.should =~ /max length: 2/
    end
  end

  describe 'input validation' do
    it 'rejects non-choice nodes' do
      expect { check(str('a')) }.to raise_error(ArgumentError, /Alternative/)
    end

    it 'refuses to enumerate beyond max_inputs' do
      expect {
        check(str('a') | str('b'), alphabet: %w[a b c d], max_length: 10)
      }.to raise_error(ArgumentError, /max_inputs/)
    end
  end
end
