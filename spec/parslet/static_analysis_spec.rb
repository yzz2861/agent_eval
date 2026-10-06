require 'spec_helper'
require 'parslet/static_analysis'

describe Parslet::StaticAnalysis do
  include Parslet

  # A parser that puts a directly nullable atom into an unbounded
  # repetition: the incident described in the feature request.
  #
  class DirectlyNullableRepetition < Parslet::Parser
    rule(:maybe_x) { str('x').maybe }
    rule(:start)   { maybe_x.repeat }
    root(:start)
  end

  # Nullability that only becomes apparent through several rule
  # references.
  #
  class IndirectlyNullableRepetition < Parslet::Parser
    rule(:alpha) { bravo }
    rule(:bravo) { charlie }
    rule(:charlie) { str('z').maybe }
    rule(:start) { alpha.repeat }
    root(:start)
  end

  # Rules calling each other without consuming anything (left recursion).
  #
  class NonConsumingCycle < Parslet::Parser
    rule(:alpha) { bravo }
    rule(:bravo) { alpha }
    rule(:start) { alpha }
    root(:start)
  end

  class SelfCallingRule < Parslet::Parser
    rule(:alpha) { alpha }
    rule(:start) { alpha }
    root(:start)
  end

  # A longer non consuming loop spanning several rules.
  #
  class LongerCycle < Parslet::Parser
    rule(:alpha) { bravo }
    rule(:bravo) { charlie }
    rule(:charlie) { bravo }
    rule(:start) { alpha }
    root(:start)
  end

  # Optional left recursion. The reference is reached with zero input
  # consumed, so it is a non consuming loop even though the rule as a whole
  # also consumes an 'x'.
  #
  class OptionalLeftRecursion < Parslet::Parser
    rule(:alpha) { alpha.maybe >> str('x') }
    rule(:start) { alpha }
    root(:start)
  end

  # Ordinary bracket recursion: a character is consumed before the
  # recursive reference. This must stay legal.
  #
  class BracketedRecursion < Parslet::Parser
    rule(:pair) { str('(') >> pair.maybe >> str(')') }
    root(:pair)
  end

  class RightRecursionWithConsume < Parslet::Parser
    rule(:list) { str('a') >> list | str('') }
    root(:list)
  end

  # Legal grammar where only one alternative branch consumes input.
  #
  class BranchThatConsumes < Parslet::Parser
    rule(:item) { str('a') | str('b') }
    rule(:start) { item.repeat }
    root(:start)
  end

  # A branch that matches empty makes the repetition body nullable, so
  # this one is genuinely broken.
  #
  class BranchThatCanBeEmpty < Parslet::Parser
    rule(:item) { str('a') | str('') }
    rule(:start) { item.repeat }
    root(:start)
  end

  # The nullable atom sits next to a consuming atom; the repetition body
  # as a whole consumes, so it is legal.
  #
  class NullableBeforeConsume < Parslet::Parser
    rule(:emptyish) { str('').maybe }
    rule(:start) { (emptyish >> str('z')).repeat }
    root(:start)
  end

  # Only one part of a branch consumes; still a legal repetition body.
  #
  class ConditionalConsume < Parslet::Parser
    rule(:item) { str('a') >> str('b').maybe | str('c') }
    rule(:start) { item.repeat }
    root(:start)
  end

  # Every part optional means the body can match empty.
  #
  class AllOptional < Parslet::Parser
    rule(:item) { str('a').maybe >> str('b').maybe }
    rule(:start) { item.repeat }
    root(:start)
  end

  class ConsumingRepetition < Parslet::Parser
    rule(:start) { str('a').repeat }
    root(:start)
  end

  class LookaheadRepetition < Parslet::Parser
    rule(:start) { str('x').present?.repeat }
    root(:start)
  end

  class NegativeLookaheadRepetition < Parslet::Parser
    rule(:start) { str('x').absent?.repeat }
    root(:start)
  end

  # A dynamic atom decides its parser at runtime. It must not be executed
  # by the checker and yields a warning rather than a firm error.
  #
  class DynamicRepetition < Parslet::Parser
    rule(:start) { dynamic { |source, context| str('x') }.repeat }
    root(:start)
  end

  describe ".check_grammar" do
    it "accepts a consuming repetition" do
      ConsumingRepetition.new.check_grammar.should be_ok
    end

    it "flags a repetition whose body is directly nullable" do
      report = DirectlyNullableRepetition.new.check_grammar
      report.should_not be_ok

      finding = report.errors.find do |candidate|
        candidate.kind == :nullable_repetition
      end
      finding.should_not be_nil
      finding.chain.should include(:start)
      finding.chain.should include(:maybe_x)
      finding.message.should =~ /empty string/
    end

    it "flags nullability that propagates indirectly through rules" do
      report = IndirectlyNullableRepetition.new.check_grammar
      finding = report.errors.find do |candidate|
        candidate.kind == :nullable_repetition
      end
      finding.should_not be_nil

      # The chain follows the user declared rules.
      finding.chain[0..3].should ==
        [:start, :alpha, :bravo, :charlie]
    end

    it "flags a cycle of rules that consumes nothing" do
      report = NonConsumingCycle.new.check_grammar
      finding = report.errors.find do |candidate|
        candidate.kind == :non_consuming_cycle
      end
      finding.should_not be_nil
      finding.chain.should include(:alpha)
      finding.chain.should include(:bravo)
      # The chain closes the loop.
      finding.chain.first.should == finding.chain.last
    end

    it "flags a rule that calls itself without consuming" do
      report = SelfCallingRule.new.check_grammar
      finding = report.errors.find do |candidate|
        candidate.kind == :non_consuming_cycle
      end
      finding.should_not be_nil
      finding.chain.uniq.should == [:alpha]
    end

    it "reports a multi rule cycle as a closed chain of rule names" do
      report = LongerCycle.new.check_grammar
      finding = report.errors.find do |candidate|
        candidate.kind == :non_consuming_cycle
      end
      finding.should_not be_nil
      finding.chain.first.should == finding.chain.last
      (finding.chain & [:bravo, :charlie]).sort.should ==
        [:bravo, :charlie]
    end

    it "flags optional left recursion reached before input is consumed" do
      report = OptionalLeftRecursion.new.check_grammar
      finding = report.errors.find do |candidate|
        candidate.kind == :non_consuming_cycle
      end
      finding.should_not be_nil
    end

    it "does not flag normal bracket recursion" do
      BracketedRecursion.new.check_grammar.should be_ok
    end

    it "does not flag right recursion that consumes a character first" do
      RightRecursionWithConsume.new.check_grammar.should be_ok
    end

    it "accepts an alternative where the chosen branch consumes" do
      BranchThatConsumes.new.check_grammar.should be_ok
    end

    it "flags an alternative with an empty branch inside a repetition" do
      report = BranchThatCanBeEmpty.new.check_grammar
      finding = report.errors.find do |candidate|
        candidate.kind == :nullable_repetition
      end
      finding.should_not be_nil
    end

    it "accepts a nullable part when the repetition body still consumes" do
      NullableBeforeConsume.new.check_grammar.should be_ok
    end

    it "accepts a branch that consumes only after an optional part" do
      ConditionalConsume.new.check_grammar.should be_ok
    end

    it "flags a repetition body made entirely of optional atoms" do
      AllOptional.new.check_grammar.should_not be_ok
    end

    it "flags a repetition made only of a lookahead" do
      LookaheadRepetition.new.check_grammar.should_not be_ok
      NegativeLookaheadRepetition.new.check_grammar.should_not be_ok
    end

    it "raises GrammarError from check_grammar!" do
      error = nil
      begin
        DirectlyNullableRepetition.new.check_grammar!
      rescue Parslet::StaticAnalysis::GrammarError => caught
        error = caught
      end
      error.should_not be_nil
      error.report.should_not be_ok
      error.message.should =~ /maybe_x/
    end

    it "does not raise from check_grammar! for a sound grammar" do
      expect {
        BracketedRecursion.new.check_grammar!
      }.not_to raise_error
    end
  end

  describe "dynamic atoms" do
    it "does not execute the dynamic block during the check" do
      executed = false
      parser = Class.new(Parslet::Parser) do
        rule(:start) do
          dynamic do |_source, _context|
            executed = true
            str('x')
          end.repeat
        end
        root(:start)
      end

      parser.new.check_grammar
      executed.should == false
    end

    it "reports a warning explaining that nullability is unconfirmed" do
      report = DynamicRepetition.new.check_grammar
      report.should be_ok
      warning = report.warnings.first
      warning.should_not be_nil
      warning.kind.should == :unconfirmed_repetition
      warning.message.should =~ /dynamic/
      warning.chain.should include(:start)
    end
  end

  describe "standalone atoms" do
    it "checks an atom that is not attached to a parser" do
      bad = str('').maybe.repeat
      bad.check_grammar.should_not be_ok

      good = str('a').repeat
      good.check_grammar.should be_ok
    end

    it "is available through Parslet.check_grammar" do
      Parslet.check_grammar(str('a').repeat).should be_ok
    end
  end

  describe "composed parsers" do
    class InnerGrammar < Parslet::Parser
      rule(:thing) { str('t').repeat }
      root(:thing)
    end

    class OuterGrammar < Parslet::Parser
      rule(:all) { InnerGrammar.new >> str('!') }
      root(:all)
    end

    it "follows references into a nested parser" do
      OuterGrammar.new.check_grammar.should be_ok
    end
  end
end
