require 'spec_helper'

describe Parslet::Atoms::Cut do
  include Parslet

  def fails(parslet, input, options={})
    catch_failed_parse { parslet.parse(input, options) }
  end

  it 'is available through the Parslet dsl' do
    cut.should be_instance_of(described_class)
    cut.inspect.should == 'cut'
  end

  it 'matches always, consuming no input' do
    (str('a') >> cut >> str('b')).parse('ab').should == 'ab'
  end

  context 'inside a choice' do
    let(:committed)   { (str('a') >> cut >> str('b')) | str('ac') }
    let(:uncommitted) { (str('a') >> str('b')) | str('ac') }

    it 'makes a later failure final for that choice' do
      fails(committed, 'ac').should_not be_nil
    end
    it 'falls back to other alternatives without a commit point' do
      uncommitted.parse('ac').should == 'ac'
    end
    it 'still tries other alternatives when failing before the cut' do
      parser = (str('x') >> cut >> str('b')) | str('ac')
      parser.parse('ac').should == 'ac'
    end
    it 'commits only its own choice, not the enclosing one' do
      inner = (str('a') >> cut >> str('b')) | str('a')
      outer = (str('x') >> inner >> str('?')) | str('xa?')

      # inner choice fails committed, outer choice remains free
      outer.parse('xa?').should == 'xa?'
    end
    it 'prevents the inner choice from falling back' do
      inner = (str('a') >> cut >> str('b')) | str('a')
      fails(inner, 'ac', prefix: true).should_not be_nil
    end
  end

  context 'inside maybe' do
    let(:committed)   { ((str('a') >> cut >> str('b')).maybe >> str('a') >> str('c')) | str('ax') }
    let(:uncommitted) { ((str('a') >> str('b')).maybe >> str('a') >> str('c')) | str('ax') }

    it 'propagates the failure instead of swallowing it' do
      fails(committed, 'ac').should_not be_nil
    end
    it 'is optional without a commit point' do
      uncommitted.parse('ac').should == 'ac'
    end
    it 'commits the enclosing choice through the maybe' do
      fails(committed, 'ax').should_not be_nil
      uncommitted.parse('ax').should == 'ax'
    end
  end

  context 'inside repeat' do
    it 'propagates the failure instead of ending the repetition' do
      parser = ((str('a') >> cut >> str('b')).repeat(1) | str('ac'))
      fails(parser, 'ac').should_not be_nil
    end
    it 'ends the repetition normally without a commit point' do
      parser = ((str('a') >> str('b')).repeat(1) | str('ac'))
      parser.parse('ac').should == 'ac'
    end
    it 'absorbs commits that were resolved inside the repeated choice' do
      body = (str('a') >> cut >> str('b')) | str('c')
      parser = body.repeat(1) >> str('a') >> str('d')
      # 'a' commits the inner choice and fails there; the repetition just
      # ends, the commit does not escape its own choice.
      parser.parse('cad').should == 'cad'
    end
    it 'has no effect without an enclosing choice' do
      parser = (str('a') >> cut >> str('b')).maybe >> str('a') >> str('c')
      parser.parse('ac').should == 'ac'
    end
  end

  context 'inside nested rules' do
    let(:parser_class) do
      Class.new(Parslet::Parser) do
        rule(:filename)     { match['0-9'].repeat(1) }
        rule(:include_stmt) { str('include') >> str(' ') >> cut >> filename }
        rule(:statement)    { include_stmt | str('includes') }
        root(:statement)
      end
    end
    let(:parser) { parser_class.new }

    it 'commits the choice that encloses the rule call' do
      fails(parser, 'include x').should_not be_nil
    end
    it 'falls back when failing before the commit point' do
      parser.parse('includes').should == 'includes'
    end
    it 'points the error tree at the real problem' do
      cause = fails(parser, 'include ')
      cause.ascii_tree.should include('Expected at least 1 of [0-9]')
      cause.ascii_tree.should_not include('Expected one of')
    end
  end

  context 'inside positive lookahead' do
    it 'does not leak the commit into the enclosing parse' do
      parser = (str('a') >> (cut >> str('b')).present? >> str('c')) | str('abd')
      parser.parse('abd').should == 'abd'
    end
    it 'still commits choices inside the lookahead' do
      parser = ((str('a') >> cut >> str('b')) | str('ac')).present? >> str('ac')
      fails(parser, 'ac').should_not be_nil
    end
  end

  context 'inside negative lookahead' do
    it 'does not leak the commit into the enclosing parse' do
      parser = (str('a') >> (cut >> str('b')).absent? >> str('c')) | str('ab')
      parser.parse('ab').should == 'ab'
    end
  end

  context 'packrat cache interaction' do
    it 'is not cached itself' do
      cut.cached?.should == false
      str('a').cached?.should == true
    end
    it 'makes containing atoms uncacheable' do
      (str('a') >> cut >> str('b')).cached?.should == false
      (str('a') >> str('b')).cached?.should == true
      ((str('a') >> cut >> str('b')) | str('c')).cached?.should == false
      (str('a') >> cut >> str('b')).repeat.cached?.should == false
      (cut >> str('b')).present?.cached?.should == false
    end
    it 'terminates on recursive rules' do
      parser_class = Class.new(Parslet::Parser) do
        rule(:rec) { str('x') >> rec.maybe >> cut | str('y') }
        root(:rec)
      end
      parser_class.new.root.has_cut?.should == true
    end
    it 'replays no committed failure from the cache' do
      s = str('a') >> cut >> str('b')
      parser = (s >> str('z')).maybe >> (s | str('ac'))

      # s fails committed once inside maybe; when it is applied again at
      # the same position, the commit must happen again - serving s from
      # the packrat cache would silently drop it.
      fails(parser, 'ac').should_not be_nil
    end
  end

  context 'reusing the same parser' do
    let(:parser_class) do
      Class.new(Parslet::Parser) do
        rule(:filename)     { match['0-9'].repeat(1) }
        rule(:include_stmt) { str('include') >> str(' ') >> cut >> filename }
        rule(:statement)    { include_stmt | str('includes') }
        root(:statement)
      end
    end
    let(:parser) { parser_class.new }

    it 'leaves no commit state behind between parses' do
      first  = fails(parser, 'include ')
      second = fails(parser, 'include ')

      second.ascii_tree.should == first.ascii_tree
      parser.parse('include 42').should == 'include 42'
      fails(parser, 'include ').ascii_tree.should == first.ascii_tree
    end
  end
end
