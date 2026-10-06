require 'spec_helper'

describe 'commit points (cuts)' do
  include Parslet

  def leaf_messages(cause)
    kids = cause.children
    if kids.empty?
      [Array(cause.message).join]
    else
      kids.flat_map { |child| leaf_messages(child) }
    end
  end

  def message_text(cause)
    Array(cause.message).join
  end

  describe Parslet::Atoms::Cut do
    it 'matches the empty string without consuming input' do
      atom = Parslet::Atoms::Cut.new
      atom.parse('', :prefix => true).should == nil
      atom.parse('abc', :prefix => true).should == nil
      # It consumes nothing: input after the cut is untouched.
      (Parslet::Atoms::Cut.new >> str('abc')).parse('abc').should == 'abc'
    end

    it 'is never cached, so the side effect runs on every application' do
      Parslet::Atoms::Cut.new.cached?.should == false
    end

    it 'prints as the cut operator' do
      Parslet::Atoms::Cut.new.to_s.should == "\u2191"
    end
  end

  describe 'DSL #cut' do
    it 'chains after a parslet' do
      atom = str('a').cut
      atom.should be_a(Parslet::Atoms::Sequence)
      atom.parse('a').should == 'a'
    end

    it 'is also available as Parslet.cut' do
      atom = str('a') >> Parslet.cut >> str('b')
      atom.parse('ab').should == 'ab'
    end
  end

  describe 'inside non-cached atoms' do
    it 'commits through a dynamic block' do
      grammar = dynamic { str('a') >> cut >> str('b') } | str('a')

      grammar.parse('ab').should == 'ab'
      cause = catch_failed_parse { grammar.parse('ax') }
      message_text(cause).should =~ /Failed to match sequence/
    end
  end

  context 'the include statement example' do
    # 'include <file>' vs. a bare identifier. Once the keyword and space
    # have been seen the statement type is known.
    def build(with_cut)
      keyword    = str('include') >> str(' ')
      keyword    = keyword.cut if with_cut
      keyword    = keyword >> match['[:alnum:]'].repeat(1).as(:file)
      identifier = match['[:alnum:]'].repeat(1).as(:name)

      keyword | identifier
    end

    let(:without_cut) { build(false) }
    let(:with_cut)    { build(true)  }

    it 'parses both statements with and without the cut' do
      without_cut.parse('include foo').should == { :file => 'foo' }
      without_cut.parse('other').should == { :name => 'other' }
      with_cut.parse('include foo').should == { :file => 'foo' }
      with_cut.parse('other').should == { :name => 'other' }
    end

    it 'does not commit before the cut is reached' do
      with_cut.parse('includx').should == { :name => 'includx' }
    end

    it 'without the cut: falls back and reports every alternative' do
      cause = catch_failed_parse { without_cut.parse('include ') }

      message_text(cause).should =~ /Expected one of/
      cause.children.size.should == 2
      message_text(cause).should =~ /Expected one of/
      cause.children.size.should == 2
    end

    it 'with the cut: reports the committed branch failure only' do
      cause = catch_failed_parse { with_cut.parse('include ') }

      message_text(cause).should =~ /Failed to match sequence/
      cause.pos.bytepos.should == 8
      cause.children.size.should == 1
      leaf_messages(cause).join.should_not =~ /Expected one of/
    end
  end

  describe 'scope of a cut' do
    it 'stops later alternatives of its own choice' do
      grammar = (str('a').cut >> str('b')) | str('a')

      grammar.parse('ab').should == 'ab'
      expect { grammar.parse('ac') }.to \
        raise_error(Parslet::ParseFailed)
      cause = catch_failed_parse { grammar.parse('ac') }
      message_text(cause).should =~ /Failed to match sequence/
    end

    it 'is contained by a nested choice' do
      inner = (str('a').cut >> str('b')) | str('x')
      outer = (inner >> str('!')) | str('a')

      outer.parse('ab!').should == 'ab!'
      # Inner branch 'a' commits the *inner* choice and fails on '!';
      # the outer choice still gets to try its fallback 'a'.
      outer.parse('a').should == 'a'
    end

    it 'does not commit when the committed branch ultimately succeeds' do
      grammar = (str('a').cut >> str('b')) | str('c')
      grammar.parse('ab').should == 'ab'
      # A second, failing use of the choice sees normal backtracking for a
      # fresh input.
      grammar.parse('c').should == 'c'
    end
  end

  describe 'inside .maybe (0/1 repetition)' do
    it 'forgets a cut from a failed maybe and keeps the outer fallback' do
      optional = (str('ab').cut >> str('c')).maybe
      grammar  = (optional >> str('z')) | str('ab')

      # Body reaches 'ab', commits, then cannot match 'c'. The maybe fails
      # after its cut; the outer fallback must still run.
      grammar.parse('ab').should == 'ab'
      grammar.parse('abcz').should == 'abcz'
    end
  end

  describe 'inside repetition' do
    it 'forgets a cut from the failing final iteration' do
      body = (str('k ').cut >> str('v')) | str('z')
      grammar = (body.repeat >> str('!')) | str('k v')

      # One iteration succeeds; the next attempt commits and fails at end
      # of input, ending the repetition. '!' then fails and the outer
      # fallback must still be attempted.
      grammar.parse('k v').should == 'k v'
    end

    it 'keeps behaving normally with successful committed iterations' do
      body = (str('k ').cut >> str('v')) | str('z')
      grammar = body.repeat(1) >> str('!')

      grammar.parse('k vk v!').should == 'k vk v!'
    end
  end

  describe 'inside lookaheads' do
    it 'keeps a positive lookahead cut inside the lookahead' do
      ahead = ((str('a').cut >> str('b')) | str('c')).present?
      grammar = (ahead >> str('d')) | str('ab')

      # Lookahead succeeds speculatively on 'ab'; 'd' then fails. The cut
      # must not have committed the outer fallback.
      grammar.parse('ab').should == 'ab'
    end

    it 'keeps a negative lookahead cut inside the lookahead' do
      ahead = ((str('a').cut >> str('b')) | str('c')).absent?
      grammar = (ahead >> str('d')) | str('ab')

      # The inner choice succeeds inside the negative lookahead, so the
      # lookahead itself fails; outer fallback must still run.
      grammar.parse('ab').should == 'ab'
      # Neither inner branch matches: lookahead succeeds and 'd' wins.
      grammar.parse('d').should == 'd'
    end
  end

  describe 'nested rules' do
    let(:grammar) do
      Class.new(Parslet::Parser) do
        root(:stmt)
        rule(:stmt) { include_stmt | name }
        rule(:include_stmt) do
          str('include') >> str(' ').cut >> filename.as(:file)
        end
        rule(:filename) { match['[:alnum:]'].repeat(1) }
        rule(:name) { match['[:alnum:]'].repeat(1).as(:name) }
      end.new
    end

    it 'commits across rule boundaries' do
      cause = catch_failed_parse { grammar.parse('include ') }
      cause.pos.bytepos.should == 8
      message_text(cause).should =~ /Failed to match sequence/
      leaf_messages(cause).join.should_not =~ /Expected one of/
    end

    it 'parses valid input through rules' do
      grammar.parse('include xrb').should == { :file => 'xrb' }
      grammar.parse('thing').should == { :name => 'thing' }
    end
  end

  describe 'reusing one parser instance' do
    let(:grammar) do
      Class.new(Parslet::Parser) do
        root(:stmt)
        rule(:stmt) { include_stmt | name }
        rule(:include_stmt) do
          str('include') >> str(' ').cut >> filename.as(:file)
        end
        rule(:filename) { match['[:alnum:]'].repeat(1) }
        rule(:name) { match['[:alnum:]'].repeat(1).as(:name) }
      end.new
    end

    it 'has no residual committed state between parses' do
      tree1 = catch_failed_parse { grammar.parse('include ') }.ascii_tree
      grammar.parse('other').should == { :name => 'other' }
      tree2 = catch_failed_parse { grammar.parse('include ') }.ascii_tree

      tree2.should == tree1
    end

    it 'survives many mixed parses on the same instance' do
      30.times do
        grammar.parse('include ok').should == { :file => 'ok' }
        grammar.parse('name7').should == { :name => 'name7' }
        expect { grammar.parse('include ') }.to \
          raise_error(Parslet::ParseFailed)
      end
    end
  end

  describe 'packrat caching' do
    it 'replays a committed failure from a cache entry' do
      atom = (str('a').cut >> str('b')) | str('c')
      grammar = atom >> atom

      grammar.parse('abab').should == 'abab'
      cause = catch_failed_parse { grammar.parse('abax') }
      cause.pos.bytepos.should == 2
      message_text(cause).should =~ /Failed to match sequence/
    end

    it 'does not replay a cut from a voided speculative attempt' do
      # The body commits on its second position inside a repetition; the
      # failing final iteration caches a result that carries the cut. That
      # cached failure is observed again after the repetition ended, and
      # must not commit the outer choice.
      body = (str('k ').cut >> str('v')) | str('z')
      grammar = (body.repeat >> str('!')) | str('k v')

      grammar.parse('k v').should == 'k v'
    end
  end
end
