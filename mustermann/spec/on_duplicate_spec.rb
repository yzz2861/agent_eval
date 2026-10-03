# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/expander'
require 'mustermann/set'

describe 'on_duplicate option' do
  context 'default behavior' do
    it 'rejects duplicate capture names' do
      expect { Mustermann.new('/accounts/:id/mirror/:id') }.to raise_error(Mustermann::CompileError, %r{can't use the same capture name twice})
    end

    it 'rejects duplicate capture names in fast-path eligible patterns' do
      # These patterns consist only of static segments and simple captures, so
      # they are eligible for the fast pattern pipeline, which must not silently
      # keep the last capture either.
      expect { Mustermann::Sinatra.new('/accounts/:id/mirror/:id') }.to raise_error(Mustermann::CompileError)
      expect { Mustermann::Rails.new('/accounts/:id/mirror/:id') }.to raise_error(Mustermann::CompileError)
    end

    it 'rejects duplicate capture names with on_duplicate: :error' do
      expect { Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :error) }.to raise_error(Mustermann::CompileError)
    end

    it 'rejects unknown strategies' do
      expect { Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :bogus) }.to raise_error(ArgumentError, /unsupported on_duplicate strategy/)
    end

    it 'keeps the existing behavior of regexp patterns with duplicate groups' do
      pattern = Mustermann.new(/(?<id>a)(?<id>b)?/, type: :regexp)
      expect(pattern.params('ab')).to eq('id' => ['a', 'b'])
      expect(pattern.params('a')).to eq('id' => ['a', nil])
    end
  end

  context 'with :check' do
    subject(:pattern) { Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :check) }

    it 'matches when all occurrences are equal' do
      expect(pattern.match('/accounts/1/mirror/1')).not_to be_nil
      expect(pattern.params('/accounts/1/mirror/1')).to eq('id' => '1')
    end

    it 'does not match when occurrences differ' do
      expect(pattern.match('/accounts/1/mirror/2')).to be_nil
      expect(pattern.params('/accounts/1/mirror/2')).to be_nil
      expect(pattern === '/accounts/1/mirror/2').to be(false)
      expect(pattern =~ '/accounts/1/mirror/2').to be_nil
      expect(pattern.peek_match('/accounts/1/mirror/2')).to be_nil
    end

    it 'returns 0 from =~ when occurrences are equal' do
      expect(pattern =~ '/accounts/1/mirror/1').to eq(0)
    end

    it 'compares occurrences after URI decoding' do
      expect(pattern.params('/accounts/x/mirror/%78')).to eq('id' => 'x')
      expect(pattern.params('/accounts/x/mirror/y')).to be_nil
    end

    it 'preserves the raw captures of each occurrence' do
      match = pattern.match('/accounts/x/mirror/%78')
      expect(match.captures).to eq(['x', '%78'])
      expect(match.params).to eq('id' => 'x')
      expect(match.names).to eq(['id'])
    end

    it 'compares occurrences after param conversion' do
      pattern = Mustermann.new('/accounts/:id/mirror/:id', capture: { id: Integer }, on_duplicate: :check)
      expect(pattern.params('/accounts/01/mirror/1')).to eq('id' => 1)
      expect(pattern.params('/accounts/1/mirror/2')).to be_nil
    end

    context 'with an optional occurrence' do
      subject(:pattern) { Mustermann.new('/accounts/:id(/mirror/:id)?', on_duplicate: :check) }

      it 'matches when the optional occurrence is absent' do
        expect(pattern.params('/accounts/1')).to eq('id' => '1')
      end

      it 'matches when the optional occurrence is equal' do
        expect(pattern.params('/accounts/1/mirror/1')).to eq('id' => '1')
      end

      it 'does not match when the optional occurrence differs' do
        expect(pattern.params('/accounts/1/mirror/2')).to be_nil
      end

      it 'assigns nil when all occurrences are absent' do
        pattern = Mustermann.new('/a(/:id)?/b(/:id)?', on_duplicate: :check)
        expect(pattern.params('/a/b')).to eq('id' => nil)
      end
    end

    context 'with constrained captures' do
      it 'applies the capture option to all occurrences' do
        pattern = Mustermann.new('/accounts/:id/mirror/:id', capture: { id: /\d+/ }, on_duplicate: :check)
        expect(pattern.params('/accounts/1/mirror/1')).to eq('id' => '1')
        expect(pattern.params('/accounts/1/mirror/2')).to be_nil
        expect(pattern.params('/accounts/a/mirror/a')).to be_nil
      end
    end

    it 'works with the rails pattern type' do
      pattern = Mustermann.new('/accounts/:id/mirror/:id', type: :rails, on_duplicate: :check)
      expect(pattern.params('/accounts/1/mirror/1')).to eq('id' => '1')
      expect(pattern.params('/accounts/1/mirror/2')).to be_nil
    end
  end
  context 'with :collect' do
    subject(:pattern) { Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :collect) }

    it 'collects all occurrences in order' do
      expect(pattern.params('/accounts/1/mirror/2')).to eq('id' => ['1', '2'])
    end

    it 'collects URI-decoded values while preserving raw captures' do
      match = pattern.match('/accounts/x/mirror/%79')
      expect(match.params).to eq('id' => ['x', 'y'])
      expect(match.captures).to eq(['x', '%79'])
    end

    it 'skips absent optional occurrences' do
      pattern = Mustermann.new('/accounts/:id(/mirror/:id)?', on_duplicate: :collect)
      expect(pattern.params('/accounts/1')).to eq('id' => ['1'])
      expect(pattern.params('/accounts/1/mirror/2')).to eq('id' => ['1', '2'])
    end

    it 'assigns an empty array when all occurrences are absent' do
      pattern = Mustermann.new('/a(/:id)?/b(/:id)?', on_duplicate: :collect)
      expect(pattern.params('/a/b')).to eq('id' => [])
    end

    it 'applies the capture option to all occurrences' do
      pattern = Mustermann.new('/accounts/:id/mirror/:id', capture: { id: /\d+/ }, on_duplicate: :collect)
      expect(pattern.params('/accounts/1/mirror/2')).to eq('id' => ['1', '2'])
      expect(pattern.params('/accounts/a/mirror/1')).to be_nil
    end
  end

  context 'expanding' do
    context 'with :check' do
      subject(:pattern) { Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :check) }

      it 'expands a scalar to all occurrences' do
        expect(pattern.expand(id: 'x')).to eq('/accounts/x/mirror/x')
      end

      it 'escapes the scalar before expanding' do
        expect(pattern.expand(id: 'a b')).to eq('/accounts/a%20b/mirror/a%20b')
      end

      it 'expands a list of equal values' do
        expect(pattern.expand(id: %w[x x])).to eq('/accounts/x/mirror/x')
      end

      it 'raises for unequal list values, naming the occurrence' do
        expect { pattern.expand(id: %w[x y]) }.to raise_error(Mustermann::ExpandError, /occurrence 2 is "y" and occurrence 1 is "x"/)
      end

      it 'raises when the list length does not match the occurrence count' do
        expect { pattern.expand(id: %w[x x x]) }.to raise_error(Mustermann::ExpandError, /with 3 values, pattern expects 2 occurrences/)
      end

      context 'with an optional occurrence' do
        subject(:pattern) { Mustermann.new('/accounts/:id(/mirror/:id)?', on_duplicate: :check) }

        it 'expands a scalar to the shortest form' do
          expect(pattern.expand(id: 'x')).to eq('/accounts/x')
        end

        it 'expands an equal list to the long form' do
          expect(pattern.expand(id: %w[x x])).to eq('/accounts/x/mirror/x')
        end
      end
    end

    context 'with :collect' do
      subject(:pattern) { Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :collect) }

      it 'expands a list in occurrence order' do
        expect(pattern.expand(id: %w[a b])).to eq('/accounts/a/mirror/b')
      end

      it 'raises for a scalar' do
        expect { pattern.expand(id: 'a') }.to raise_error(Mustermann::ExpandError, /cannot expand :id with a single value/)
      end

      it 'raises when the list length does not match the occurrence count' do
        expect { pattern.expand(id: %w[a b c]) }.to raise_error(Mustermann::ExpandError, /with 3 values, pattern expects 2 occurrences/)
      end

      context 'with an optional occurrence' do
        subject(:pattern) { Mustermann.new('/accounts/:id(/mirror/:id)?', on_duplicate: :collect) }

        it 'expands a single value to the short form' do
          expect(pattern.expand(id: %w[a])).to eq('/accounts/a')
        end

        it 'expands two values to the long form' do
          expect(pattern.expand(id: %w[a b])).to eq('/accounts/a/mirror/b')
        end
      end
    end

    context 'with an Expander object' do
      it 'forwards the option to patterns' do
        expander = Mustermann::Expander.new(on_duplicate: :check)
        expander << '/accounts/:id/mirror/:id'
        expect(expander.expand(id: 'x')).to eq('/accounts/x/mirror/x')
        expect(expander.expandable?(id: 'x')).to be(true)
      end

      it 'reads the option from pattern instances' do
        expander = Mustermann::Expander.new
        expander << Mustermann.new('/accounts/:id/mirror/:id', on_duplicate: :collect)
        expect(expander.expand(id: %w[a b])).to eq('/accounts/a/mirror/b')
      end

      it 'raises on conflicting strategies for the same capture name' do
        expander = Mustermann::Expander.new
        expander << Mustermann.new('/a/:id/b/:id', on_duplicate: :check)
        expect { expander << Mustermann.new('/c/:id/d/:id', on_duplicate: :collect) }.to raise_error(ArgumentError, /conflicting on_duplicate strategies/)
      end

      it 'raises when no expansion fits the given keys' do
        expander = Mustermann::Expander.new(on_duplicate: :check)
        expander << '/accounts/:id/mirror/:id'
        expect { expander.expand(id: 'x', other: 'y') }.to raise_error(Mustermann::ExpandError, /cannot expand with keys/)
      end
    end
  end

  # Both strategies are exercised against the linear matcher (before the set's
  # trie optimization) and the trie matcher (after optimization); the results
  # must be identical.
  context 'in a pattern set' do
    shared_examples 'a duplicate-aware set' do |use_trie:|
      context 'with :check' do
        subject(:set) { Mustermann::Set.new(on_duplicate: :check, use_trie: use_trie, use_cache: false) }

        before do
          set.add('/accounts/:id/mirror/:id', :mirror)
          set.add('/accounts/:id(/copy/:id)?/end', :optional)
        end

        it 'matches when occurrences are equal' do
          match = set.match('/accounts/1/mirror/1')
          expect(match.value).to eq(:mirror)
          expect(match.params).to eq('id' => '1')
        end

        it 'does not match when occurrences differ' do
          expect(set.match('/accounts/1/mirror/2')).to be_nil
        end

        it 'matches the optional form' do
          expect(set.match('/accounts/1/end').params).to eq('id' => '1')
          expect(set.match('/accounts/1/copy/1/end').params).to eq('id' => '1')
          expect(set.match('/accounts/1/copy/2/end')).to be_nil
        end

        it 'compares occurrences after URI decoding' do
          expect(set.match('/accounts/x/mirror/%78').params).to eq('id' => 'x')
        end

        it 'assigns nil when all occurrences are absent' do
          set = Mustermann::Set.new(on_duplicate: :check, use_trie: use_trie, use_cache: false)
          set.add('/a(/:id)?/b(/:id)?', :absent)
          expect(set.match('/a/b').params).to eq('id' => nil)
        end
      end

      it 'expands patterns in the set' do
        set = Mustermann::Set.new(on_duplicate: :check, use_trie: use_trie, use_cache: false)
        set.add('/accounts/:id/mirror/:id', :mirror)
        expect(set.expand(id: 'x')).to eq('/accounts/x/mirror/x')
      end

      context 'with :collect' do
        subject(:set) { Mustermann::Set.new(on_duplicate: :collect, use_trie: use_trie, use_cache: false) }

        before do
          set.add('/accounts/:id/mirror/:id', :mirror)
          set.add('/accounts/:id(/copy/:id)?/end', :optional)
        end

        it 'collects all occurrences in order' do
          match = set.match('/accounts/1/mirror/2')
          expect(match.value).to eq(:mirror)
          expect(match.params).to eq('id' => ['1', '2'])
        end

        it 'skips absent optional occurrences' do
          expect(set.match('/accounts/1/end').params).to eq('id' => ['1'])
          expect(set.match('/accounts/1/copy/2/end').params).to eq('id' => ['1', '2'])
        end

        it 'collects URI-decoded values' do
          expect(set.match('/accounts/x/mirror/%79').params).to eq('id' => ['x', 'y'])
        end

        it 'assigns an empty array when all occurrences are absent' do
          set = Mustermann::Set.new(on_duplicate: :collect, use_trie: use_trie, use_cache: false)
          set.add('/a(/:id)?/b(/:id)?', :absent)
          expect(set.match('/a/b').params).to eq('id' => [])
        end
      end

      it 'expands patterns in the set' do
        set = Mustermann::Set.new(on_duplicate: :collect, use_trie: use_trie, use_cache: false)
        set.add('/accounts/:id/mirror/:id', :mirror)
        expect(set.expand(id: %w[a b])).to eq('/accounts/a/mirror/b')
      end

      it 'does not use the regex-free fast path for constrained captures' do
        set = Mustermann::Set.new(capture: :digit, use_trie: use_trie, use_cache: false)
        set.add('/accounts/:id', :show)
        expect(set.match('/accounts/123').params).to eq('id' => '123')
        expect(set.match('/accounts/abc')).to be_nil
      end
    end

    context 'with the linear matcher (before optimization)' do
      include_examples 'a duplicate-aware set', use_trie: false
    end

    context 'with the trie matcher (after optimization)' do
      include_examples 'a duplicate-aware set', use_trie: true
    end

    it 'produces the same results before and after explicit optimization' do
      %i[check collect].each do |strategy|
        linear = Mustermann::Set.new(on_duplicate: strategy, use_trie: false, use_cache: false)
        trie   = Mustermann::Set.new(on_duplicate: strategy, use_trie: true, use_cache: false)
        [linear, trie].each do |set|
          set.add('/accounts/:id/mirror/:id', :mirror)
          set.add('/accounts/:id(/copy/:id)?/end', :optional)
          set.optimize!
        end
        %w[/accounts/1/mirror/1 /accounts/1/mirror/2 /accounts/1/end /accounts/1/copy/1/end /accounts/1/copy/2/end /accounts/x/mirror/%78].each do |string|
          expect(trie.match(string)&.params).to eq(linear.match(string)&.params)
        end
      end
    end
  end
end
