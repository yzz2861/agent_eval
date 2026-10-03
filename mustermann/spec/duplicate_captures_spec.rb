# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/regular'
require 'mustermann/set'

describe 'duplicate_captures' do
  describe 'default behavior' do
    example 'still rejects repeated capture names' do
      expect { Mustermann.new('/accounts/:id/mirror/:id') }.
        to raise_error(Mustermann::CompileError, "can't use the same capture name twice: \"/accounts/:id/mirror/:id\"")
    end

    example 'still rejects repeated names with explicit :raise' do
      expect { Mustermann.new('/:a/:a', duplicate_captures: :raise) }.
        to raise_error(Mustermann::CompileError, "can't use the same capture name twice: \"/:a/:a\"")
    end

    example 'rejects unknown strategies' do
      expect { Mustermann.new('/:a/:a', duplicate_captures: :collect_stuff) }.
        to raise_error(ArgumentError, /unsupported value :collect_stuff for duplicate_captures/)
    end
  end

  describe ':equal strategy' do
    subject(:pattern) { Mustermann.new('/accounts/:id/mirror/:id', duplicate_captures: :equal) }

    example('matches when decoded values are equal') { should be === '/accounts/42/mirror/42' }
    example('does not match when values differ')   { should_not be === '/accounts/42/mirror/17' }

    example 'exposes a scalar param' do
      expect(pattern.params('/accounts/42/mirror/42')).to eq('id' => '42')
    end

    example 'compares decoded values, not raw captures' do
      expect(pattern.params('/accounts/%32/mirror/2')).to eq('id' => '2')
      expect(pattern.match('/accounts/%32/mirror/2')).to be_a(Mustermann::Match)
    end

    example 'keeps the raw range of every occurrence' do
      match = pattern.match('/accounts/42/mirror/42')
      expect(match.capture_ranges.fetch('id')).to eq([10...12, 20...22])
      expect(match.string[match.capture_ranges.fetch('id').first]).to eq('42')
      expect(match.match_data).to be_a(MatchData)
    end

    example 'keeps raw ranges while comparing percent-encoded values' do
      match = pattern.match('/accounts/%32/mirror/2')
      expect(match.capture_ranges.fetch('id')).to eq([10...13, 21...22])
      expect(match.string[match.capture_ranges.fetch('id').first]).to eq('%32')
    end

    example 'does not match differing decoded values' do
      expect(pattern.params('/accounts/4%32/mirror/17')).to be_nil
      expect(pattern.match('/accounts/4%32/mirror/17')).to be_nil
      expect(pattern =~ '/accounts/4%32/mirror/17').to be_nil
    end

    example 'expands scalars into every occurrence' do
      expect(pattern.expand(id: '9')).to eq('/accounts/9/mirror/9')
    end

    example 'expands equal lists' do
      expect(pattern.expand(id: ['9', '9'])).to eq('/accounts/9/mirror/9')
    end

    example 'rejects unequal lists and points at the occurrences' do
      expect { pattern.expand(id: %w[1 2]) }.
        to raise_error(Mustermann::ExpandError, /occurrences 1 vs 2 of :id/)
    end

    example 'rejects lists of the wrong size' do
      expect { pattern.expand(id: %w[1 2 3]) }.
        to raise_error(Mustermann::ExpandError, /expected 2 value.s. for 2 occurrence.s. of :id, got 3/)
    end
  end

  describe ':collect strategy' do
    subject(:pattern) { Mustermann.new('/accounts/:id/mirror/:id', duplicate_captures: :collect) }

    example('matches regardless of the values') { should be === '/accounts/42/mirror/17' }

    example 'collects values in order of appearance' do
      expect(pattern.params('/accounts/42/mirror/17')).to eq('id' => %w[42 17])
    end

    example 'collects decoded values' do
      expect(pattern.params('/accounts/%32/mirror/2')).to eq('id' => %w[2 2])
    end

    example 'keeps the raw range of every occurrence' do
      match = pattern.match('/accounts/42/mirror/17')
      expect(match.capture_ranges.fetch('id')).to eq([10...12, 20...22])
    end

    example 'expands lists in order' do
      expect(pattern.expand(id: %w[1 2])).to eq('/accounts/1/mirror/2')
    end

    example 'expands a scalar into every occurrence' do
      expect(pattern.expand(id: '7')).to eq('/accounts/7/mirror/7')
    end

    example 'rejects lists of the wrong size' do
      expect { pattern.expand(id: %w[1 2 3]) }.
        to raise_error(Mustermann::ExpandError, /expected 2 value.s. for 2 occurrence.s. of :id, got 3/)
    end
  end

  describe 'absent optional occurrences' do
    subject(:pattern) { Mustermann.new('/a/:x(/b/:x)?', duplicate_captures: strategy) }

    context 'with :collect' do
      let(:strategy) { :collect }

      example 'collects only present occurrences' do
        expect(pattern.params('/a/1')).to eq('x' => ['1'])
        expect(pattern.params('/a/1/b/2')).to eq('x' => %w[1 2])
      end

      example 'records nil ranges for absent occurrences' do
        expect(pattern.match('/a/1').capture_ranges.fetch('x')).to eq([3...4, nil])
        expect(pattern.match('/a/1/b/2').capture_ranges.fetch('x')).to eq([3...4, 7...8])
      end

      example 'expands present and absent variants' do
        expect(pattern.expand(x: '1')).to eq('/a/1')
        expect(pattern.expand(x: %w[1 2])).to eq('/a/1/b/2')
      end

      example 'rejects a list when the optional occurrence is absent' do
        expect { pattern.expand(x: %w[1 2 3]) }.
          to raise_error(Mustermann::ExpandError, /expected 2 value.s. for 2 occurrence.s. of :x, got 3/)
      end

    end

    context 'with :equal' do
      let(:strategy) { :equal }

      example 'matches with one occurrence absent' do
        expect(pattern.params('/a/1')).to eq('x' => '1')
        expect(pattern === '/a/1').to be(true)
      end

      example 'matches when present occurrences are equal' do
        expect(pattern.params('/a/1/b/1')).to eq('x' => '1')
      end

      example 'does not match when present occurrences differ' do
        expect(pattern.params('/a/1/b/2')).to be_nil
        expect(pattern === '/a/1/b/2').to be(false)
      end

      example 'records nil ranges for absent occurrences' do
        expect(pattern.match('/a/1').capture_ranges.fetch('x')).to eq([3...4, nil])
      end
    end
  end

  describe 'constrained captures' do
    example 'applies the constraint to every occurrence' do
      pattern = Mustermann.new('/:id/:id', type: :sinatra, capture: { id: /\d+/ }, duplicate_captures: :collect)
      expect(pattern.params('/1/2')).to eq('id' => %w[1 2])
      expect(pattern === '/a/2').to be(false)
    end
  end

  describe 'regular expression patterns' do
    example 'keeps the built-in duplicate group behavior unchanged' do
      pattern = Mustermann.new(/(?<a>[0-9]+)(?: and (?<a>[0-9]+))?/, type: :regexp)
      expect(pattern.params('12 and 34')).to eq('a' => %w[12 34])
      expect(pattern.params('12')).to eq('a' => '12')
    end
  end

  describe Mustermann::Set do
    def build_set(strategy, trie)
      set = Mustermann::Set.new(use_trie: trie, use_cache: false, duplicate_captures: strategy)
      set.add('/accounts/:id/mirror/:id', :mirror)
      set.add('/a/:x(/b/:x)?', :optional)
      set
    end

    {linear: false, trie: true}.each do |mode, trie|
      context "with #{mode} matching" do
        [:equal, :collect].each do |strategy|
          context strategy.to_s do
            subject(:set) { build_set(strategy, trie) }

            example 'collects/validates required occurrences' do
              equal   = set.match('/accounts/42/mirror/42')
              unequal = set.match('/accounts/42/mirror/17')
              if strategy == :equal
                expect(equal.params).to eq('id' => '42')
                expect(unequal).to be_nil
              else
                expect(equal.params).to eq('id' => %w[42 42])
                expect(unequal.params).to eq('id' => %w[42 17])
              end
            end

            example 'handles absent optional occurrences' do
              match = set.match('/a/1')
              expect(match.value).to eq(:optional)
              expected = strategy == :equal ? '1' : ['1']
              expect(match.params).to eq('x' => expected)
              expect(match.capture_ranges.fetch('x')).to eq([3...4, nil])
            end

            example 'handles present optional occurrences' do
              equal   = set.match('/a/1/b/1')
              unequal = set.match('/a/1/b/2')
              expect(equal.params.fetch('x')).to eq(strategy == :equal ? '1' : %w[1 1])
              expect(equal.capture_ranges.fetch('x')).to eq([3...4, 7...8])
              if strategy == :equal
                expect(unequal).to be_nil
              else
                expect(unequal.params.fetch('x')).to eq(%w[1 2])
              end
            end

            example 'peeks consistently' do
              prefixed = '/a/1/b/2/rest'
              match = set.peek_match(prefixed)
              if strategy == :equal
                expect(match).to be_nil
              else
                expect(match.params.fetch('x')).to eq(%w[1 2])
                expect(match.post_match).to eq('/rest')
              end
            end

            example 'expands from the set' do
              expect(set.expand(:mirror, id: %w[7 8])).to eq('/accounts/7/mirror/8') if strategy == :collect
              expect(set.expand(:mirror, id: '7')).to eq('/accounts/7/mirror/7')
            end
          end
        end
      end
    end

    example 'optimizes without changing results' do
      paths = ['/accounts/42/mirror/42', '/accounts/42/mirror/17', '/a/1', '/a/1/b/2', '/a/1/b/1']
      [:equal, :collect].each do |strategy|
        linear = build_set(strategy, false)
        trie   = build_set(strategy, true)
        paths.each do |path|
          a = linear.match(path)
          b = trie.match(path)
          expect(a&.params).to eq(b&.params)
          expect(a&.capture_ranges).to eq(b&.capture_ranges)
        end
      end
    end

    example 'normalizes equal scalars on the identity fast path too' do
      set = Mustermann::Set.new(use_trie: true, use_cache: false, duplicate_captures: :equal)
      set.add('/e/:v/:v', :e)
      expect(set.match('/e/9/9').params).to eq('v' => '9')
      expect(set.match('/e/9/8')).to be_nil
    end

    example 'fills in empty arrays for absent collects on the identity path' do
      set = Mustermann::Set.new(use_trie: true, use_cache: false, duplicate_captures: :collect)
      set.add('/e/:v(/x/:v)?', :e)
      expect(set.match('/e/9').params).to eq('v' => ['9'])
    end

    example 'expands concatenated patterns with the configured strategy' do
      second  = Mustermann.new('/:a', duplicate_captures: :collect)
      pattern = Mustermann.new('/:a', duplicate_captures: :collect) + second
      expect(pattern.expand(a: %w[x y])).to eq('/x/y')
    end

    example 'keeps the single value for absent repeated optional captures' do
      pattern = Mustermann.new('/:a(/:a)', type: :rails, duplicate_captures: :equal)
      expect(pattern.match('/x').params).to eq('a' => 'x')
    end
  end
end
