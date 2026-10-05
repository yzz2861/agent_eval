require 'flipper/actor_index'
require 'flipper/actor_indexes/bloom'

RSpec.describe Flipper::ActorIndex do
  # Builds a stub index that artificially reports every actor as a possible
  # hit, simulating worst-case Bloom filter false positives.
  def always_hit_index(version: 1)
    Class.new do
      define_method(:index_version) { version }
      define_method(:might_include?) { |_actor_value| true }
    end.new
  end

  # Builds a stub precise list backed by a plain array, with its own version.
  def stub_list(members, version: 1)
    Class.new do
      define_method(:list_version) { version }
      define_method(:include?) { |actor_value| members.include?(actor_value) }
    end.new
  end

  let(:bloom) { Flipper::ActorIndexes::Bloom.new(capacity: 1_000, false_positive_rate: 0.01) }
  subject(:checker) { described_class.new(bloom) }

  context 'when versions match' do
    before do
      bloom.add('User;1')
      bloom.add('User;2')
    end

    it 'excludes actors that are definitely not on the list without a precise query' do
      expect(checker.include?('User;999')).to be(false)
      expect(checker.bloom_exclusions).to eq(1)
      expect(checker.precise_queries).to eq(0)
      expect(checker.fallbacks).to eq(0)
    end

    it 'confirms possible hits with a precise query' do
      expect(checker.include?('User;1')).to be(true)
      expect(checker.precise_queries).to eq(1)
      expect(checker.bloom_exclusions).to eq(0)
    end

    it 'is not stale' do
      expect(checker.stale?).to be(false)
    end
  end

  context 'with artificial false positives' do
    subject(:checker) do
      described_class.new(always_hit_index, list: stub_list(['User;1']))
    end

    it 'still returns the precise answer for non-members' do
      # The index claims every actor might be listed, but the final decision
      # must come from the precise list.
      expect(checker.include?('User;999')).to be(false)
      expect(checker.precise_queries).to eq(1)
      expect(checker.bloom_exclusions).to eq(0)
    end

    it 'still returns the precise answer for members' do
      expect(checker.include?('User;1')).to be(true)
      expect(checker.precise_queries).to eq(1)
    end
  end

  context 'when index and list versions do not match' do
    subject(:checker) do
      # Stale index: claims nobody is listed, and its version lags the list.
      stale_index = Class.new do
        def index_version
          1
        end

        def might_include?(_actor_value)
          false
        end
      end.new
      described_class.new(stale_index, list: stub_list(['User;1'], version: 2))
    end

    it 'is stale' do
      expect(checker.stale?).to be(true)
    end

    it 'falls back to precise queries and stays correct' do
      # The stale index would wrongly exclude User;1, so the fallback must
      # bypass it entirely.
      expect(checker.include?('User;1')).to be(true)
      expect(checker.include?('User;999')).to be(false)
      expect(checker.fallbacks).to eq(2)
      expect(checker.precise_queries).to eq(2)
      expect(checker.bloom_exclusions).to eq(0)
    end
  end

  describe '#reset_counts' do
    it 'resets all counters' do
      bloom.add('User;1')
      checker.include?('User;1')
      checker.include?('User;999')

      checker.reset_counts

      expect(checker.precise_queries).to eq(0)
      expect(checker.bloom_exclusions).to eq(0)
      expect(checker.fallbacks).to eq(0)
    end
  end
end
