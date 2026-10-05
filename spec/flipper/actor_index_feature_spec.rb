RSpec.describe 'Feature with an actor index' do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:bloom) { Flipper::ActorIndexes::Bloom.new(capacity: 100, false_positive_rate: 0.01) }
  let(:checker) { Flipper::ActorIndex.new(bloom) }
  let(:feature) { Flipper::Feature.new(:search, adapter, actor_index: checker) }
  let(:actor) { Flipper::Actor.new('User;1') }
  let(:outsider) { Flipper::Actor.new('User;999') }

  it 'exposes the configured index' do
    expect(feature.actor_index).to be(checker)
  end

  it 'enables and checks actors through the index' do
    feature.enable(actor)

    checker.reset_counts
    expect(feature.enabled?(actor)).to be(true)
    expect(checker.precise_queries).to eq(1)
    expect(checker.bloom_exclusions).to eq(0)
  end

  it 'excludes non-members without a precise query' do
    feature.enable(actor)

    checker.reset_counts
    expect(feature.enabled?(outsider)).to be(false)
    expect(checker.bloom_exclusions).to eq(1)
    expect(checker.precise_queries).to eq(0)
  end

  it 'keeps the index in sync when actors are disabled' do
    feature.enable(actor)
    feature.disable(actor)

    expect(feature.enabled?(actor)).to be(false)
    expect(bloom.include?('User;1')).to be(false)
    expect(bloom.might_include?('User;1')).to be(false)
  end

  it 'keeps the index in sync when the feature is cleared' do
    feature.enable(actor)
    feature.clear

    expect(feature.enabled?(actor)).to be(false)
    expect(bloom.size).to eq(0)
  end

  it 'does not let a bloom hit enable the feature without a precise match' do
    # Artificial false positive: the index claims every actor might be
    # listed, but the precise list is empty.
    always_hit = Class.new do
      def index_version
        1
      end

      def might_include?(_value)
        true
      end
    end.new
    empty_list = Class.new do
      def list_version
        1
      end

      def include?(_value)
        false
      end
    end.new
    lying_checker = Flipper::ActorIndex.new(always_hit, list: empty_list)
    feature = Flipper::Feature.new(:search, adapter, actor_index: lying_checker)

    expect(feature.enabled?(outsider)).to be(false)
    expect(lying_checker.precise_queries).to eq(1)
  end

  it 'falls back to precise queries when index and list versions diverge' do
    stale_index = Class.new do
      def index_version
        1
      end

      def might_include?(_value)
        false
      end
    end.new
    list = Class.new do
      def list_version
        2
      end

      def include?(value)
        value == 'User;1'
      end
    end.new
    stale_checker = Flipper::ActorIndex.new(stale_index, list: list)
    feature = Flipper::Feature.new(:search, adapter, actor_index: stale_checker)

    # The stale index would wrongly exclude User;1; the fallback must not.
    expect(feature.enabled?(actor)).to be(true)
    expect(feature.enabled?(outsider)).to be(false)
    expect(stale_checker.fallbacks).to eq(2)
  end

  it 'ignores the index for non-actor gates' do
    feature.enable

    checker.reset_counts
    expect(feature.enabled?(outsider)).to be(true)
    expect(checker.precise_queries).to eq(0)
    expect(checker.bloom_exclusions).to eq(0)
  end

  it 'leaves read-only indexes untouched on enable' do
    read_only_index = Class.new do
      def index_version
        1
      end

      def might_include?(_value)
        false
      end

      def list_version
        1
      end

      def include?(_value)
        false
      end
    end.new
    read_only = Flipper::ActorIndex.new(read_only_index)
    feature = Flipper::Feature.new(:search, adapter, actor_index: read_only)

    # The underlying index has no add/delete, so enable must not try to
    # mutate it or fail.
    expect { feature.enable(actor) }.not_to raise_error
  end
end
