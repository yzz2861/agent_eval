require 'flipper/actor_indexes/bloom'

RSpec.describe Flipper::ActorIndexes::Bloom do
  subject(:index) { described_class.new(capacity: 100, false_positive_rate: 0.01) }

  it 'implements the index and list protocol with a shared version' do
    index.add('User;1')

    expect(index.index_version).to eq(index.list_version)
    expect(index.might_include?('User;1')).to be(true)
    expect(index.include?('User;1')).to be(true)
  end

  describe '#add' do
    it 'adds the actor to the precise list and the filter, bumping the version' do
      expect { index.add('User;1') }
        .to change { index.version }.by(1)
        .and change { index.size }.by(1)

      expect(index.include?('User;1')).to be(true)
      expect(index.might_include?('User;1')).to be(true)
    end

    it 'returns false and does not bump the version for duplicates' do
      index.add('User;1')

      expect(index.add('User;1')).to be(false)
      expect { index.add('User;1') }.not_to change { index.version }
    end

    it 'grows the filter when the list outgrows capacity, without false negatives' do
      small = described_class.new(capacity: 2, false_positive_rate: 0.01)
      values = (1..10).map { |n| "User;#{n}" }
      values.each { |value| small.add(value) }

      values.each do |value|
        expect(small.might_include?(value)).to be(true)
        expect(small.include?(value)).to be(true)
      end
    end
  end

  describe '#delete' do
    it 'removes the actor from the precise list and the rebuilt filter' do
      index.add('User;1')
      index.add('User;2')

      expect { index.delete('User;1') }
        .to change { index.version }.by(1)
        .and change { index.size }.by(-1)

      expect(index.include?('User;1')).to be(false)
      # The filter was rebuilt without the deleted actor, so it cannot linger
      # as a false positive in the new version.
      expect(index.might_include?('User;1')).to be(false)
      expect(index.include?('User;2')).to be(true)
      expect(index.might_include?('User;2')).to be(true)
    end

    it 'returns false and does not bump the version for unknown actors' do
      expect(index.delete('User;999')).to be(false)
      expect { index.delete('User;999') }.not_to change { index.version }
    end
  end

  describe '#clear' do
    it 'empties the list and filter and bumps the version' do
      index.add('User;1')

      expect { index.clear }.to change { index.version }.by(1)

      expect(index.size).to eq(0)
      expect(index.include?('User;1')).to be(false)
      expect(index.might_include?('User;1')).to be(false)
    end
  end

  describe '#memory_bytes' do
    it 'reflects the filter sized for the configured capacity and rate' do
      expect(index.memory_bytes).to eq(120)
    end
  end
end
