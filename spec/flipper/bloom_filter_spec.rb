require 'flipper/bloom_filter'

RSpec.describe Flipper::BloomFilter do
  describe '.build' do
    it 'sizes bits and hashes from capacity and false positive rate' do
      filter = described_class.build(capacity: 1_000, false_positive_rate: 0.01)

      # m = -n * ln(p) / (ln 2)^2, k = (m / n) * ln 2
      expect(filter.size).to eq(9_586)
      expect(filter.hash_count).to eq(7)
    end

    it 'uses more memory for lower false positive rates' do
      loose = described_class.build(capacity: 1_000, false_positive_rate: 0.05)
      tight = described_class.build(capacity: 1_000, false_positive_rate: 0.001)

      expect(tight.memory_bytes).to be > loose.memory_bytes
    end

    it 'raises for invalid capacity' do
      expect { described_class.build(capacity: 0, false_positive_rate: 0.01) }
        .to raise_error(ArgumentError)
    end

    it 'raises for invalid false positive rate' do
      expect { described_class.build(capacity: 10, false_positive_rate: 0) }
        .to raise_error(ArgumentError)
      expect { described_class.build(capacity: 10, false_positive_rate: 1) }
        .to raise_error(ArgumentError)
    end
  end

  describe '#add and #include?' do
    it 'never reports a false negative for added values' do
      filter = described_class.build(capacity: 1_000, false_positive_rate: 0.01)
      values = (1..1_000).map { |n| "User;#{n}" }
      values.each { |value| filter.add(value) }

      values.each do |value|
        expect(filter.include?(value)).to be(true), "expected #{value} to maybe be present"
      end
    end

    it 'excludes the vast majority of non-members within the target rate' do
      filter = described_class.build(capacity: 1_000, false_positive_rate: 0.01)
      (1..1_000).each { |n| filter.add("User;#{n}") }

      probes = (1..10_000).map { |n| "Other;#{n}" }
      false_positives = probes.count { |value| filter.include?(value) }

      expect(false_positives).to be < 200 # target is ~100 (1%), allow slack
    end

    it 'stringifies values like flipper actor identifiers' do
      filter = described_class.build(capacity: 10, false_positive_rate: 0.01)
      filter.add(1)

      expect(filter.include?('1')).to be(true)
    end
  end

  describe '#memory_bytes' do
    it 'returns the bit storage size in bytes' do
      filter = described_class.new(size: 9_586, hash_count: 7)

      expect(filter.memory_bytes).to eq(1_199)
    end
  end
end
