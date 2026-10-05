require 'zlib'
require 'flipper/layer'

RSpec.describe Flipper::Layer do
  let(:actors) do
    (1..20).map { |number| Flipper::Types::Actor.new(Flipper::Actor.new("User;#{number}")) }
  end

  describe '#initialize' do
    it 'accepts non-overlapping allocations that leave buckets unused' do
      layer = described_class.new(:experiments, checkout: 0...250, search: 250...500)

      expect(layer.feature_names).to contain_exactly(:checkout, :search)
    end

    it 'does not use gaps for another feature when one experiment stops' do
      layer = described_class.new(:experiments, checkout: 0...250, search: 500...750)
      actor = Flipper::Types::Actor.new(Flipper::Actor.new('User;6'))
      bucket = layer.bucket_for(actor)
      expect(bucket).to eq(321)

      expect(layer.matches?(:checkout, [actor])).to be(false)
      expect(layer.matches?(:search, [actor])).to be(false)
    end

    it 'accepts inclusive ranges that end at the final bucket' do
      layer = described_class.new(:experiments, checkout: 0..999)

      expect(layer.feature_names).to eq([:checkout])
    end

    it 'rejects overlapping allocations' do
      expect do
        described_class.new(:experiments, checkout: 0...500, search: 400...800)
      end.to raise_error(Flipper::InvalidLayer, /overlaps another allocation/)
    end

    it 'rejects allocations outside the bucket space' do
      expect do
        described_class.new(:experiments, checkout: -1...250)
      end.to raise_error(Flipper::InvalidLayer, /within buckets 0...1000/)
    end

    it 'rejects allocations larger than the bucket space' do
      expect do
        described_class.new(:experiments, checkout: 0..1000)
      end.to raise_error(Flipper::InvalidLayer, /allocates 1001 buckets, but only 1000 are available/)
    end

    it 'rejects allocations that use more than the bucket space' do
      expect do
        described_class.new(
          :experiments,
          checkout: 0...400,
          search: 400...800,
          billing: 800...1100
        )
      end.to raise_error(Flipper::InvalidLayer, /allocates 1100 buckets, but only 1000 are available/)
    end

    it 'rejects empty allocations' do
      expect do
        described_class.new(:experiments, checkout: 500...500)
      end.to raise_error(Flipper::InvalidLayer, /within buckets 0...1000/)
    end

    it 'rejects non-integer ranges' do
      expect do
        described_class.new(:experiments, checkout: 0...25.5)
      end.to raise_error(Flipper::InvalidLayer, /integer bucket Range/)
    end
  end

  describe '#bucket_for' do
    it 'uses a layer-specific hash domain' do
      layer = described_class.new(:experiments, checkout: 0...1000)
      actor = Flipper::Types::Actor.new(Flipper::Actor.new('User;9'))

      expect(layer.bucket_for(actor)).to eq(
        Zlib.crc32('flipper.layer:experiments:User;9') % 1000
      )
    end

    it 'orders multiple actors so the bucket is stable regardless of argument order' do
      layer = described_class.new(:experiments, checkout: 0...1000)
      first = Flipper::Types::Actor.new(Flipper::Actor.new('User;2'))
      second = Flipper::Types::Actor.new(Flipper::Actor.new('User;1'))

      expect(layer.bucket_for([first, second])).to eq(layer.bucket_for([second, first]))
    end
  end

  describe '#matches?' do
    it 'matches an actor only in the feature allocation' do
      layer = described_class.new(
        :experiments,
        checkout: 0...400,
        search: 400...800
      )

      expect(layer.matches?(:checkout, [actors.find { |actor| actor.value == 'User;9' }])).to be(true)
      expect(layer.matches?(:search, [actors.find { |actor| actor.value == 'User;1' }])).to be(true)
      expect(layer.matches?(:checkout, [actors.find { |actor| actor.value == 'User;1' }])).to be(false)
      expect(layer.matches?(:search, [actors.find { |actor| actor.value == 'User;2' }])).to be(false)
    end

    it 'does not match a feature that is not allocated in the layer' do
      layer = described_class.new(:experiments, checkout: 0...400)

      expect(layer.matches?(:search, actors)).to be(false)
    end
  end
end
