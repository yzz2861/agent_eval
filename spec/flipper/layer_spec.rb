require 'spec_helper'

RSpec.describe Flipper::Layer do
  # Fixed actor set shared by all examples so bucketing assertions are
  # deterministic across runs.
  let(:actors) { (1..200).map { |n| Flipper::Actor.new("user:#{n}") } }

  subject(:layer) { described_class.new(:checkout) }

  describe '#assign' do
    it 'assigns fixed ranges to features' do
      layer.assign :new_checkout, 0...50
      layer.assign :checkout_v2, 50...75

      expect(layer.feature_names).to eq([:new_checkout, :checkout_v2])
      expect(layer.range_for(:new_checkout)).to eq(0...50)
      expect(layer.range_for(:checkout_v2)).to eq(50...75)
      expect(layer.include?(:new_checkout)).to be(true)
      expect(layer.include?(:other)).to be(false)
    end

    it 'supports fractional percentages up to 3 decimal places' do
      layer.assign :new_checkout, 0...0.001
      layer.assign :checkout_v2, 0.001...33.333

      expect(layer.range_for(:new_checkout)).to eq(0...0.001)
      expect(layer.range_for(:checkout_v2)).to eq(0.001...33.333)
    end

    it 'rejects ranges that overlap an existing assignment' do
      layer.assign :new_checkout, 0...50

      expect { layer.assign :checkout_v2, 49.999...75 }
        .to raise_error(Flipper::LayerOverlap, /overlaps/)
      expect { layer.assign :checkout_v2, 0...1 }
        .to raise_error(Flipper::LayerOverlap)
    end

    it 'rejects allocation beyond 100 percent' do
      layer.assign :new_checkout, 0...60

      expect { layer.assign :checkout_v2, 60...120 }
        .to raise_error(ArgumentError, /0...100/)
      expect { layer.assign :checkout_v2, 40...100 }
        .to raise_error(Flipper::LayerOverlap)
    end

    it 'rejects malformed ranges' do
      expect { layer.assign :new_checkout, 0..50 }
        .to raise_error(ArgumentError, /exclude its end/)
      expect { layer.assign :new_checkout, 50...0 }
        .to raise_error(ArgumentError, /0...100/)
      expect { layer.assign :new_checkout, -1...50 }
        .to raise_error(ArgumentError, /0...100/)
      expect { layer.assign :new_checkout, 50 }
        .to raise_error(ArgumentError, /Range/)
    end

    it 'rejects re-assigning a feature without unassigning it first' do
      layer.assign :new_checkout, 0...50

      expect { layer.assign :new_checkout, 50...75 }
        .to raise_error(ArgumentError, /already assigned/)
    end
  end

  describe '#unassign' do
    it 'frees only the removed feature range' do
      layer.assign :new_checkout, 0...50
      layer.assign :checkout_v2, 50...100

      layer.unassign(:new_checkout)

      expect(layer.include?(:new_checkout)).to be(false)
      expect(layer.range_for(:checkout_v2)).to eq(50...100)
    end
  end

  describe 'bucketing' do
    it 'pins the hash domain to layer name plus actor value' do
      actors.each do |actor|
        expected = Zlib.crc32("layer:checkout#{actor.flipper_id}") % 100_000
        expect(layer.bucket_for(actor)).to eq(expected)
      end
    end

    it 'uses a different hash domain than the percentage of actors gate' do
      layer.assign :new_checkout, 0...100

      differing = actors.count do |actor|
        layer_bucket = layer.bucket_for(actor)
        gate_bucket = Zlib.crc32("new_checkout#{actor.flipper_id}") % 100_000
        layer_bucket != gate_bucket
      end

      expect(differing).to be > 0
    end

    it 'assigns each actor to at most one feature' do
      layer.assign :new_checkout, 0...50
      layer.assign :checkout_v2, 50...100

      actors.each do |actor|
        claimed = layer.feature_names.select { |name| layer.assigned?(name, actor) }
        expect(claimed.size).to eq(1)
        expect(claimed.first).to eq(layer.feature_for(actor))
      end
    end

    it 'leaves actors in unassigned ranges unclaimed' do
      layer.assign :new_checkout, 0...50

      actors.each do |actor|
        if layer.bucket_for(actor) < 50_000
          expect(layer.feature_for(actor)).to eq(:new_checkout)
        else
          expect(layer.feature_for(actor)).to be_nil
        end
      end
    end

    it 'buckets independently across layers' do
      other_layer = described_class.new(:search)

      differing = actors.count do |actor|
        layer.bucket_for(actor) != other_layer.bucket_for(actor)
      end

      expect(differing).to be > 0
    end
  end

  describe 'configuration changes' do
    it 'does not re-bucket other features when a feature is stopped' do
      layer.assign :new_checkout, 0...50
      layer.assign :checkout_v2, 50...100

      before = actors.map { |actor| layer.feature_for(actor) }
      layer.unassign(:new_checkout)
      after = actors.map { |actor| layer.feature_for(actor) }

      actors.each_with_index do |actor, i|
        if before[i] == :checkout_v2
          expect(after[i]).to eq(:checkout_v2)
        else
          expect(after[i]).to be_nil
        end
      end
    end

    it 'only affects actors in the freed range when a new feature is assigned' do
      layer.assign :new_checkout, 0...50
      layer.assign :checkout_v2, 50...75

      before = actors.map { |actor| layer.feature_for(actor) }
      layer.assign :checkout_v3, 75...100
      after = actors.map { |actor| layer.feature_for(actor) }

      actors.each_with_index do |actor, i|
        if before[i].nil?
          expect(after[i]).to eq(:checkout_v3)
        else
          expect(after[i]).to eq(before[i])
        end
      end
    end
  end

  describe 'Flipper layer registry' do
    after { Flipper.unregister_layers }

    it 'registers and fetches layers by name' do
      registered = Flipper.register_layer(:checkout) do |l|
        l.assign :new_checkout, 0...50
      end

      expect(Flipper.layer(:checkout)).to be(registered)
      expect(Flipper.layer('checkout')).to be(registered)
      expect(Flipper.layers).to eq([registered])
      expect(Flipper.layer_for(:new_checkout)).to be(registered)
      expect(Flipper.layer_for(:other)).to be_nil
    end

    it 'rejects duplicate layer names' do
      Flipper.register_layer(:checkout)

      expect { Flipper.register_layer(:checkout) }
        .to raise_error(Flipper::DuplicateLayer, /already been registered/)
    end

    it 'clears layers with unregister_layers' do
      Flipper.register_layer(:checkout)
      Flipper.unregister_layers

      expect(Flipper.layers).to be_empty
      expect(Flipper.layer(:checkout)).to be_nil
    end
  end

  describe 'feature enabled checks through a layer' do
    before do
      Flipper.register_layer(:checkout) do |l|
        l.assign :new_checkout, 0...50
        l.assign :checkout_v2, 50...100
      end
    end

    it 'makes features in the same layer mutually exclusive per actor' do
      Flipper.enable_percentage_of_actors(:new_checkout, 100)
      Flipper.enable_percentage_of_actors(:checkout_v2, 100)

      actors.each do |actor|
        results = [:new_checkout, :checkout_v2].map do |name|
          Flipper.enabled?(name, actor)
        end
        expect(results.count(true)).to eq(1)

        expected = Flipper.layer(:checkout).feature_for(actor)
        expect(Flipper.enabled?(expected, actor)).to be(true)
      end
    end

    it 'checks the layer before the feature percentage gate' do
      Flipper.enable_percentage_of_actors(:new_checkout, 50)

      actors.each do |actor|
        assigned = Flipper.layer(:checkout).assigned?(:new_checkout, actor)
        in_rollout = Zlib.crc32("new_checkout#{actor.flipper_id}") % 100_000 < 50_000
        expect(Flipper.enabled?(:new_checkout, actor)).to eq(assigned && in_rollout)
      end
    end

    it 'keeps layer assignment independent from the feature rollout' do
      Flipper.enable_percentage_of_actors(:new_checkout, 50)

      assigned = actors.select { |a| Flipper.layer(:checkout).assigned?(:new_checkout, a) }
      in_rollout = actors.select do |a|
        Zlib.crc32("new_checkout#{a.flipper_id}") % 100_000 < 50_000
      end

      # Separate hash domains: neither stage implies the other, so some
      # assigned actors fall outside the rollout and vice versa.
      expect(assigned - in_rollout).not_to be_empty
      expect(in_rollout - assigned).not_to be_empty
    end

    it 'does not affect features outside the layer' do
      Flipper.enable_percentage_of_actors(:recommendations, 100)

      actors.each do |actor|
        expect(Flipper.enabled?(:recommendations, actor)).to be(true)
      end
    end

    it 'excludes unassigned actors even when the feature is fully on' do
      Flipper.enable(:new_checkout)

      actors.each do |actor|
        expected = Flipper.layer(:checkout).assigned?(:new_checkout, actor)
        expect(Flipper.enabled?(:new_checkout, actor)).to be(expected)
      end
    end

    it 'does not restrict checks without actors' do
      Flipper.enable(:new_checkout)

      expect(Flipper.enabled?(:new_checkout)).to be(true)
    end

    it 'frees actors of a stopped experiment without moving others' do
      Flipper.enable_percentage_of_actors(:new_checkout, 100)
      Flipper.enable_percentage_of_actors(:checkout_v2, 100)

      v2_before = actors.select { |actor| Flipper.enabled?(:checkout_v2, actor) }

      # Stop the experiment the usual way (disable the feature), then
      # release its range in the layer.
      Flipper.disable_percentage_of_actors(:new_checkout)
      Flipper.layer(:checkout).unassign(:new_checkout)

      v2_after = actors.select { |actor| Flipper.enabled?(:checkout_v2, actor) }
      expect(v2_after).to eq(v2_before)
      expect(v2_after).not_to be_empty

      new_checkout_actors = actors.select { |actor| Flipper.enabled?(:new_checkout, actor) }
      expect(new_checkout_actors).to be_empty
    end
  end
end
