require 'spec_helper'

RSpec.describe 'Flipper variants via DSL' do
  let(:flipper) { Flipper.new(Flipper::Adapters::Memory.new) }

  let(:weights) { { control: 20, a: 30, b: 50 } }

  describe '#configure_variants and #variant' do
    it 'evaluates configured variants and keeps the configuration available' do
      configuration = flipper.configure_variants(:search, weights, salt: 'v1', version: 4)

      expect(flipper).to be_variants_configured(:search)
      expect(flipper.variant_configuration(:search)).to be(configuration)

      result = flipper.variant('search', Flipper::Actor.new('User;77'))
      expect(result.variant?(:control)).to be(false)
      expect(result.variant).to eq('a')
      expect(result.bucket).to eq(5)
      expect(result.feature).to eq('search')
      expect(result.version).to eq(4)
      expect(result.actor_id).to eq('User;77')
    end

    it 'is exposed through the Flipper module delegation' do
      Flipper.configure do |config|
        config.adapter { Flipper::Adapters::Memory.new }
      end

      Flipper.configure_variants(:search, weights, salt: 'v1')
      expect(Flipper.variant(:search, 'User;77').variant).to eq('a')
      expect(Flipper).to be_variants_configured(:search)
    end

    it 'raises when variants have not been configured' do
      expect { flipper.variant(:search, 'User;1') }.to(
        raise_error(Flipper::VariantsNotConfigured, /search/)
      )
      expect(flipper).not_to be_variants_configured(:search)
    end

    it 'validates configuration at registration time' do
      expect {
        flipper.configure_variants(:search, { control: 99, a: 0 }, salt: 'v1')
      }.to raise_error(Flipper::InvalidVariantConfiguration, /summed to 99/)
      expect(flipper).not_to be_variants_configured(:search)
    end

    it 'supports replacing and removing a configuration' do
      flipper.configure_variants(:search, weights, salt: 'v1', version: 1)
      replacement = flipper.configure_variants(:search, { control: 100 }, salt: 'v2', version: 2)

      expect(flipper.variant_configuration(:search)).to be(replacement)

      removed = flipper.remove_variants(:search)
      expect(removed).to be(replacement)
      expect(flipper).not_to be_variants_configured(:search)
      expect(flipper.remove_variants(:search)).to be_nil
    end

    it 'scopes configurations per feature' do
      flipper.configure_variants(:search, weights, salt: 'v1')
      flipper.configure_variants(:checkout, { control: 100 }, salt: 'v1')

      (1..500).each do |n|
        expect(flipper.variant(:checkout, "User;#{n}").variant).to eq('control')
      end
    end

    it 'rejects bad feature names' do
      expect { flipper.configure_variants(123, weights, salt: 'v1') }.to(
        raise_error(ArgumentError)
      )
    end
  end

  describe 'independence from enabled?' do
    let(:actor) { Flipper::Actor.new('User;77') }

    it 'keeps enabled? boolean while variants exist' do
      flipper.configure_variants(:search, weights, salt: 'v1')

      expect(flipper.enabled?(:search, actor)).to be(false)
      expect(flipper.variant(:search, actor).variant).to eq('a')

      flipper.enable(:search)
      expect(flipper.enabled?(:search, actor)).to be(true)
      expect(flipper.variant(:search, actor).variant).to eq('a')

      flipper.disable(:search)
      expect(flipper.enabled?(:search, actor)).to be(false)
      expect(flipper.variant(:search, actor).variant).to eq('a')
    end

    it 'does not create or mutate adapter state' do
      flipper.configure_variants(:search, weights, salt: 'v1')
      flipper.variant(:search, actor)

      expect(flipper.exist?(:search)).to be(false)
      values = flipper.adapter.get(flipper.feature(:search))
      expect(values[:boolean]).to be_nil
      expect(values[:actors]).to be_empty
      expect(values[:groups]).to be_empty
      expect(values[:expression]).to be_nil
      expect(values[:percentage_of_actors]).to be_nil
      expect(values[:percentage_of_time]).to be_nil
    end

    it 'keeps variant assignment stable when boolean gates change' do
      flipper.configure_variants(:search, weights, salt: 'v1')
      before = flipper.variant(:search, actor)

      flipper.enable_percentage_of_actors(:search, 50)
      flipper.enable_actor(:search, actor)

      after = flipper.variant(:search, actor)
      expect(after.variant).to eq(before.variant)
      expect(after.bucket).to eq(before.bucket)
    end

    it 'does not affect variant configuration when a feature is removed from the adapter' do
      flipper.configure_variants(:search, weights, salt: 'v1')
      flipper.enable(:search)
      flipper.remove(:search)

      expect(flipper.variant(:search, actor).variant).to eq('a')
    end
  end
end
