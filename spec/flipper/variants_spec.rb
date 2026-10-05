require 'spec_helper'

RSpec.describe Flipper::Variants do
  # Fixed hash vectors for feature "search", salt "v1". The bucket is
  # Zlib.crc32("search\u001fv1\u001f#{actor_id}") % 100. These ids were
  # selected so that every weight boundary below has a pinned actor on each
  # side.
  GOLDEN = {
    0  => 'User;12',
    5  => 'User;77',
    15 => 'User;60',
    19 => 'User;74',
    20 => 'User;314',
    25 => 'User;147',
    49 => 'User;526',
    50 => 'User;109',
    55 => 'User;192',
    99 => 'User;8',
  }.freeze

  # Canonical order is name-sorted: a: [0, 30), b: [30, 80), control: [80, 100)
  WEIGHTS = { control: 20, a: 30, b: 50 }.freeze

  def configuration(weights = WEIGHTS, salt: 'v1', version: 1)
    Flipper::Variants::Configuration.new(weights, salt: salt, version: version)
  end

  describe Flipper::Variants::Configuration do
    describe '#bucket_for' do
      it 'matches the fixed hash vectors' do
        config = configuration
        GOLDEN.each do |bucket, actor_id|
          expect(config.bucket_for('search', actor_id)).to eq(bucket)
        end
      end

      it 'is stable across calls and processes' do
        config = configuration
        first = (1..500).map { |n| config.bucket_for(:search, "User;#{n}") }
        second = (1..500).map { |n| config.bucket_for(:search, "User;#{n}") }
        expect(second).to eq(first)
      end

      it 'includes the actor id, feature and salt so each changes bucketing' do
        config = configuration
        other_salt = configuration(WEIGHTS, salt: 'v2')
        other_feature = configuration

        actor_id = 'User;1'

        expect(other_salt.bucket_for('search', actor_id)).not_to(
          eq(config.bucket_for('search', actor_id))
        )
        expect(other_feature.bucket_for('checkout', actor_id)).not_to(
          eq(config.bucket_for('search', actor_id))
        )
        expect(config.bucket_for('search', 'User;2')).not_to(
          eq(config.bucket_for('search', actor_id))
        )
      end

      it 'does not let field values bleed into each other' do
        config = configuration

        # "search" + actor "x" + salt "y!z" must not hash the same as a
        # different feature/actor/salt split of the concatenated bytes.
        expect(config.bucket_for('search', "xy")).not_to(
          eq(config.bucket_for('search', 'x'))
        )
      end
    end

    describe '#evaluate' do
      it 'places each fixed vector in the weight interval containing its bucket' do
        config = configuration
        expected = {
          0  => 'a',
          5  => 'a',
          15 => 'a',
          19 => 'a',
          20 => 'a',
          25 => 'a',
          49 => 'b',
          50 => 'b',
          55 => 'b',
          99 => 'control',
        }

        expected.each do |bucket, variant|
          actor_id = GOLDEN.fetch(bucket)
          result = config.evaluate('search', actor_id)

          expect(result.variant).to eq(variant)
          expect(result.bucket).to eq(bucket)
          expect(result.feature).to eq('search')
          expect(result.salt).to eq('v1')
          expect(result.version).to eq(1)
          expect(result.configuration).to be(config)
        end
      end

      it 'is stable for the same actor, feature and salt' do
        config = configuration
        results = Array.new(3) { config.evaluate(:search, 'User;77') }

        expect(results.map(&:variant).uniq).to eq(['a'])
        expect(results.map(&:bucket).uniq).to eq([5])
      end

      it 'stamps the configured version for traceability' do
        config = configuration(WEIGHTS, salt: 'v1', version: '2026-10-05.3')
        result = config.evaluate('search', GOLDEN.fetch(0))

        expect(result.version).to eq('2026-10-05.3')
      end

      it 'supports a zero-weight variant that is never selected' do
        config = configuration({ control: 20, a: 30, b: 50, holdout: 0 }, salt: 'v1')

        (1..2000).each do |n|
          expect(config.evaluate('search', "User;#{n}").variant).not_to eq('holdout')
        end
      end

      it 'supports a single variant weighted at the full range' do
        config = configuration({ control: 100 }, salt: 'v1')

        GOLDEN.each_value do |actor_id|
          expect(config.evaluate('search', actor_id).variant).to eq('control')
        end
      end
    end

    describe 'weight intervals when weights change' do
      # Canonical (name-sorted) layout before:
      #   a: [0, 20), b: [20, 50), control: [50, 100)
      # Shrinking a from 20 to 10 grows b from 30 to 40; control is
      # untouched. New layout:
      #   a: [0, 10), b: [10, 50), control: [50, 100)
      before do
        @before = configuration({ a: 20, b: 30, control: 50 }, salt: 'v1')
        @after  = configuration({ a: 10, b: 40, control: 50 }, salt: 'v1')
      end

      it 'only reassigns actors in the moved boundary region' do
        moved_before = {
          5  => 'a',       # stays a
          15 => 'a',       # a -> b
          25 => 'b',       # stays b
          55 => 'control', # stays control
        }

        moved_before.each do |bucket, old_variant|
          actor_id = GOLDEN.fetch(bucket)
          before_result = @before.evaluate('search', actor_id)
          after_result = @after.evaluate('search', actor_id)

          expect(before_result.variant).to eq(old_variant)
          expect(before_result.bucket).to eq(after_result.bucket),
            'bucketing must not change when only weights change'

          case bucket
          when 5
            expect(after_result.variant).to eq('a')
          when 15
            expect(after_result.variant).to eq('b')
          when 25
            expect(after_result.variant).to eq('b')
          when 55
            expect(after_result.variant).to eq('control')
          end
        end
      end

      it 'keeps every actor outside the changed segment in the same variant' do
        changed = (1..5000).select do |n|
          actor_id = "User;#{n}"
          @before.evaluate('search', actor_id).variant !=
            @after.evaluate('search', actor_id).variant
        end

        changed.each do |n|
          bucket = @before.bucket_for('search', "User;#{n}")
          # Only a's former tail overlaps b's expanded interval.
          expect(bucket).to be_between(10, 19)
        end

        expect(changed).not_to be_empty
      end

      it 'does not move the control boundary because control was untouched' do
        [50, 55, 99].each do |bucket|
          actor_id = GOLDEN.fetch(bucket)
          expect(@before.evaluate('search', actor_id).variant).to eq('control')
          expect(@after.evaluate('search', actor_id).variant).to eq('control')
        end
      end
    end

    describe 'configuration order' do
      it 'orders variants by name so hash order cannot change assignment' do
        first = configuration({ control: 20, a: 30, b: 50 }, salt: 'v1')
        second = configuration({ b: 50, control: 20, a: 30 }, salt: 'v1')

        expect(second.names).to eq(first.names)
        expect(second.names).to eq(%w[a b control])

        (1..2000).each do |n|
          actor_id = "User;#{n}"
          expect(second.evaluate('search', actor_id).variant).to eq(
            first.evaluate('search', actor_id).variant
          )
        end
      end

      it 'treats symbol and string spellings of a name as the same variant' do
        symbol_keys = configuration({ 'control' => 20, :a => 30, :b => 50 }, salt: 'v1')
        expect(symbol_keys.evaluate('search', GOLDEN.fetch(25)).variant).to eq('a')

        expect {
          configuration({ a: 50, 'a' => 50 }, salt: 'v1')
        }.to raise_error(Flipper::InvalidVariantConfiguration, /declared more than once/)
      end
    end

    describe 'validation' do
      it 'rejects weights that do not sum to 100' do
        expect { configuration({ control: 20, a: 30, b: 49 }) }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /summed to 99/)
        )
        expect { configuration({ control: 20, a: 30, b: 51 }) }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /summed to 101/)
        )
      end

      it 'rejects empty variant sets (every bucket is an empty slot)' do
        expect { configuration({}, salt: 'v1') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /cannot be empty/)
        )
      end

      it 'rejects missing or nil weights for a declared variant' do
        expect { configuration({ control: nil }, salt: 'v1') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /must be an Integer/)
        )
      end

      it 'rejects non-integer and negative weights' do
        expect { configuration({ control: 20.5, a: 79.5 }, salt: 'v1') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /must be an Integer/)
        )
        expect { configuration({ control: -1, a: 101 }, salt: 'v1') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /greater than or equal to 0/)
        )
      end

      it 'rejects blank variant names' do
        expect { configuration({ ' ' => 100 }, salt: 'v1') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /cannot be blank/)
        )
      end

      it 'requires an explicit, non-blank salt' do
        expect { configuration(WEIGHTS, salt: nil) }.to(
          raise_error(Flipper::InvalidVariantConfiguration)
        )
        expect { configuration(WEIGHTS, salt: '  ') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /salt cannot be blank/)
        )
      end

      it 'rejects non-hash weights' do
        expect { configuration([[:control, 100]], salt: 'v1') }.to(
          raise_error(Flipper::InvalidVariantConfiguration, /must be a Hash/)
        )
      end
    end
  end

  describe Flipper::Variants::Result do
    it 'exposes its fields and compares variants by string name' do
      result = configuration(version: 7).evaluate('search', GOLDEN.fetch(25))

      expect(result.variant?(:a)).to be(true)
      expect(result.variant?(:b)).to be(false)
      expect(result.name).to eq('a')
      expect(result.version).to eq(7)
      expect(result.to_h).to eq(
        feature: 'search',
        variant: 'a',
        salt: 'v1',
        version: 7,
        bucket: 25,
      )
    end
  end

  describe '.actor_id' do
    it 'resolves flipper ids, plain ids, and wrapped actors' do
      user = Struct.new(:flipper_id).new('User;9')

      expect(described_class.actor_id('User;9')).to eq('User;9')
      expect(described_class.actor_id(:'User;9')).to eq('User;9')
      expect(described_class.actor_id(user)).to eq('User;9')
      expect(described_class.actor_id(Flipper::Actor.new('User;9'))).to eq('User;9')
      expect(described_class.actor_id(Flipper::Types::Actor.wrap(user))).to eq('User;9')
    end

    it 'rejects actors without an id and blank ids' do
      expect { described_class.actor_id(nil) }.to raise_error(ArgumentError)
      expect { described_class.actor_id(Object.new) }.to raise_error(ArgumentError, /flipper_id/)
      expect { described_class.actor_id('  ') }.to raise_error(ArgumentError, /cannot be blank/)
    end
  end

  describe '.evaluate' do
    it 'evaluates without touching a DSL or adapter' do
      result = described_class.evaluate(:search, Flipper::Actor.new(GOLDEN.fetch(25)),
                                         { control: 20, a: 30, b: 50 }, salt: 'v1', version: 2)

      expect(result.variant).to eq('a')
      expect(result.bucket).to eq(25)
      expect(result.version).to eq(2)
      expect(result.actor_id).to eq(GOLDEN.fetch(25))
    end
  end
end
