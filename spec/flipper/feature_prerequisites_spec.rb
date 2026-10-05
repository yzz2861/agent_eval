RSpec.describe 'Feature prerequisites' do
  let(:adapter) { Flipper::Adapters::Memory.new }
  let(:flipper) { Flipper.new(adapter) }

  describe 'declaring prerequisites' do
    it 'returns the declared prerequisites' do
      flipper.requires(:new_settlement, :base_payments)
      flipper.requires(:new_settlement, :legacy_mode, on: false)

      expect(flipper.prerequisites(:new_settlement)).to eq([
        Flipper::Prerequisite.new(:base_payments),
        Flipper::Prerequisite.new(:legacy_mode, on: false),
      ])
    end

    it 'replaces an existing prerequisite for the same dependency' do
      flipper.requires(:new_settlement, :legacy_mode)
      flipper.requires(:new_settlement, :legacy_mode, on: false)

      expect(flipper.prerequisites(:new_settlement)).to eq([
        Flipper::Prerequisite.new(:legacy_mode, on: false),
      ])
    end

    it 'is accessible from the feature itself' do
      prerequisite = flipper[:new_settlement].requires(:base_payments)

      expect(prerequisite).to eq(Flipper::Prerequisite.new(:base_payments))
      expect(flipper[:new_settlement].prerequisites).to eq([prerequisite])
    end
  end

  describe 'requiring a feature to be on' do
    it 'only enables the feature when the dependency is enabled' do
      flipper.requires(:new_settlement, :base_payments)
      flipper.enable(:new_settlement)
      flipper.add(:base_payments)

      expect(flipper.enabled?(:new_settlement)).to be(false)

      flipper.enable(:base_payments)

      expect(flipper.enabled?(:new_settlement)).to be(true)
    end
  end

  describe 'requiring a feature to be off' do
    it 'only enables the feature while the dependency is disabled' do
      flipper.requires(:new_settlement, :legacy_mode, on: false)
      flipper.enable(:new_settlement)
      flipper.add(:legacy_mode)

      expect(flipper.enabled?(:new_settlement)).to be(true)

      flipper.enable(:legacy_mode)

      expect(flipper.enabled?(:new_settlement)).to be(false)
    end
  end

  describe 'missing dependencies' do
    it 'does not treat a missing dependency as satisfied when requiring on' do
      flipper.requires(:new_settlement, :base_payments)
      flipper.enable(:new_settlement)

      expect(flipper.enabled?(:new_settlement)).to be(false)
    end

    it 'does not treat a missing dependency as satisfied when requiring off' do
      flipper.requires(:new_settlement, :legacy_mode, on: false)
      flipper.enable(:new_settlement)

      expect(flipper.enabled?(:new_settlement)).to be(false)
    end
  end

  describe 'combination with regular gates' do
    it 'requires satisfied prerequisites AND an open gate' do
      flipper.requires(:new_settlement, :base_payments)
      flipper.enable(:base_payments)

      # prerequisites satisfied, but no gate open
      expect(flipper.enabled?(:new_settlement)).to be(false)

      flipper.enable(:new_settlement)

      # prerequisites satisfied and gate open
      expect(flipper.enabled?(:new_settlement)).to be(true)

      flipper.disable(:base_payments)

      # gate open, but prerequisites unsatisfied
      expect(flipper.enabled?(:new_settlement)).to be(false)
    end

    it 'supports multi-level dependency chains' do
      flipper.requires(:settlement_report, :new_settlement)
      flipper.requires(:new_settlement, :base_payments)
      flipper.enable(:settlement_report)
      flipper.enable(:new_settlement)
      flipper.enable(:base_payments)

      expect(flipper.enabled?(:settlement_report)).to be(true)

      flipper.disable(:base_payments)

      expect(flipper.enabled?(:settlement_report)).to be(false)
      expect(flipper.enabled?(:new_settlement)).to be(false)
    end
  end

  describe 'actor and context handling' do
    let(:actor) { Flipper::Actor.new('User;1') }
    let(:other_actor) { Flipper::Actor.new('User;2') }

    it 'evaluates prerequisites with the same actors as the original check' do
      flipper.requires(:new_settlement, :base_payments)
      flipper.enable(:new_settlement)
      flipper.enable_actor(:base_payments, actor)

      expect(flipper.enabled?(:new_settlement, actor)).to be(true)
      expect(flipper.enabled?(:new_settlement, other_actor)).to be(false)
      expect(flipper.enabled?(:new_settlement)).to be(false)
    end

    it 'evaluates prerequisite groups against the same actor' do
      Flipper.register(:admins) { |actor| actor.respond_to?(:admin?) && actor.admin? }
      admin = double('Admin', flipper_id: 'User;1', admin?: true)
      user = double('User', flipper_id: 'User;2', admin?: false)

      flipper.requires(:new_settlement, :base_payments)
      flipper.enable(:new_settlement)
      flipper.enable_group(:base_payments, :admins)

      expect(flipper.enabled?(:new_settlement, admin)).to be(true)
      expect(flipper.enabled?(:new_settlement, user)).to be(false)
    end
  end

  describe 'cycle detection' do
    it 'raises with the feature chain for indirect cycles' do
      flipper.requires(:a, :b)
      flipper.requires(:b, :c)
      flipper.requires(:c, :a)
      flipper.add(:a)
      flipper.add(:b)
      flipper.add(:c)

      expect { flipper.enabled?(:a) }.to raise_error(Flipper::CircularPrerequisite) { |error|
        expect(error.chain).to eq([:a, :b, :c, :a])
        expect(error.message).to include('a -> b -> c -> a')
      }
    end

    it 'raises with the feature chain for two feature cycles' do
      flipper.requires(:a, :b)
      flipper.requires(:b, :a)
      flipper.add(:a)
      flipper.add(:b)

      expect { flipper.enabled?(:a) }.to raise_error(Flipper::CircularPrerequisite) { |error|
        expect(error.chain).to eq([:a, :b, :a])
      }
    end

    it 'raises for a feature that requires itself' do
      flipper.requires(:a, :a)
      flipper.add(:a)

      expect { flipper.enabled?(:a) }.to raise_error(Flipper::CircularPrerequisite) { |error|
        expect(error.chain).to eq([:a, :a])
      }
    end
  end

  describe 'per-evaluation memoization' do
    let(:actor) { Flipper::Actor.new('User;1') }
    let(:evaluations) { [] }

    before do
      counting = evaluations
      Flipper.register(:counting) do |actor|
        counting << actor
        true
      end

      # diamond: top requires left and right, both require shared
      flipper.requires(:top, :left)
      flipper.requires(:top, :right)
      flipper.requires(:left, :shared)
      flipper.requires(:right, :shared)
      flipper.enable(:top)
      flipper.enable(:left)
      flipper.enable(:right)
      flipper.enable_group(:shared, :counting)
    end

    it 'evaluates a shared dependency only once per check' do
      expect(flipper.enabled?(:top, actor)).to be(true)
      expect(evaluations.size).to eq(1)
    end

    it 'does not cache dependency results across checks' do
      expect(flipper.enabled?(:top, actor)).to be(true)
      expect(flipper.enabled?(:top, actor)).to be(true)
      expect(evaluations.size).to eq(2)
    end

    it 'reflects dependency changes between checks' do
      expect(flipper.enabled?(:top, actor)).to be(true)

      flipper.disable_group(:shared, :counting)

      expect(flipper.enabled?(:top, actor)).to be(false)
    end
  end

  describe 'directly built features' do
    it 'resolves dependencies against the same adapter by default' do
      feature = Flipper::Feature.new(:new_settlement, adapter)
      feature.requires(:base_payments)
      feature.enable

      expect(feature.enabled?).to be(false)

      Flipper::Feature.new(:base_payments, adapter).enable

      expect(feature.enabled?).to be(true)
    end
  end
end
