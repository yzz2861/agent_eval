require 'spec_helper'

describe MessagePack::Negotiation do
  class NegotiationAlphaPoint
    attr_reader :x, :y

    def initialize(x, y)
      @x = x
      @y = y
    end

    def to_msgpack_ext
      MessagePack.pack([@x, @y])
    end

    def self.from_msgpack_ext(data)
      new(*MessagePack.unpack(data))
    end

    def ==(other)
      self.class == other.class && x == other.x && y == other.y
    end
  end

  class NegotiationBetaPoint
    attr_reader :coords

    def initialize(x, y)
      @coords = [x, y]
    end

    def to_msgpack_ext
      MessagePack.pack(@coords)
    end

    def self.from_msgpack_ext(data)
      new(*MessagePack.unpack(data))
    end

    def ==(other)
      self.class == other.class && coords == other.coords
    end
  end

  class NegotiationLabel
    attr_reader :text

    def initialize(text)
      @text = text
    end

    def to_msgpack_ext
      @text
    end

    def self.from_msgpack_ext(data)
      new(data)
    end

    def ==(other)
      self.class == other.class && text == other.text
    end
  end

  # Two services that both extended MessagePack on their own: the same
  # type ids mean different objects on each side (alpha's id 3 is a point,
  # beta's id 3 is a label), so only negotiation can find a safe wire id.
  let(:alpha_registry) do
    registry = MessagePack::Negotiation::Registry.new
    registry.register(:point, version: 1, types: [3, 10], klass: NegotiationAlphaPoint)
    registry.register(:telemetry, version: 1, type: 5, klass: NegotiationLabel, required: false)
    registry
  end

  let(:beta_registry) do
    registry = MessagePack::Negotiation::Registry.new
    registry.register(:point, version: 1, types: [7, 10], klass: NegotiationBetaPoint)
    registry.register(:label, version: 1, type: 3, klass: NegotiationLabel, required: false)
    registry
  end

  let(:alpha_session) { described_class.negotiate(alpha_registry, beta_registry) }
  let(:beta_session) { described_class.negotiate(beta_registry, alpha_registry) }

  describe 'negotiation between conflicting registries' do
    it 'picks a type id both sides can use for the logical type' do
      expect(alpha_session.enabled).to eq([{ name: :point, version: 1, type: 10 }])
      expect(beta_session.enabled).to eq([{ name: :point, version: 1, type: 10 }])
    end

    it 'puts the negotiated id on the wire' do
      payload = alpha_session.dump(NegotiationAlphaPoint.new(1, 2))
      ext = MessagePack::DefaultFactory.unpacker(allow_unknown_ext: true).tap { |u| u.feed(payload) }.read
      expect(ext).to be_a(MessagePack::ExtensionValue)
      expect(ext.type).to eq(10)
    end

    it 'round-trips objects both ways across the conflicting registries' do
      point = NegotiationAlphaPoint.new(1, 2)
      unpacked = beta_session.load(alpha_session.dump(point))
      expect(unpacked).to eq(NegotiationBetaPoint.new(1, 2))

      label_source = MessagePack::DefaultFactory # never used for sessions
      expect(label_source).not_to be_nil
      back = alpha_session.load(beta_session.dump(NegotiationBetaPoint.new(3, 4)))
      expect(back).to eq(NegotiationAlphaPoint.new(3, 4))
    end

    it 'lists optional types that could not be enabled' do
      expect(alpha_session.disabled).to eq([{ name: :telemetry, reason: :not_supported_by_peer }])
      expect(beta_session.disabled).to eq([{ name: :label, reason: :not_supported_by_peer }])
      expect(alpha_session.enabled?(:telemetry)).to be(false)
      expect(alpha_session.enabled?(:point)).to be(true)
    end

    it 'does not modify the global DefaultFactory' do
      expect { alpha_session; beta_session }.not_to change { MessagePack::DefaultFactory.registered_types }
    end
  end

  describe MessagePack::Negotiation::Registry do
    subject(:registry) { described_class.new }

    it 'rejects protocol-reserved type ids' do
      expect { registry.register(:ts, version: 1, type: -1, klass: NegotiationLabel) }
        .to raise_error(MessagePack::Negotiation::InvalidTypeIdError)
      expect { registry.register(:ts, version: 1, type: -128, klass: NegotiationLabel) }
        .to raise_error(MessagePack::Negotiation::InvalidTypeIdError)
      expect { registry.register(:ts, version: 1, type: 128, klass: NegotiationLabel) }
        .to raise_error(MessagePack::Negotiation::InvalidTypeIdError)
    end

    it 'accepts the edges of the application range' do
      registry.register(:low, version: 1, type: 0, klass: NegotiationLabel)
      registry.register(:high, version: 1, type: 127, klass: NegotiationLabel)
      expect(registry.advertisement).to eq({ low: { 1 => [0] }, high: { 1 => [127] } })
    end

    it 'refuses to reuse a type id instead of overwriting it' do
      registry.register(:point, version: 1, type: 3, klass: NegotiationAlphaPoint)
      expect { registry.register(:label, version: 1, type: 3, klass: NegotiationLabel) }
        .to raise_error(MessagePack::Negotiation::ConflictError)
      expect(registry.advertisement).to eq({ point: { 1 => [3] } })
    end

    it 'refuses to redefine a (name, version) pair' do
      registry.register(:point, version: 1, type: 3, klass: NegotiationAlphaPoint)
      expect { registry.register(:point, version: 1, type: 4, klass: NegotiationAlphaPoint) }
        .to raise_error(MessagePack::Negotiation::ConflictError)
    end

    it 'allows the same logical name in several versions' do
      registry.register(:point, version: 1, type: 3, klass: NegotiationAlphaPoint)
      registry.register(:point, version: 2, type: 4, klass: NegotiationAlphaPoint)
      expect(registry.advertisement).to eq({ point: { 1 => [3], 2 => [4] } })
    end
  end

  describe 'version matching' do
    it 'picks the highest common version' do
      local = MessagePack::Negotiation::Registry.new
      local.register(:point, version: 1, type: 3, klass: NegotiationAlphaPoint)
      local.register(:point, version: 2, types: [4, 12], klass: NegotiationAlphaPoint)

      remote = MessagePack::Negotiation::Registry.new
      remote.register(:point, version: 1, type: 8, klass: NegotiationBetaPoint)
      remote.register(:point, version: 2, types: [9, 12], klass: NegotiationBetaPoint)
      remote.register(:point, version: 3, type: 10, klass: NegotiationBetaPoint)

      session = described_class.negotiate(local, remote)
      expect(session.enabled).to eq([{ name: :point, version: 2, type: 12 }])
    end

    it 'falls back to a lower version when the higher one has no common id' do
      local = MessagePack::Negotiation::Registry.new
      local.register(:point, version: 1, types: [3, 10], klass: NegotiationAlphaPoint)
      local.register(:point, version: 2, type: 4, klass: NegotiationAlphaPoint)

      remote = MessagePack::Negotiation::Registry.new
      remote.register(:point, version: 1, types: [7, 10], klass: NegotiationBetaPoint)
      remote.register(:point, version: 2, type: 9, klass: NegotiationBetaPoint)

      session = described_class.negotiate(local, remote)
      expect(session.enabled).to eq([{ name: :point, version: 1, type: 10 }])
    end
  end

  describe 'failed negotiation' do
    let(:gamma_registry) do
      registry = MessagePack::Negotiation::Registry.new
      registry.register(:point, version: 1, types: [3, 10], klass: NegotiationAlphaPoint)
      registry.register(:matrix, version: 2, type: 6, klass: NegotiationAlphaPoint)
      registry.register(:telemetry, version: 1, type: 5, klass: NegotiationLabel, required: false)
      registry
    end

    let(:delta_registry) do
      registry = MessagePack::Negotiation::Registry.new
      registry.register(:point, version: 1, types: [7, 10], klass: NegotiationBetaPoint)
      registry.register(:matrix, version: 1, type: 6, klass: NegotiationBetaPoint)
      registry
    end

    it 'refuses to create a session when a required type has no common version' do
      expect { described_class.negotiate(gamma_registry, delta_registry) }
        .to raise_error(MessagePack::Negotiation::NegotiationError) do |error|
          expect(error.unresolved).to eq([{ name: :matrix, reason: :no_common_version }])
          expect(error.disabled).to eq([{ name: :telemetry, reason: :not_supported_by_peer }])
        end
    end

    it 'refuses when a required type only has reserved ids in common' do
      local = MessagePack::Negotiation::Registry.new
      local.register(:point, version: 1, types: [3, 10], klass: NegotiationAlphaPoint)
      remote = { point: { 1 => [-1, 7] } } # -1 is reserved, 7 was never offered locally

      expect { described_class.negotiate(local, remote) }
        .to raise_error(MessagePack::Negotiation::NegotiationError) do |error|
          expect(error.unresolved).to eq([{ name: :point, reason: :no_common_type_id }])
        end
    end

    it 'leaves no half-installed codec behind' do
      default_factory_types = MessagePack::DefaultFactory.registered_types

      expect { described_class.negotiate(gamma_registry, delta_registry) }
        .to raise_error(MessagePack::Negotiation::NegotiationError)

      # The global factory was not touched.
      expect(MessagePack::DefaultFactory.registered_types).to eq(default_factory_types)

      # Both registries are intact and still usable: even though :point
      # could have been negotiated, nothing was installed anywhere.
      expect(gamma_registry.advertisement).to eq(
        point: { 1 => [3, 10] }, matrix: { 2 => [6] }, telemetry: { 1 => [5] }
      )
      expect { gamma_registry.register(:extra, version: 1, types: [8, 11], klass: NegotiationLabel) }
        .not_to raise_error

      # A later attempt with a compatible peer still succeeds.
      fixed_delta = MessagePack::Negotiation::Registry.new
      fixed_delta.register(:point, version: 1, types: [7, 10], klass: NegotiationBetaPoint)
      fixed_delta.register(:matrix, version: 2, types: [6, 9], klass: NegotiationBetaPoint)
      fixed_delta.register(:extra, version: 1, type: 11, klass: NegotiationLabel, required: false)

      session = described_class.negotiate(gamma_registry, fixed_delta)
      expect(session.enabled).to contain_exactly(
        { name: :point, version: 1, type: 10 },
        { name: :matrix, version: 2, type: 6 },
        { name: :extra, version: 1, type: 11 },
      )
    end
  end

  describe 'session immutability' do
    it 'freezes the session factory' do
      expect(alpha_session.factory).to be_frozen
      expect { alpha_session.factory.register_type(0x40, Symbol) }
        .to raise_error(FrozenError)
    end

    it 'is not affected by later registrations in the source registry' do
      session = alpha_session
      payload = session.dump(NegotiationAlphaPoint.new(5, 6))
      registered_before = session.factory.registered_types

      alpha_registry.register(:label, version: 1, type: 42, klass: NegotiationLabel, required: false)

      expect(session.factory.registered_types).to eq(registered_before)
      expect(session.enabled).to eq([{ name: :point, version: 1, type: 10 }])
      expect(session.load(payload)).to eq(NegotiationAlphaPoint.new(5, 6))
    end
  end
end
