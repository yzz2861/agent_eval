require 'spec_helper'

describe MessagePack::TypeNegotiator do
  def wire_class(*attributes)
    Class.new do
      attr_reader(*attributes)

      define_method(:initialize) do |*values|
        attributes.zip(values).each do |attribute, value|
          instance_variable_set("@#{attribute}", value)
        end
      end

      define_method(:==) do |other|
        other.class == self.class && attributes.all? { |attribute| public_send(attribute) == other.public_send(attribute) }
      end

      define_method(:to_msgpack_ext) do
        attributes.map { |attribute| public_send(attribute) }.pack('C*')
      end

      define_singleton_method(:from_msgpack_ext) do |data|
        new(*data.unpack('C*'))
      end
    end
  end

  let(:left_point) { wire_class(:x, :y) }
  let(:right_point) { wire_class(:x, :y) }
  let(:left_shape) { wire_class(:sides) }
  let(:right_shape) { wire_class(:sides) }
  let(:left_color) { wire_class(:red) }
  let(:right_color) { wire_class(:red) }
  let(:left_badge) { wire_class(:level) }
  let(:right_badge) { wire_class(:level) }
  let(:left_hat) { wire_class(:size) }
  let(:right_hat) { wire_class(:size) }
  let(:left_tag) { wire_class(:code) }
  let(:right_tag) { wire_class(:code) }

  let :left do
    negotiator = described_class.new
    negotiator.register_type('point', 1, [7, 8], left_point, required: true)
    negotiator.register_type('shape', 1, [8, 9], left_shape, required: true)
    negotiator.register_type('color', 1, [7], left_color, required: true)
    negotiator.register_type('hat', 1, [6], left_hat, required: false)
    negotiator.register_type('badge', 1, [5], left_badge, required: false)
    negotiator.register_type('tag', 1, [7], left_tag, required: false)
    negotiator
  end

  let :right do
    negotiator = described_class.new
    negotiator.register_type('point', 1, [7, 8], right_point, required: true)
    negotiator.register_type('shape', 1, [8, 9], right_shape, required: true)
    negotiator.register_type('color', 1, [7], right_color, required: true)
    negotiator.register_type('hat', 1, [6], right_hat, required: false)
    negotiator.register_type('badge', 2, [5], right_badge, required: false)
    negotiator.register_type('tag', 1, [7], right_tag, required: false)
    negotiator
  end

  describe '#negotiate' do
    it 'builds session-specific codecs for conflicting extension registries' do
      left_session = left.negotiate(right.offer)
      right_session = right.negotiate(left.offer)

      expect(left_session.enabled_types).to eq(
        'color' => { version: 1, type: 7 },
        'point' => { version: 1, type: 8 },
        'shape' => { version: 1, type: 9 },
        'hat' => { version: 1, type: 6 }
      )
      expect(right_session.enabled_types).to eq(left_session.enabled_types)
      expect(left_session.factory).to be_frozen
      expect(right_session.factory).to be_frozen
      expect(left_session.factory).to_not equal(right_session.factory)
    end

    it 'round-trips logical types across registries with conflicting ids' do
      left_session = left.negotiate(right.offer)
      right_session = right.negotiate(left.offer)

      point = left_point.new(2, 3)
      point_payload = left_session.dump(point)
      expect(point_payload.bytes.first(2)).to eq([0xd5, 8])
      expect(right_session.load(point_payload)).to eq(right_point.new(2, 3))

      shape = left_shape.new(4)
      shape_payload = left_session.dump(shape)
      expect(shape_payload.bytes.first(2)).to eq([0xd4, 9])
      expect(right_session.load(shape_payload)).to eq(right_shape.new(4))

      color = left_color.new(255)
      color_payload = left_session.dump(color)
      expect(color_payload.bytes.first(2)).to eq([0xd4, 7])
      expect(right_session.load(color_payload)).to eq(right_color.new(255))
    end

    it 'lists optional types that could not be enabled' do
      session = left.negotiate(right.offer)

      expect(session.enabled?('hat')).to be(true)
      expect(session.enabled?('badge')).to be(false)
      expect(session.disabled?('badge')).to be(true)
      expect(session.disabled?('tag')).to be(true)
      expect(session.disabled_types['badge']).to eq(
        reason: :no_common_version,
        local_versions: [1],
        remote_versions: [2]
      )
      expect(session.disabled_types['tag']).to eq(
        reason: :no_available_type_id,
        local_versions: [1],
        remote_versions: [1]
      )
    end

    it 'rejects conflicting required ids before creating a codec' do
      local = described_class.new
      local.register_type('point', 1, [8], wire_class(:x, :y), required: true)
      local.register_type('shape', 1, [8], wire_class(:sides), required: true)
      remote = described_class.new
      remote.register_type('point', 1, [8], wire_class(:x, :y), required: true)
      remote.register_type('shape', 1, [8], wire_class(:sides), required: true)

      expect(MessagePack::Factory).to_not receive(:new)
      expect do
        local.negotiate(remote.offer)
      end.to raise_error(MessagePack::NegotiationError, /shape.*no_available_type_id/)
    end

    it 'rejects a required type without a common version' do
      local = described_class.new
      local.register_type('widget', 1, [10], wire_class(:id), required: true)
      remote = described_class.new
      remote.register_type('widget', 2, [10], wire_class(:id), required: true)

      expect do
        local.negotiate(remote.offer)
      end.to raise_error(MessagePack::NegotiationError, /widget.*no_common_version/)
    end

    it 'does not leave a partially installed codec when installation fails' do
      failed_factory = instance_double(MessagePack::Factory)
      allow(failed_factory).to receive(:register_type).and_raise('boom')
      allow(failed_factory).to receive(:packer)
      allow(failed_factory).to receive(:unpacker)
      allow(failed_factory).to receive(:freeze)
      allow(MessagePack::Factory).to receive(:new).and_return(failed_factory)

      expect do
        left.negotiate(right.offer)
      end.to raise_error(MessagePack::NegotiationError, /failed to install negotiated MessagePack codec/)

      expect(failed_factory).to have_received(:register_type).once
      expect(failed_factory).to_not have_received(:packer)
      expect(failed_factory).to_not have_received(:unpacker)
      expect(failed_factory).to_not have_received(:freeze)
    end

    it 'does not modify DefaultFactory' do
      default_types_before = MessagePack::DefaultFactory.registered_types.map do |entry|
        [entry[:type], entry[:class]]
      end

      left.negotiate(right.offer)

      default_types_after = MessagePack::DefaultFactory.registered_types.map do |entry|
        [entry[:type], entry[:class]]
      end
      expect(default_types_after).to eq(default_types_before)
    end

    it 'keeps an existing session stable after later local registration' do
      session = left.negotiate(right.offer)
      enabled_before = session.enabled_types.dup
      point = left_point.new(9, 7)

      later_type = wire_class(:value)
      left.register_type('later', 1, 8, later_type, required: false)

      expect(session.enabled_types).to eq(enabled_before)
      expect(session.factory).to be_frozen
      expect(session.load(session.dump(point))).to eq(point)
      expect do
        session.factory.register_type(10, later_type)
      end.to raise_error(FrozenError, "can't modify frozen MessagePack::Factory")
    end
  end

  describe '#register_type' do
    it 'rejects protocol-reserved negative ids' do
      expect do
        described_class.new.register_type('time', 1, [-1], wire_class(:sec))
      end.to raise_error(ArgumentError, 'negative MessagePack extension type ids are reserved')
    end

    it 'does not allow a repeated registration to override a previous one' do
      klass = wire_class(:value)
      negotiator = described_class.new
      negotiator.register_type('thing', 1, [1], klass)

      expect do
        negotiator.register_type('thing', 1, [2], klass)
      end.to raise_error(ArgumentError, /already registered/)
    end

    it 'does not register one packer class under two logical names' do
      klass = wire_class(:value)
      negotiator = described_class.new
      negotiator.register_type('thing', 1, [1], klass)

      expect do
        negotiator.register_type('other', 1, [2], klass)
      end.to raise_error(ArgumentError, /already registered as "thing"/)
    end
  end

  describe '#offer' do
    it 'returns a frozen snapshot of logical names, versions, and ids' do
      offer = left.offer

      expect(offer).to be_frozen
      expect(offer[:types]).to include(
        hash_including(
          name: 'point',
          required: true,
          versions: [{ version: 1, type_ids: [7, 8] }]
        )
      )
      expect { offer[:types] << {} }.to raise_error(FrozenError)
    end
  end
end
