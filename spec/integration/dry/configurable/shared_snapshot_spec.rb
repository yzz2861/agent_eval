# frozen_string_literal: true

require "pathname"

RSpec.describe "Dry::Configurable::Config#to_shared_snapshot" do
  subject(:config) { klass.config }

  let(:klass) do
    Class.new do
      extend Dry::Configurable
    end
  end

  describe "basic values" do
    it "snapshots scalars and containers into a frozen hash" do
      klass.setting :name, default: "app"
      klass.setting :port, default: 3000
      klass.setting :ratio, default: 0.5
      klass.setting :tags, default: %w[a b]
      klass.setting :opts, default: {retries: 3}
      klass.setting :ids, default: Set[1, 2]
      klass.setting :flag, default: false
      klass.setting :missing, default: nil

      snapshot = config.to_shared_snapshot

      expect(snapshot).to eq(
        name: "app",
        port: 3000,
        ratio: 0.5,
        tags: %w[a b],
        opts: {retries: 3},
        ids: Set[1, 2],
        flag: false,
        missing: nil
      )
      expect(snapshot).to be_frozen
      expect(snapshot[:tags]).to be_frozen
      expect(snapshot[:tags].first).to be_frozen
      expect(snapshot[:opts]).to be_frozen
      expect(snapshot[:ids]).to be_frozen
      expect(Ractor.shareable?(snapshot)).to be true
    end

    it "snapshots nested configs into nested hashes" do
      klass.setting :database do
        setting :dsn, default: "sqlite:memory"
      end

      snapshot = config.to_shared_snapshot

      expect(snapshot[:database]).to eq(dsn: "sqlite:memory")
      expect(snapshot[:database]).to be_frozen
    end

    it "does not freeze or modify the original config or its values" do
      klass.setting :tags, default: %w[a b]
      klass.setting :name, default: +"app"

      original_tags = config.tags
      original_name = config.name

      config.to_shared_snapshot

      expect(config).not_to be_frozen
      expect(original_tags).not_to be_frozen
      expect(original_name).not_to be_frozen

      config.tags << "c"
      config.name = "renamed"
      expect(config.tags).to eq(%w[a b c])
      expect(config.name).to eq("renamed")
    end

    it "works on a finalized config" do
      klass.setting :name, default: "app"
      klass.finalize!

      snapshot = config.to_shared_snapshot

      expect(snapshot).to eq(name: "app")
      expect(Ractor.shareable?(snapshot)).to be true
    end
  end

  describe "object graph handling" do
    it "preserves repeated references" do
      shared = %w[x y]
      klass.setting :first
      klass.setting :second
      config.first = shared
      config.second = shared

      snapshot = config.to_shared_snapshot

      expect(snapshot[:first]).to equal(snapshot[:second])
    end

    it "supports cyclic structures" do
      cyclic = []
      cyclic << cyclic
      klass.setting :node
      config.node = cyclic

      snapshot = config.to_shared_snapshot

      expect(snapshot[:node].first).to equal(snapshot[:node])
      expect(snapshot[:node]).to be_frozen
      expect(Ractor.shareable?(snapshot)).to be true
    end
  end

  describe "custom types" do
    let(:money_class) do
      Struct.new(:currency, :cents)
    end

    it "raises SnapshotError identifying the setting path when no converter is given" do
      klass.setting :database do
        setting :dsn, default: "sqlite:memory"
        setting :timeout, default: Object.new
      end

      expect { config.to_shared_snapshot }.to raise_error(
        Dry::Configurable::SnapshotError,
        /database\.timeout/
      )
    end

    it "raises SnapshotError with an index path for values inside containers" do
      klass.setting :handlers, default: ["ok", Object.new]

      expect { config.to_shared_snapshot }.to raise_error(
        Dry::Configurable::SnapshotError,
        /handlers\[1\]/
      )
    end

    it "converts custom types with a caller-provided converter" do
      klass.setting :price, default: money_class.new("USD", 100)

      snapshot = config.to_shared_snapshot(
        converters: {money_class => ->(m) { {currency: m.currency, cents: m.cents} }}
      )

      expect(snapshot[:price]).to eq(currency: "USD", cents: 100)
      expect(snapshot[:price]).to be_frozen
      expect(Ractor.shareable?(snapshot)).to be true
    end

    it "recursively converts converter output" do
      klass.setting :price, default: money_class.new("USD", 100)

      snapshot = config.to_shared_snapshot(
        converters: {money_class => ->(m) { [m.currency, "cents"] }}
      )

      expect(snapshot[:price]).to eq(["USD", "cents"])
      expect(snapshot[:price].first).to be_frozen
    end

    it "raises when a converter returns the object itself" do
      value = money_class.new("USD", 100)
      klass.setting :price, default: value

      expect {
        config.to_shared_snapshot(converters: {money_class => ->(m) { m }})
      }.to raise_error(Dry::Configurable::SnapshotError, /price/)
    end

    it "does not silently serialize arbitrary objects" do
      klass.setting :callback, default: -> { "hi" }

      expect { config.to_shared_snapshot }.to raise_error(
        Dry::Configurable::SnapshotError,
        /callback/
      )
    end
  end

  describe "Ractor hand-off" do
    it "can be read from a short-lived Ractor" do
      klass.setting :name, default: "app"
      klass.setting :tags, default: %w[a b]
      klass.setting :database do
        setting :dsn, default: "sqlite:memory"
      end

      snapshot = config.to_shared_snapshot

      result = Ractor.new(snapshot) { |snap|
        [
          snap[:name],
          snap[:tags].length,
          snap[:database][:dsn],
          snap.frozen?
        ]
      }.take

      expect(result).to eq(["app", 2, "sqlite:memory", true])
    end

    it "keeps the original config usable in the main Ractor after hand-off" do
      klass.setting :tags, default: %w[a]

      snapshot = config.to_shared_snapshot
      Ractor.new(snapshot) { |snap| snap[:tags].first }.take

      config.tags << "b"
      expect(config.tags).to eq(%w[a b])
      expect(snapshot[:tags]).to eq(%w[a])
    end
  end
end
