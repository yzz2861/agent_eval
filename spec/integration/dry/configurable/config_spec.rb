# frozen_string_literal: true

require "pathname"

RSpec.describe Dry::Configurable::Config do
  subject(:config) do
    klass.config
  end

  let(:klass) do
    Class.new do
      extend Dry::Configurable
    end
  end

  describe "#configured?" do
    it "returns false if the key has not been accessed" do
      klass.setting :db
      expect(klass.config.configured?(:db)).to be false
    end

    it "returns true if the key has been assigned" do
      klass.setting :db
      klass.config.db = "sqlite"
      expect(klass.config.configured?(:db)).to be true
    end

    it "returns true when the key was assigned in a superclass" do
      klass.setting :db
      klass.config.db = "sqlite"
      subclass = Class.new(klass)
      expect(subclass.config.configured?(:db)).to be true
    end

    describe "assignable values" do
      it "returns false if the key has been read" do
        klass.setting :db
        klass.config.db
        expect(klass.config.configured?(:db)).to be false
      end

      it "returns false when the key was read in a superclass" do
        klass.setting :db
        klass.config.db
        subclass = Class.new(klass)
        expect(subclass.config.configured?(:db)).to be false
      end
    end

    describe "cloneable values" do
      it "returns false if the key has been read only" do
        klass.setting :db, cloneable: true, default: []
        klass.config.db
        expect(klass.config.configured?(:db)).to be false
      end

      it "returns false if the key was read in a superclass" do
        klass.setting :db, cloneable: true, default: []
        klass.config.db
        subclass = Class.new(klass)
        expect(subclass.config.configured?(:db)).to be false
      end

      it "returns true if the value has been mutated" do
        klass.setting :db, cloneable: true, default: []
        klass.config.db << "sqlite"
        expect(klass.config.configured?(:db)).to be true
      end

      it "returns true if the value was mutated in a superclass" do
        klass.setting :db, cloneable: true, default: []
        klass.config.db << "sqlite"
        subclass = Class.new(klass)
        expect(subclass.config.configured?(:db)).to be true
      end
    end
  end

  describe "#update" do
    it "sets new config values in a flat config" do
      klass.setting :db

      config = klass.config.update(db: "sqlite")

      expect(klass.config).to be(config)
      expect(config.db).to eql("sqlite")
    end

    it "sets new config values in a nested config" do
      klass.setting :db do
        setting :user, default: "root"
        setting :pass, default: "secret"
      end

      klass.config.update(db: {user: "jane", pass: "supersecret"})

      expect(klass.config.db.user).to eql("jane")
      expect(klass.config.db.pass).to eql("supersecret")
    end

    it "runs constructors" do
      klass.setting :db do
        setting :user, default: "root", constructor: ->(v) { v.upcase }
        setting :sslcert, constructor: ->(v) { v&.values_at(:pem, :pass)&.join }
      end

      klass.config.update(db: {user: "jane", sslcert: {pem: "cert", pass: "qwerty"}})

      expect(klass.config.db.user).to eql("JANE")
      expect(klass.config.db.sslcert).to eql("certqwerty")
    end

    it "raises ArgumentError when setting value is not a Hash" do
      klass.setting :db do
        setting :user
      end

      expect { klass.config.update(db: "string") }
        .to raise_error(ArgumentError, '"string" is not a valid setting value')
    end
  end

  describe "#to_h" do
    before do
      klass.setting :db do
        setting :user, default: "root"
        setting :pass, default: "secret"
        setting :ports, default: Set[123, 321]
      end
    end

    it "returns the values as a hash" do
      expect(klass.config.to_h).to eq(
        db: {
          user: "root",
          pass: "secret",
          ports: Set[123, 321]
        }
      )
    end
  end

  describe "#dup" do
    context "with an object" do
      it "returns a deep-copy" do
        klass = Class.new do
          include Dry::Configurable

          setting :db do
            setting :user, default: "root"
            setting :pass, default: "secret"
            setting :ports, default: Set[123]
          end
        end

        parent = Class.new(klass).new
        parent.config.db.ports << 312

        expect(parent.config.db.ports).to eql(Set[123, 312])
        expect(parent.config.dup.db.ports).to eql(Set[123, 312])

        child = Class.new(parent.class).new
        child.config.db.ports << 476

        expect(child.config.db.ports).to eql(Set[123, 476])
        expect(child.config.dup.db.ports).to eql(Set[123, 476])

        expect(klass.new.config.db.ports).to eql(Set[123])
      end

      it "returns an equal copy" do
        klass = Class.new do
          include Dry::Configurable

          setting :db do
            setting :user, default: "root"
            setting :pass, default: "secret"
            setting :ports, default: Set[123]
          end
        end

        object = klass.new

        expect(object.config.dup).to eql(object.config)
      end
    end

    context "with a class" do
      it "returns a deep-copy" do
        klass.setting :db do
          setting :user, default: "root"
          setting :pass, default: "secret"
          setting :ports, default: Set[123]
        end

        parent = Class.new(klass) do
          config.db.ports << 312
        end

        child = Class.new(parent) do
          config.db.ports << 476
        end

        expect(klass.config.db.ports).to eql(Set[123])

        expect(parent.config.db.ports).to eql(Set[123, 312])
        expect(child.config.db.ports).to eql(Set[123, 312, 476])

        expect(parent.config.dup.db.ports).to eql(Set[123, 312])
        expect(child.config.dup.db.ports).to eql(Set[123, 312, 476])
      end

      it "returns an equal copy" do
        klass = Class.new do
          extend Dry::Configurable

          setting :db do
            setting :user, default: "root"
            setting :pass, default: "secret"
            setting :ports, default: Set[123]
          end
        end

        expect(klass.config.dup).to eql(klass.config)
      end
    end
  end

  describe "#[]" do
    it "coerces name from string" do
      klass.setting :db, default: :sqlite

      expect(klass.config["db"]).to eql(:sqlite)
    end

    it "raises ArgumentError when name is not valid" do
      expect { klass.config[:hello] }.to raise_error(ArgumentError, /hello/)
    end
  end

  describe "#hash" do
    it "returns the integer hash value for the convig based on its values" do
      klass.setting :db

      expect(klass.config.hash).to be_an_instance_of(Integer)
      expect { klass.config.db = "sqlite" }.to change { klass.config.hash }
    end

    it "is memoized when the config is finalized", :performance do
      klass.setting :a
      klass.setting :b
      klass.setting :c
      klass.setting :d
      klass.setting :e

      finalized_config = klass.config.dup.finalize!

      expect(finalized_config.hash).to eq klass.config.hash
      expect { finalized_config.hash }.to perform_faster_than { klass.config.hash }.at_least(5).times
    end
  end

  describe "finalize!" do
    it "can be finalized" do
      klass.setting :db do
        setting :user, default: "root".dup
      end

      klass.finalize!
      klass.finalize! # second call becomes a no op

      # It freezes the config and nested config classes
      expect(klass.config).to be_frozen
      expect(klass.config.db).to be_frozen

      # But does not freeze values by default
      expect(klass.config.db.user).not_to be_frozen
      klass.config.db.user << "foo"
      expect(klass.config.db.user).to eq("rootfoo")

      # It does not allow configure block anymore
      expect { klass.configure {} }.to raise_error(Dry::Configurable::FrozenConfigError)
    end

    it "can be finalized with freezing values" do
      klass.setting :db do
        setting :user, default: "root".dup
      end

      klass.finalize!(freeze_values: true)
      klass.finalize!(freeze_values: true) # second call becomes a no op

      expect(klass.config).to be_frozen
      expect(klass.config.db).to be_frozen

      expect(klass.config.db.user).to be_frozen
      expect { klass.config.db.user << "foo" }.to raise_error(FrozenError)

      # does not allow configure block anymore
      expect { klass.configure {} }.to raise_error(Dry::Configurable::FrozenConfigError)
    end

    it "returns early when finalizing a second time" do
      klass.setting :db do
        setting :user, default: "root".dup
      end

      klass.finalize!
      expect(klass.config).to be_frozen
      expect(klass.config.db.user).not_to be_frozen

      # Calling the second time does not do any work
      klass.finalize!(freeze_values: true)
      expect(klass.config.db.user).not_to be_frozen
    end
  end

  describe "#to_data" do
    it "raises if the config is not finalized" do
      klass.setting :db

      expect { klass.config.to_data }.to raise_error(
        Dry::Configurable::FrozenConfigError,
        /must be finalized/
      )
    end

    it "returns a frozen Data instance with a member for every setting" do
      klass.setting :db, default: "sqlite"
      klass.setting :pool, default: 5
      klass.finalize!

      data = klass.config.to_data

      expect(data).to be_frozen
      expect(data).to be_a(Data)
      expect(data.db).to eq("sqlite")
      expect(data.pool).to eq(5)
      expect(data.members).to eq(%i[db pool])
    end

    it "converts nested configs recursively as Data instances" do
      klass.setting :db do
        setting :host, default: "localhost"
        setting :port, default: 5432
      end
      klass.finalize!

      data = klass.config.to_data

      expect(data.db).to be_a(Data)
      expect(data.db).to be_frozen
      expect(data.db.host).to eq("localhost")
      expect(data.db.port).to eq(5432)
    end

    it "returns a fresh but structurally-equal instance per call" do
      klass.setting :db, default: "sqlite"
      klass.finalize!

      first = klass.config.to_data
      second = klass.config.to_data

      expect(first).not_to equal(second)
      expect(first).to eq(second)
      expect(first).to eql(second)
      expect(first.hash).to eq(second.hash)
    end

    it "shares the underlying Data class across configs with the same schema" do
      klass.setting :db
      klass.setting :pool

      first = klass.config.dup.finalize!
      second = klass.config.dup.finalize!

      expect(first.to_data.class).to equal(second.to_data.class)
    end

    it "captures mutable values by reference (not deep-frozen by default)" do
      klass.setting :list, default: []
      klass.finalize!

      klass.config.list << "added after finalize"

      expect(klass.config.to_data.list).to eq(["added after finalize"])
    end
  end

  describe "#to_ractor_snapshot" do
    before do
      klass.setting :db do
        setting :host, default: "localhost"
        setting :port, default: 5432
        setting :ports, default: Set[5432]
        setting :options, default: {pool: 5}
        setting :tags, default: ["primary"]
        setting :enabled, default: true
      end
    end

    it "raises if the config is not finalized" do
      expect { klass.config.to_ractor_snapshot }.to raise_error(
        Dry::Configurable::FrozenConfigError,
        /must be finalized/
      )
    end

    it "builds a frozen shareable Data snapshot readable from another Ractor" do
      klass.finalize!

      snapshot = klass.config.to_ractor_snapshot
      result = Ractor.new(snapshot) do |received|
        [
          Ractor.shareable?(received),
          received.db.host,
          received.db.port,
          received.db.ports.to_a,
          received.db.options,
          received.db.tags,
          received.db.enabled
        ]
      end.take

      expect(snapshot).to be_frozen
      expect(Ractor.shareable?(snapshot)).to be(true)
      expect(result).to eq([
        true,
        "localhost",
        5432,
        [5432],
        {pool: 5},
        ["primary"],
        true
      ])
    end

    it "supports the library Undefined singleton" do
      undefined_klass = Class.new do
        extend Dry::Configurable(default_undefined: true)

        setting :missing
      end
      undefined_klass.finalize!

      snapshot = undefined_klass.config.to_ractor_snapshot

      expect(snapshot.missing).to be(Dry::Configurable::Undefined)
      expect(Ractor.new(snapshot) { |config|
        config.missing.equal?(Dry::Configurable::Undefined)
      }.take).to be(true)
    end

    it "does not freeze or rewrite the live config or its values" do
      string = String.new("localhost")
      tags = ["primary"]
      options = {pool: 5}
      ports = Set[5432]
      klass.config.db.host = string
      klass.config.db.tags = tags
      klass.config.db.options = options
      klass.config.db.ports = ports
      klass.finalize!

      klass.config.to_ractor_snapshot

      expect(klass.config).to be_frozen
      expect(klass.config.db).to be_frozen
      expect(string).not_to be_frozen
      expect(tags).not_to be_frozen
      expect(options).not_to be_frozen
      expect(ports).not_to be_frozen
      expect(klass.config.db.tags).to equal(tags)
      expect(klass.config.db.options).to equal(options)
      expect(klass.config.db.ports).to equal(ports)
    end

    it "preserves duplicate references" do
      shared = {name: "primary"}
      klass.config.db.tags = [shared, shared]
      klass.finalize!

      snapshot = klass.config.to_ractor_snapshot
      first = snapshot.db.tags[0]
      second = snapshot.db.tags[1]

      expect(first).to equal(second)
      expect(Ractor.new(snapshot) { |config|
        config.db.tags[0].equal?(config.db.tags[1])
      }.take).to be(true)
    end

    it "preserves cycles through nested setting paths" do
      database = {}
      database[:self] = database
      services = [database]
      services << services
      klass.config.db.tags = services
      klass.finalize!

      snapshot = klass.config.to_ractor_snapshot

      expect(snapshot.db.tags[0][:self]).to equal(snapshot.db.tags[0])
      expect(snapshot.db.tags[1]).to equal(snapshot.db.tags)
      expect(Ractor.new(snapshot) { |config|
        tags = config.db.tags
        tags[0][:self].equal?(tags[0]) && tags[1].equal?(tags)
      }.take).to be(true)
    end

    it "requires an explicit converter for unsupported values and reports the setting path" do
      klass.setting :path, default: Pathname("tmp/db.sqlite")
      klass.finalize!

      expect { klass.config.to_ractor_snapshot }.to raise_error(
        Dry::Configurable::RactorSnapshotError,
        /Pathname at settings\.path: provide an explicit converter/
      )
    end

    it "uses explicit converters and passes the setting path when accepted" do
      seen_path = nil
      klass.setting :path, default: Pathname("tmp/db.sqlite")
      klass.finalize!

      snapshot = klass.config.to_ractor_snapshot(
        converters: {
          Pathname => ->(path, path_setting) {
            seen_path = path_setting
            path.to_s.freeze
          }
        }
      )

      expect(snapshot.path).to eq("tmp/db.sqlite")
      expect(seen_path).to eq(%i[path])
    end

    it "reports converter failures with the nested setting path" do
      klass.setting :path, default: Pathname("tmp/db.sqlite")
      klass.finalize!

      expect do
        klass.config.to_ractor_snapshot(
          converters: {Pathname => ->(_) { raise "boom" }}
        )
      end.to raise_error(
        Dry::Configurable::RactorSnapshotError,
        /Converter failed at settings\.path: RuntimeError: boom/
      )
    end

    it "rejects converter results that are not shareable" do
      klass.setting :path, default: Pathname("tmp/db.sqlite")
      klass.finalize!

      expect do
        klass.config.to_ractor_snapshot(
          converters: {Pathname => ->(path) { path.to_s }}
        )
      end.to raise_error(
        Dry::Configurable::RactorSnapshotError,
        /Converter for settings\.path returned a non-shareable value: String/
      )
    end

    it "rejects converter results that are shareable but not frozen" do
      klass.setting :path, default: Pathname("tmp/db.sqlite")
      klass.finalize!

      expect do
        klass.config.to_ractor_snapshot(
          converters: {Pathname => ->(_) { Ractor.new {} }}
        )
      end.to raise_error(
        Dry::Configurable::RactorSnapshotError,
        /Converter for settings\.path returned a non-shareable value: Ractor/
      )
    end

    it "reports unsupported nested hash keys with a setting path" do
      klass.config.db.options = {Pathname("key") => 1}
      klass.finalize!

      expect { klass.config.to_ractor_snapshot }.to raise_error(
        Dry::Configurable::RactorSnapshotError,
        /hash key at settings\.db\.options\.key.*Pathname/m
      )
    end
  end

  describe "#method_missing" do
    it "provides access to reader methods" do
      klass.setting :hello

      expect { klass.config.method(:hello) }.to_not raise_error
    end

    it "provides access to writer methods" do
      klass.setting :hello

      expect { klass.config.method(:hello=) }.to_not raise_error
    end
  end
end
