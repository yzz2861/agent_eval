# frozen_string_literal: true

RSpec.describe Dry::Configurable, ".members" do
  let(:klass) do
    Class.new do
      extend Dry::Configurable

      members(:connections) do
        setting :adapter, default: "postgres"
        setting :pool, default: "1", constructor: -> value { Integer(value) }
        setting :options, default: {}
        setting :tags, default: []

        setting :ssl do
          setting :enabled, default: false
        end
      end
    end
  end

  def add_primary
    klass.config.connections.add(:primary) do |connection|
      connection.adapter = "mysql"
      connection.pool = "5"
      connection.options[:timeout] = 3
      connection.tags << "writable"
      connection.ssl.enabled = true
    end
  end

  def add_archive
    klass.config.connections.add(:archive,
      adapter: "postgres",
      pool: 2,
      options: {read_only: true},
      tags: ["readonly"],
      ssl: {enabled: true}
    )
  end

  it "declares one schema and creates independently named members" do
    add_primary
    add_archive

    expect(klass.settings.keys).to eql([:connections])
    expect(klass.config.connections.keys).to eql(%i[primary archive])

    expect(klass.config.connections[:primary]).to have_attributes(
      adapter: "mysql",
      pool: 5
    )
    expect(klass.config.connections.primary.tags).to eql(["writable"])
    expect(klass.config.connections.primary.options).to eq(timeout: 3)
    expect(klass.config.connections.primary.ssl.enabled).to be(true)

    expect(klass.config.connections[:archive]).to have_attributes(
      adapter: "postgres",
      pool: 2
    )
    expect(klass.config.connections.archive.tags).to eql(["readonly"])
    expect(klass.config.connections.archive.options).to eq(read_only: true)
    expect(klass.config.connections.archive.ssl.enabled).to be(true)
  end

  it "does not share mutable defaults between members" do
    add_primary
    add_archive

    klass.config.connections.primary.tags << "shared?"
    klass.config.connections.primary.options[:shared] = true

    expect(klass.config.connections.archive.tags).to eql(["readonly"])
    expect(klass.config.connections.archive.options).to eq(read_only: true)
  end

  it "distinguishes unknown members from unknown member fields" do
    add_primary

    expect { klass.config.connections[:missing] }
      .to raise_error(Dry::Configurable::UnknownMemberError, "missing")
    expect { klass.config.connections.missing }
      .to raise_error(Dry::Configurable::UnknownMemberError, "missing")

    expect { klass.config.connections[:primary][:missing] }
      .to raise_error(Dry::Configurable::UnknownMemberFieldError, "+missing+ is not a member field name")
    expect { klass.config.connections.primary.missing }
      .to raise_error(Dry::Configurable::UnknownMemberFieldError, "+missing+ is not a member field name")
    expect { klass.config.connections.primary.missing = true }
      .to raise_error(Dry::Configurable::UnknownMemberFieldError, "+missing+ is not a member field name")
  end

  it "rejects duplicate names and names that conflict with the config API" do
    add_primary

    expect { klass.config.connections.add(:primary) }
      .to raise_error(ArgumentError, "+primary+ is already a member name")

    expect { klass.config.connections.add(:add) }
      .to raise_error(ArgumentError, /conflicts with a config API method/)
  end

  it "removes members" do
    add_primary
    add_archive

    klass.config.connections.delete(:archive)

    expect(klass.config.connections.keys).to eql([:primary])
    expect { klass.config.connections.delete(:archive) }
      .to raise_error(Dry::Configurable::UnknownMemberError, "archive")
  end

  it "updates existing members through config assignment" do
    add_primary

    klass.config.connections = {primary: {adapter: "sqlite", pool: "7"}}

    expect(klass.config.connections.keys).to eql([:primary])
    expect(klass.config.connections.primary.adapter).to eql("sqlite")
    expect(klass.config.connections.primary.pool).to eql(7)

    expect { klass.config.connections = {missing: {adapter: "sqlite"}} }
      .to raise_error(Dry::Configurable::UnknownMemberError, "missing")
  end

  it "copies members without sharing their configs" do
    add_primary
    add_archive

    copy = klass.config.dup
    copy.connections[:primary].adapter = "sqlite"
    copy.connections.primary.tags << "copied"
    copy.connections.delete(:archive)

    expect(copy.to_h).to eq(
      connections: {
        primary: {
          adapter: "sqlite",
          pool: 5,
          options: {timeout: 3},
          tags: ["writable", "copied"],
          ssl: {enabled: true}
        }
      }
    )
    expect(klass.config.connections[:primary].adapter).to eql("mysql")
    expect(klass.config.connections.primary.tags).to eql(["writable"])
    expect(klass.config.connections.keys).to eql(%i[primary archive])
  end

  it "restores a pristine empty collection" do
    add_primary
    add_archive

    pristine = klass.config.pristine

    expect(pristine.to_h).to eq(connections: {})
    expect(klass.config.connections.keys).to eql(%i[primary archive])

    pristine.connections.add(:primary)
    expect(pristine.connections.primary.adapter).to eql("postgres")
    expect(pristine.connections.primary.tags).to eql([])
  end

  it "finalizes every member and converts it to data" do
    add_primary
    add_archive

    klass.finalize!

    expect(klass.config).to be_frozen
    expect(klass.config.connections).to be_frozen
    expect(klass.config.connections[:primary]).to be_frozen
    expect(klass.config.connections[:archive]).to be_frozen

    expect { klass.config.connections.add(:readonly) }
      .to raise_error(Dry::Configurable::FrozenConfigError)
    expect { klass.config.connections.delete(:primary) }
      .to raise_error(Dry::Configurable::FrozenConfigError)
    expect { klass.config.connections[:primary].adapter = "sqlite" }
      .to raise_error(Dry::Configurable::FrozenConfigError)

    data = klass.config.to_data

    expect(data.connections.primary.adapter).to eql("mysql")
    expect(data.connections.archive.adapter).to eql("postgres")
  end

  it "preserves finalized members when cloning" do
    add_primary
    add_archive

    klass.finalize!

    copy = klass.config.clone

    expect(copy).to be_frozen
    expect(copy.connections).to be_frozen
    expect(copy.connections[:primary]).to be_frozen
  end

  it "works with independently configured included instances" do
    instance_klass = Class.new do
      include Dry::Configurable

      members(:connections) do
        setting :adapter, default: "postgres"
        setting :pool, default: 1
        setting :tags, default: []
      end
    end

    primary_instance = instance_klass.new
    archive_instance = instance_klass.new

    primary_instance.config.connections.add(:primary) do |connection|
      connection.adapter = "mysql"
      connection.tags << "primary"
    end
    archive_instance.config.connections.add(:archive) do |connection|
      connection.adapter = "sqlite"
      connection.tags << "archive"
    end

    expect(primary_instance.config.connections.keys).to eql([:primary])
    expect(archive_instance.config.connections.keys).to eql([:archive])
    expect(primary_instance.config.connections[:primary].tags).to eql(["primary"])
    expect(archive_instance.config.connections[:archive].tags).to eql(["archive"])

    primary_instance.finalize!

    expect(primary_instance).to be_frozen
    expect(primary_instance.config.connections[:primary]).to be_frozen
    expect(archive_instance).not_to be_frozen
    expect(archive_instance.config.connections[:archive]).not_to be_frozen
  end

  it "builds members with a custom config class" do
    custom_config_class = Class.new(Dry::Configurable::Config)
    custom_klass = Class.new do
      extend Dry::Configurable(config_class: custom_config_class)

      members(:connections) do
        setting :host
      end
    end

    custom_klass.config.connections.add(:primary)

    expect(custom_klass.config).to be_instance_of(custom_config_class)
    expect(custom_klass.config.connections[:primary]).to be_instance_of(custom_config_class)
  end
end
