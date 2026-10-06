# frozen_string_literal: true

RSpec.describe Dry::Configurable, ".setting_collection" do
  subject(:service) do
    Class.new do
      extend Dry::Configurable

      setting_collection :connections do
        setting :dsn, default: "postgres://localhost", constructor: ->(v) { v.to_s }
        setting :pool_size, default: 5
        setting :tags, default: []

        setting :auth do
          setting :user, default: "deploy"
        end
      end
    end
  end

  let(:connections) { service.config.connections }

  # Two members built from the same template, then modified independently
  def add_connections
    connections.add(:primary) do |primary|
      primary.dsn = "postgres://primary"
      primary.tags << "hot"
    end

    connections.add(:archive) do |archive|
      archive.dsn = "postgres://archive"
      archive.pool_size = 2
      archive.auth.user = "archivist"
    end
  end

  describe "member configs" do
    it "builds members from the declared template, with constructors, defaults and nesting" do
      connections.add(:primary)

      expect(connections.primary.dsn).to eql("postgres://localhost")
      expect(connections.primary.pool_size).to be(5)
      expect(connections.primary.auth.user).to eql("deploy")

      connections.primary.dsn = :primary_dsn

      expect(connections.primary.dsn).to eql("primary_dsn")
    end

    it "keeps members added from the same template independent of each other" do
      add_connections

      expect(connections.primary.dsn).to eql("postgres://primary")
      expect(connections.primary.pool_size).to be(5)
      expect(connections.primary.auth.user).to eql("deploy")

      expect(connections[:archive].dsn).to eql("postgres://archive")
      expect(connections[:archive].pool_size).to be(2)
      expect(connections[:archive].auth.user).to eql("archivist")
    end

    it "does not share mutable defaults between members" do
      add_connections

      expect(connections.primary.tags).to eql(["hot"])
      expect(connections.archive.tags).to eql([])

      connections.archive.tags << "cold"

      expect(connections.primary.tags).to eql(["hot"])
    end

    it "exposes members by method, index and iteration" do
      add_connections

      expect(connections.keys).to eql(%i[primary archive])
      expect(connections.key?(:primary)).to be(true)
      expect(connections.key?(:missing)).to be(false)
      expect(connections.map { |name, member| [name, member.pool_size] })
        .to eql([[:primary, 5], [:archive, 2]])
    end
  end

  describe "member names" do
    it "rejects names that are not valid setting names" do
      expect { connections.add("1dsn") }
        .to raise_error(ArgumentError, /1dsn is not a valid member name/)
    end

    it "rejects names conflicting with the collection API" do
      expect { connections.add(:keys) }
        .to raise_error(ArgumentError, /conflicts with the setting collection API/)

      expect { connections.add(:freeze) }
        .to raise_error(ArgumentError, /conflicts with the setting collection API/)
    end

    it "rejects duplicate members" do
      connections.add(:primary)

      expect { connections.add(:primary) }
        .to raise_error(ArgumentError, /\+primary\+ member is already defined/)
    end
  end

  describe "unknown members and unknown member settings" do
    it "raises UnknownMemberError when reading an unknown member" do
      expect { connections[:missing] }
        .to raise_error(Dry::Configurable::UnknownMemberError, /\+missing\+/)
    end

    it "raises UnknownMemberError when deleting an unknown member" do
      expect { connections.delete(:missing) }
        .to raise_error(Dry::Configurable::UnknownMemberError, /\+missing\+/)
    end

    it "raises a different error for unknown settings on a known member" do
      connections.add(:primary)

      expect { connections.primary[:missing] }
        .to raise_error(ArgumentError, /\+missing\+ is not a setting name/)

      expect { connections.primary.missing }.to raise_error(NoMethodError)
    end
  end

  describe "deleting members" do
    it "removes the member and returns it" do
      add_connections

      removed = connections.delete(:archive)

      expect(removed.dsn).to eql("postgres://archive")
      expect(connections.keys).to eql(%i[primary])
      expect(connections.key?(:archive)).to be(false)
    end
  end

  describe "copying the config" do
    it "detaches copied members from the source" do
      add_connections

      copy = service.config.dup
      copy.connections.primary.pool_size = 50
      copy.connections.primary.tags << "copied"
      copy.connections.delete(:archive)
      copy.connections.add(:analytics)

      expect(connections.primary.pool_size).to be(5)
      expect(connections.primary.tags).to eql(["hot"])
      expect(connections.keys).to eql(%i[primary archive])

      expect(copy.connections.keys).to eql(%i[primary analytics])
    end
  end

  describe "restoring pristine config" do
    it "returns a config without any members" do
      add_connections

      pristine = service.config.pristine

      expect(pristine.connections.keys).to be_empty
      expect(pristine.configured?(:connections)).to be(false)
    end

    it "resets added members via the test interface" do
      service.enable_test_interface

      add_connections

      service.reset_config

      expect(service.config.connections.keys).to be_empty
    end
  end

  describe "finalizing" do
    it "freezes the collection and its members" do
      add_connections

      service.finalize!

      expect(connections).to be_frozen
      expect(connections.primary).to be_frozen
      expect(connections.archive).to be_frozen
      expect(connections.archive.auth).to be_frozen
    end

    it "prevents adding and deleting members" do
      add_connections

      service.finalize!

      expect { connections.add(:analytics) }
        .to raise_error(Dry::Configurable::FrozenConfigError)
      expect { connections.delete(:primary) }
        .to raise_error(Dry::Configurable::FrozenConfigError)
      expect { connections.primary.dsn = "postgres://other" }
        .to raise_error(Dry::Configurable::FrozenConfigError)
    end

    it "exposes members through #to_data" do
      add_connections

      service.finalize!

      data = service.config.to_data

      expect(data.connections[:primary].dsn).to eql("postgres://primary")
      expect(data.connections[:archive].pool_size).to be(2)
      expect(data.connections).to be_frozen
    end
  end

  describe "config as a whole" do
    it "includes members in #to_h" do
      add_connections

      expect(service.config.to_h[:connections]).to eql(
        primary: {
          dsn: "postgres://primary",
          pool_size: 5,
          tags: ["hot"],
          auth: {user: "deploy"}
        },
        archive: {
          dsn: "postgres://archive",
          pool_size: 2,
          tags: [],
          auth: {user: "archivist"}
        }
      )
    end

    it "marks the collection as configured once members are added" do
      expect(service.config.configured?(:connections)).to be(false)

      connections.add(:primary)

      expect(service.config.configured?(:connections)).to be(true)
    end

    it "supports a reader accessor" do
      klass = Class.new do
        extend Dry::Configurable

        setting_collection :connections, reader: true do
          setting :dsn
        end
      end

      klass.config.connections.add(:primary)

      expect(klass.connections.primary).to be(klass.config.connections.primary)
    end

    it "works with instance-level configuration" do
      klass = Class.new do
        include Dry::Configurable

        setting_collection :connections do
          setting :dsn
        end
      end

      object = klass.new
      object.config.connections.add(:primary) { |primary| primary.dsn = "postgres://primary" }

      other = klass.new

      expect(object.config.connections.primary.dsn).to eql("postgres://primary")
      expect(other.config.connections.keys).to be_empty
    end

    it "requires a block of member settings" do
      expect {
        Class.new do
          extend Dry::Configurable

          setting_collection :connections
        end
      }.to raise_error(ArgumentError, /requires a block/)
    end
  end
end
