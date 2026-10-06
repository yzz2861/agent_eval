# frozen_string_literal: true

RSpec.describe Dry::Configurable, "profiles" do
  subject(:klass) do
    Class.new do
      extend Dry::Configurable

      setting :dsn, default: "sqlite:memory"
      setting :pool, default: 5
      setting :adapter, default: "sqlite"
      setting :tags, default: []

      setting :database do
        setting :url, default: "sqlite:memory"
        setting :options, default: {}
      end
    end
  end

  describe ".profile" do
    it "registers a named profile" do
      klass.profile(:production) { |config| config.pool = 50 }

      expect(klass.profiles.keys).to eql(%i[production])
      expect(klass.profiles[:production].parents).to eql([])
    end

    it "registers a profile with multiple parents" do
      klass.profile(:base) { |config| config.pool = 10 }
      klass.profile(:tuned) { |config| config.adapter = "sqlcipher" }
      klass.profile(:production, inherits: %i[base tuned]) { |config| }

      expect(klass.profiles[:production].parents).to eql(%i[base tuned])
    end

    it "requires a block" do
      expect { klass.profile(:production) }.to raise_error(
        ArgumentError, "a profile requires a configuration block"
      )
    end
  end

  describe ".config_for" do
    it "returns a config with the profile's values applied" do
      klass.profile(:production) do |config|
        config.dsn = "postgres://localhost/app"
        config.pool = 50
      end

      config = klass.config_for(:production)

      expect(config.dsn).to eql("postgres://localhost/app")
      expect(config.pool).to be(50)
    end

    it "returns an independent config object on every call" do
      klass.profile(:production) { |config| config.pool = 50 }

      first = klass.config_for(:production)
      second = klass.config_for(:production)

      expect(first).not_to be(second)
      expect(first).to eql(second)

      first.pool = 1
      expect(second.pool).to be(50)
    end

    it "does not leak profile values into the class-level config" do
      klass.profile(:production) { |config| config.pool = 50 }

      klass.config_for(:production)

      expect(klass.config.pool).to be(5)
    end

    it "does not share mutable defaults between profiles" do
      klass.profile(:production) { |config| config.tags << "prod" }
      klass.profile(:development) { |config| config }

      production = klass.config_for(:production)
      development = klass.config_for(:development)

      expect(production.tags).to eql(["prod"])
      expect(development.tags).to eql([])

      production.tags << "mutated"
      expect(klass.config_for(:development).tags).to eql([])
    end

    it "does not share nested configs between profiles" do
      klass.profile(:production) do |config|
        config.database.url = "postgres://localhost/app"
        config.database.options[:ssl] = true
      end
      klass.profile(:development) { |config| config }

      production = klass.config_for(:production)
      development = klass.config_for(:development)

      expect(production.database.url).to eql("postgres://localhost/app")
      expect(production.database.options).to eql(ssl: true)
      expect(development.database.url).to eql("sqlite:memory")
      expect(development.database.options).to eql({})

      production.database.options[:ssl] = false
      expect(klass.config_for(:production).database.options).to eql(ssl: true)
    end

    it "raises UnknownProfileError for an undefined profile" do
      expect { klass.config_for(:missing) }.to raise_error(
        Dry::Configurable::UnknownProfileError,
        "+missing+ is not a defined profile"
      )
    end
  end

  describe "inheritance" do
    before do
      klass.profile(:base) do |config|
        config.pool = 10
        config.tags << "base"
      end
      klass.profile(:development, inherits: %i[base]) do |config|
        config.dsn = "sqlite:dev"
        config.tags << "development"
      end
      klass.profile(:test, inherits: %i[base]) do |config|
        config.pool = 2
        config.tags << "test"
      end
      klass.profile(:ci, inherits: %i[development test]) do |config|
        config.tags << "ci"
      end
    end

    it "exposes the resolved linearization order" do
      expect(klass.profile_order(:ci)).to eql(%i[ci development test base])
      expect(klass.profile_order(:base)).to eql(%i[base])
    end

    it "lets more specific profiles override their ancestors" do
      config = klass.config_for(:ci)

      expect(config.dsn).to eql("sqlite:dev")
      expect(config.pool).to be(2)
    end

    it "applies a shared diamond ancestor exactly once" do
      config = klass.config_for(:ci)

      expect(config.tags).to eql(%w[base test development ci])
    end

    it "keeps unset, explicit nil and restored defaults distinct" do
      klass.profile(:nil_pool, inherits: %i[base]) do |config|
        config.pool = nil
      end
      klass.profile(:default_pool, inherits: %i[base]) do |config|
        config.restore_default(:pool)
      end

      expect(klass.config_for(:base).pool).to be(10)
      expect(klass.config_for(:base)).to be_configured(:pool)

      nil_config = klass.config_for(:nil_pool)
      expect(nil_config.pool).to be_nil
      expect(nil_config).to be_configured(:pool)

      default_config = klass.config_for(:default_pool)
      expect(default_config.pool).to be(5)
      expect(default_config).not_to be_configured(:pool)
    end

    it "restores mutable defaults as fresh copies" do
      klass.profile(:reset_tags, inherits: %i[base]) do |config|
        config.restore_default(:tags)
      end

      config = klass.config_for(:reset_tags)

      expect(config.tags).to eql([])
      expect(config).not_to be_configured(:tags)

      config.tags << "mutated"
      expect(klass.config_for(:reset_tags).tags).to eql([])
    end
  end

  describe "invalid inheritance chains" do
    it "raises ProfileLinearizationError for contradictory constraints" do
      klass.profile(:x) { |config| config }
      klass.profile(:y) { |config| config }
      klass.profile(:a, inherits: %i[x y]) { |config| config }
      klass.profile(:b, inherits: %i[y x]) { |config| config }
      klass.profile(:c, inherits: %i[a b]) { |config| config }

      expect { klass.config_for(:c) }.to raise_error(
        Dry::Configurable::ProfileLinearizationError,
        /contradictory precedence constraints/
      )
      expect { klass.profile_order(:c) }.to raise_error(
        Dry::Configurable::ProfileLinearizationError
      )
    end

    it "raises CyclicProfileInheritanceError for a cycle" do
      klass.profile(:a, inherits: %i[b]) { |config| config }
      klass.profile(:b, inherits: %i[a]) { |config| config }

      expect { klass.config_for(:a) }.to raise_error(
        Dry::Configurable::CyclicProfileInheritanceError,
        "cyclic profile inheritance: a -> b -> a"
      )
    end
  end

  describe "subclassing" do
    it "inherits profiles and resolves them against inherited settings" do
      klass.profile(:production) { |config| config.pool = 50 }

      subclass = Class.new(klass) do
        setting :extra, default: true
      end
      subclass.profile(:staging, inherits: %i[production]) do |config|
        config.extra = false
      end

      expect(subclass.profile_order(:staging)).to eql(%i[staging production])

      config = subclass.config_for(:staging)
      expect(config.pool).to be(50)
      expect(config.extra).to be(false)

      expect(klass.profiles.keys).to eql(%i[production])
    end
  end

  context "when Dry::Configurable is included" do
    subject(:klass) do
      Class.new do
        include Dry::Configurable

        setting :pool, default: 5
      end
    end

    it "builds configs for profiles" do
      klass.profile(:production) { |config| config.pool = 50 }

      expect(klass.config_for(:production).pool).to be(50)
      expect(klass.new.config.pool).to be(5)
    end
  end
end
