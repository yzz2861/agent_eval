# frozen_string_literal: true

RSpec.describe Dry::Configurable, "named profiles" do
  subject(:klass) do
    Class.new do
      extend Dry::Configurable
    end
  end

  describe "definition and lookup" do
    before do
      klass.setting :db, default: "default-db"
      klass.setting :cache, default: "default-cache"

      klass.profile :development do
        db "sqlite:memory"
      end

      klass.profile :production, inherits: :development do
        db "postgresql://prod"
      end
    end

    it "lists registered profiles in declaration order" do
      expect(klass.profiles.names).to eql(%i[development production])
    end

    it "resolves a profile with its parent's overrides" do
      config = klass.config_for(:development)

      expect(config.db).to eql("sqlite:memory")
      expect(config.cache).to eql("default-cache")
    end

    it "lets the child override the parent" do
      config = klass.config_for(:production)

      expect(config.db).to eql("postgresql://prod")
      expect(config.cache).to eql("default-cache")
    end

    it "exposes the resolved linearization" do
      expect(klass.profile_lineage(:production)).to eql(%i[production development])
    end

    it "supports profile_config as an alias of config_for" do
      expect(klass.profile_config(:production).db).to eql("postgresql://prod")
    end

    it "keeps the class-level config unaffected by profiles" do
      klass.config_for(:production)

      expect(klass.config.db).to eql("default-db")
    end

    it "raises for an unknown profile" do
      expect { klass.config_for(:nope) }
        .to raise_error(Dry::Configurable::ProfileError, /profile :nope is not defined/)
    end

    it "raises when a profile name is registered twice" do
      expect { klass.profile(:development) }
        .to raise_error(Dry::Configurable::ProfileError, /already defined/)
    end

    it "raises for an unknown parent profile" do
      expect {
        klass.profile(:weird, inherits: :ghost)
      }.to raise_error(Dry::Configurable::ProfileError, /unknown profile :ghost/)
    end
  end

  describe "multiple inheritance and C3 linearization (diamond)" do
    #      a=1 (top)
    #     /       \
    #   b          c
    #   a=200      d=5
    #     \       /
    #       d
    #       d=4, a=100
    before do
      klass.setting :a, default: 0
      klass.setting :b, default: 0
      klass.setting :c, default: 0
      klass.setting :d, default: 0

      klass.profile :d do
        d 4
        a 100
      end

      klass.profile :b, inherits: :d do
        b 2
        a 200
      end

      klass.profile :c, inherits: :d do
        d 5
      end

      # b is listed before c, so b (and its overrides) take precedence over c
      klass.profile :top, inherits: %i[b c] do
        a 1
      end
    end

    it "linearizes as [top, b, c, d], visiting the diamond root once" do
      expect(klass.profile_lineage(:top)).to eql(%i[top b c d])
    end

    it "merges overrides in that precedence order" do
      config = klass.config_for(:top)

      # a: top wins (1); b itself contributes 2; c has no own settings besides d;
      # d: c(5) beats the shared ancestor d(4) because c is closer than d
      expect(config.a).to eql(1)
      expect(config.b).to eql(2)
      expect(config.c).to eql(0)
      expect(config.d).to eql(5)
    end

    it "respects parent order: swapping parents reorders the merge" do
      klass.profile :other, inherits: %i[c b]

      expect(klass.profile_lineage(:other)).to eql(%i[other c b d])
      # b overrides d (50) while c leaves it; when c is listed first b still wins
      # because c's own layer has no d, so b's value is not shadowed. Build a
      # direct ordering case: a fresh pair that both set the same key.
      klass.profile :left do
        a 1000
      end
      klass.profile :right do
        a 2000
      end
      klass.profile :left_first, inherits: %i[left right]
      klass.profile :right_first, inherits: %i[right left]

      expect(klass.profile_lineage(:left_first)).to eql(%i[left_first left right])
      expect(klass.profile_lineage(:right_first)).to eql(%i[right_first right left])
      expect(klass.config_for(:left_first).a).to eql(1000)
      expect(klass.config_for(:right_first).a).to eql(2000)
    end
  end

  describe "non-linearizable inheritance" do
    before do
      klass.setting :v
      klass.profile :x
      klass.profile :y
      # x > y
      klass.profile :a, inherits: %i[x y]
      # y > x: directly contradicts the ordering required by a
      klass.profile :b, inherits: %i[y x]
    end

    it "raises a ProfileLinearizationError naming the contradictory constraints" do
      klass.profile :m, inherits: %i[a b]

      expect { klass.profile_lineage(:m) }.to raise_error(
        Dry::Configurable::ProfileLinearizationError,
        /cannot linearize profiles for :m.*\[x > y\].*\[y > x\]/m
      )
    end

    it "raises when a profile references itself as a parent" do
      expect {
        klass.profile :cyc, inherits: :cyc
      }.to raise_error(Dry::Configurable::ProfileError, /unknown profile :cyc/)
    end
  end

  describe "unset, explicit nil and restored defaults" do
    before do
      klass.setting :maybe, default: "hello"

      klass.profile :with_nil do
        maybe nil
      end

      klass.profile :restored, inherits: :with_nil do
        restore_default! :maybe
      end
    end

    it "keeps an untouched setting unset" do
      expect(klass.config_for(:with_nil).configured?(:other)).to be(false)
    end

    it "allows profiles without any overrides" do
      klass.setting :other, default: "x"
      klass.profile :empty

      config = klass.config_for(:empty)

      expect(config.configured?(:other)).to be(false)
      expect(config.other).to eql("x")
    end

    it "treats explicit nil as a real override" do
      expect(klass.config_for(:with_nil).maybe).to be(nil)
    end

    it "restore_default! falls back to the declared default, shadowing nil" do
      config = klass.config_for(:restored)

      expect(config.maybe).to eql("hello")
      expect(config.configured?(:maybe)).to be(true)
    end
  end

  describe "nested settings" do
    before do
      klass.setting :db do
        setting :host, default: "localhost"
        setting :port, default: 5432
      end

      klass.profile :base do
        db do
          host "base.example"
          port 6000
        end
      end

      klass.profile :child, inherits: :base do
        db do
          restore_default! :host
          port 7000
        end
      end
    end

    it "merges nested overrides independently" do
      config = klass.config_for(:child)

      expect(config.db.host).to eql("localhost")
      expect(config.db.port).to eql(7000)
    end

    it "restores a whole nested setting to its declared defaults" do
      klass.profile :fresh, inherits: :child do
        restore_default! :db
      end

      config = klass.config_for(:fresh)

      expect(config.db.host).to eql("localhost")
      expect(config.db.port).to eql(5432)
    end

    it "rejects a scalar value for a nested setting" do
      expect {
        klass.profile :bad do
          db "not-a-config"
        end
      }.to raise_error(Dry::Configurable::ProfileSettingError, /nested setting :db/)
    end

    it "rejects a nested block for a scalar setting" do
      klass.setting :flat, default: 1

      expect {
        klass.profile :bad do
          flat do
            # anything here
          end
        end
      }.to raise_error(Dry::Configurable::ProfileSettingError, /scalar setting :flat/)
    end

    it "rejects unknown setting names" do
      expect {
        klass.profile :bad do
          nope 1
        end
      }.to raise_error(Dry::Configurable::ProfileSettingError, /unknown setting :nope/)
    end

    it "supports the setter-style assignment syntax" do
      klass.profile :setter, inherits: :base do
        db do
          self.host = "setter.example"
        end
      end

      expect(klass.config_for(:setter).db.host).to eql("setter.example")
    end
  end

  describe "independent built configs and mutable defaults" do
    before do
      klass.setting :tags, default: %w[a b]
      klass.setting :nested do
        setting :list, default: [1]
      end

      klass.profile :one do
        tags %w[a b c]
      end
    end

    it "returns independent config objects per call" do
      first = klass.config_for(:one)
      second = klass.config_for(:one)

      expect(first).not_to equal(second)

      first.tags << "mutated"

      expect(second.tags).to eql(%w[a b c])
    end

    it "does not share mutable defaults between profiles" do
      klass.profile :two

      first = klass.config_for(:one)
      plain = klass.config_for(:two)

      first.tags << "x"
      plain.nested.list << 99

      expect(klass.config_for(:one).tags).to eql(%w[a b c])
      expect(klass.config_for(:two).nested.list).to eql([1])
    end

    it "runs setting constructors on profile values" do
      klass.setting :upcased, default: "", constructor: -> v { v.to_s.upcase }
      klass.profile :loud do
        upcased "hello"
      end

      expect(klass.config_for(:loud).upcased).to eql("HELLO")
    end
  end

  describe "inheritance of the configurable class" do
    it "copies profiles into subclasses independently" do
      klass.setting :db, default: "d"
      klass.profile :development do
        db "dev"
      end

      subclass = Class.new(klass)
      subclass.profile :staging, inherits: :development do
        db "staging"
      end

      expect(klass.profiles.names).to eql(%i[development])
      expect(subclass.profiles.names).to eql(%i[development staging])
      expect(subclass.config_for(:staging).db).to eql("staging")
      expect(klass.config_for(:development).db).to eql("dev")
    end
  end

  describe "included Dry::Configurable" do
    subject(:klass) do
      Class.new do
        include Dry::Configurable
      end
    end

    it "builds profile configs at the class level for instances" do
      klass.setting :db, default: "d"
      klass.profile :production do
        db "prod"
      end

      instance = klass.new
      expect(instance.config.db).to eql("d")
      expect(klass.config_for(:production).db).to eql("prod")
    end
  end
end
