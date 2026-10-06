# frozen_string_literal: true

RSpec.describe Dry::Configurable::Config, "#with_secrets" do
  subject(:config) { klass.config }

  let(:klass) do
    Class.new do
      extend Dry::Configurable

      setting :db do
        setting :user, default: "root"
        setting :password, secret: true, default: "vault:db/password"
      end

      setting :token, secret: true

      setting :derived, secret: true, default: "vault:derived",
        constructor: ->(value) { "wrapped:#{value}" }
    end
  end

  # A local secret provider: opens a bounded session, reads values from an
  # in-memory store, and records its resource lifecycle for assertions. It is a
  # plain local object (no network, no real secrets).
  let(:store) do
    {"vault:db/password" => "original-password", "vault:derived" => "derived-value"}
  end

  let(:provider) do
    store = self.store
    sessions = []
    reads = []

    provider = Object.new

    provider.define_singleton_method(:sessions) { sessions }
    provider.define_singleton_method(:reads) { reads }

    provider.define_singleton_method(:open) do
      closed = {value: false}
      session = Object.new
      session.define_singleton_method(:closed?) { closed[:value] }
      session.define_singleton_method(:close) { closed[:value] = true }
      sessions << session
      session
    end

    provider.define_singleton_method(:read) do |_session, reference|
      unless store.key?(reference)
        raise Dry::Configurable::SecretNotFoundError, "missing from local store"
      end

      reads << reference
      store[reference]
    end

    provider.define_singleton_method(:close) { |session| session.close }

    provider
  end

  describe "secret definitions" do
    it "exposes a secret? predicate on the setting" do
      password = klass.settings[:db].children.find { |setting| setting.name == :password }
      user = klass.settings[:db].children.find { |setting| setting.name == :user }

      expect(password).to be_secret
      expect(user).not_to be_secret
    end

    it "does not treat secret references as mutable values" do
      expect(klass.settings[:db].children.find { |s| s.name == :password }).not_to be_mutable
    end

    it "rejects nested secret settings" do
      expect {
        klass.setting(:creds, secret: true) { setting(:x) }
      }.to raise_error(ArgumentError, /secret setting cannot have nested settings/)
    end
  end

  describe "config storage" do
    it "stores only the reference outside of a scope" do
      expect(config.db.password).to eql("vault:db/password")
      expect(config.values).to include(token: nil)
    end

    it "keeps references in to_h after values have been resolved" do
      config.with_secrets(provider) { |secrets| secrets.db.password }

      expect(config.to_h).to eq(
        db: {user: "root", password: "vault:db/password"},
        token: nil,
        derived: "vault:derived"
      )
    end

    it "never contains resolved values in inspect output" do
      config.with_secrets(provider) { |secrets|
        secrets.db.password
        secrets.derived
      }

      expect(config.inspect).not_to include("original-password")
      expect(config.inspect).to include("vault:db/password")
    end

    it "keeps references when copied" do
      config.with_secrets(provider) { |secrets| secrets.db.password }

      copy = config.dup
      copy.with_secrets(provider) { |secrets| secrets.db.password }

      expect(copy.to_h[:db][:password]).to eql("vault:db/password")
      expect(config.to_h[:db][:password]).to eql("vault:db/password")
      expect(copy.inspect).not_to include("original-password")
      expect(config.inspect).not_to include("original-password")
    end

    it "keeps references when finalized" do
      config.with_secrets(provider) { |secrets| secrets.db.password }
      config.finalize!

      expect(config.to_h[:db][:password]).to eql("vault:db/password")
      expect(config.frozen?).to be(true)
    end

    it "keeps references in to_data after finalization" do
      config.with_secrets(provider) { |secrets| secrets.db.password }
      config.finalize!

      expect(config.to_data.db.password).to eql("vault:db/password")
    end

    it "does not apply the constructor when assigning a reference" do
      store["vault:other"] = "other-value"
      config.derived = "vault:other"

      expect(config.derived).to eql("vault:other")

      config.with_secrets(provider) { |secrets|
        expect(secrets.derived).to eql("wrapped:other-value")
      }
    end
  end

  describe "scoped reads" do
    it "resolves secret values through the provider" do
      value = nil
      config.with_secrets(provider) { |secrets|
        expect(secrets).to be_an_instance_of(Dry::Configurable::SecretScope)
        value = secrets.db.password
      }

      expect(value).to eql("original-password")
    end

    it "resolves nested scopes with the shared resource" do
      seen = nil

      config.with_secrets(provider) { |secrets|
        db = secrets.db
        expect(db).to be_an_instance_of(Dry::Configurable::SecretScope)
        seen = [db.user, db.password]
      }

      expect(seen).to eq(["root", "original-password"])
      expect(provider.sessions.size).to be(1)
    end

    it "applies the setting constructor to the resolved value" do
      config.with_secrets(provider) { |secrets|
        expect(secrets.derived).to eql("wrapped:derived-value")
      }
    end

    it "supports bracket access" do
      config.with_secrets(provider) { |secrets|
        expect(secrets[:db][:password]).to eql("original-password")
      }
    end

    it "is read-only" do
      config.with_secrets(provider) { |secrets|
        expect { secrets.token = "x" }.to raise_error(Dry::Configurable::FrozenConfigError)
      }
    end

    it "raises for unknown setting names without touching the provider" do
      config.with_secrets(provider) { |secrets|
        expect { secrets[:nope] }.to raise_error(ArgumentError, /\+nope\+ is not a setting name/)
      }

      expect(provider.reads).to be_empty
    end

    it "reads the current value again on each access (no plaintext caching)" do
      values = []

      config.with_secrets(provider) { |secrets|
        values << secrets.db.password
        store["vault:db/password"] = "rotated-password"
        values << secrets.db.password
      }

      expect(values).to eq(["original-password", "rotated-password"])
      expect(provider.reads).to eq(["vault:db/password", "vault:db/password"])
    end

    it "observes a rotation between two separate scopes" do
      first = config.with_secrets(provider) { |secrets| secrets.db.password }
      store["vault:db/password"] = "rotated-password"
      second = config.with_secrets(provider) { |secrets| secrets.db.password }

      expect(first).to eql("original-password")
      expect(second).to eql("rotated-password")
    end

    it "does not leave resolved values on the config after the scope" do
      config.with_secrets(provider) { |secrets| secrets.db.password }

      config.instance_variables.each do |ivar|
        expect(config.instance_variable_get(ivar).inspect).not_to include("original-password")
      end

      expect(config._values.inspect).not_to include("original-password")
    end

    it "does not store resolved values on the scope" do
      captured = nil

      config.with_secrets(provider) { |secrets|
        secrets.db.password
        secrets.derived
        captured = secrets
      }

      captured.instance_variables.each do |ivar|
        expect(captured.instance_variable_get(ivar).inspect).not_to include("original-password")
        expect(captured.instance_variable_get(ivar).inspect).not_to include("derived-value")
      end
    end

    it "still resolves secrets after the config has been finalized" do
      config.finalize!

      value = config.with_secrets(provider) { |secrets| secrets.db.password }

      expect(value).to eql("original-password")
      expect(provider.sessions).to all(be_closed)
    end
  end

  describe "integration with the class/instance API" do
    it "is available directly on configurable classes" do
      value = klass.with_secrets(provider) { |secrets| secrets.db.password }

      expect(value).to eql("original-password")
    end

    it "is available on instances including Dry::Configurable" do
      app_class = Class.new do
        include Dry::Configurable

        setting :password, secret: true, default: "vault:db/password"
      end

      app = app_class.new
      value = app.with_secrets(provider) { |secrets| secrets.password }

      expect(value).to eql("original-password")
      expect(app.config.password).to eql("vault:db/password")
    end

    it "exposes only the reference through a reader" do
      app_class = Class.new do
        extend Dry::Configurable

        setting :password, secret: true, default: "vault:db/password", reader: true
      end

      expect(app_class.password).to eql("vault:db/password")
    end
  end

  describe "resource lifecycle" do
    it "opens one resource and closes it when the block ends" do
      config.with_secrets(provider) { |secrets| secrets.db.password }

      expect(provider.sessions.size).to be(1)
      expect(provider.sessions).to all(be_closed)
    end

    it "closes the resource when the block raises" do
      expect {
        config.with_secrets(provider) { |secrets|
          secrets.db.password
          raise "boom"
        }
      }.to raise_error(RuntimeError, "boom")

      expect(provider.sessions).to all(be_closed)
    end

    it "closes the resource when a read fails" do
      store.delete("vault:db/password")

      expect {
        config.with_secrets(provider) { |secrets| secrets.db.password }
      }.to raise_error(Dry::Configurable::SecretNotFoundError)

      expect(provider.sessions).to all(be_closed)
    end

    it "cannot be read after the scope has ended" do
      scope = config.with_secrets(provider)

      expect(scope).to be_open
      expect(scope.db.password).to eql("original-password")

      scope.close

      expect(scope).not_to be_open
      expect { scope.db.password }
        .to raise_error(Dry::Configurable::SecretProviderError, /outside of their scope/)
      expect(provider.sessions).to all(be_closed)
    end

    it "cannot be read after a block scope has ended" do
      captured = nil
      config.with_secrets(provider) { |secrets| captured = secrets }

      expect(captured).not_to be_open
      expect { captured.db.password }
        .to raise_error(Dry::Configurable::SecretProviderError, /outside of their scope/)
    end

    it "only closes the outer resource once for nested scopes" do
      closes = 0
      values = store
      counting_provider = Object.new
      counting_provider.define_singleton_method(:open) { :resource }
      counting_provider.define_singleton_method(:read) { |_, ref| values[ref] }
      counting_provider.define_singleton_method(:close) { |_| closes += 1 }

      config.with_secrets(counting_provider) { |secrets| secrets.db.password }

      expect(closes).to be(1)
    end

    it "rejects a provider missing provider methods" do
      expect { config.with_secrets(Object.new) { }
      }.to raise_error(Dry::Configurable::SecretProviderError, /#open.*#read.*#close/m)
      expect(provider.sessions).to be_empty
    end
  end

  describe "errors" do
    it "raises SecretNotFoundError when no reference is configured" do
      expect {
        config.with_secrets(provider) { |secrets| secrets.token }
      }.to raise_error(
        Dry::Configurable::SecretNotFoundError,
        /no secret reference is configured for \+token\+ setting/
      )
    end

    it "raises SecretNotFoundError when the provider has no such secret" do
      store.delete("vault:db/password")

      expect {
        config.with_secrets(provider) { |secrets| secrets.db.password }
      }.to raise_error(Dry::Configurable::SecretNotFoundError)
    end

    it "wraps other provider failures in SecretReadError without leaking the message" do
      failing_provider = Object.new
      failing_provider.define_singleton_method(:open) { :resource }
      failing_provider.define_singleton_method(:read) do |_, _|
        raise "internal-secret-LEAK-token"
      end
      failing_provider.define_singleton_method(:close) { |_| }

      error =
        begin
          config.with_secrets(failing_provider) { |secrets| secrets.db.password }
          nil
        rescue Dry::Configurable::SecretReadError => caught
          caught
        end

      expect(error.message).to include("+password+")
      expect(error.message).to include("RuntimeError")
      expect(error.message).not_to include("LEAK")
      expect(error.cause.message).to include("LEAK")
    end

    it "closes the resource for a wrapped read failure" do
      failing_provider = Object.new
      closed = false
      failing_provider.define_singleton_method(:open) { :resource }
      failing_provider.define_singleton_method(:read) { |_, _| raise "nope" }
      failing_provider.define_singleton_method(:close) { |_| closed = true }

      expect {
        config.with_secrets(failing_provider) { |secrets| secrets.db.password }
      }.to raise_error(Dry::Configurable::SecretReadError)

      expect(closed).to be(true)
    end

    it "distinguishes read failure from a missing secret" do
      not_found = Dry::Configurable::SecretNotFoundError.new
      read_failure = Dry::Configurable::SecretReadError.new

      expect(not_found).to be_a(Dry::Configurable::SecretError)
      expect(read_failure).to be_a(Dry::Configurable::SecretError)
      expect(read_failure).not_to be_a(Dry::Configurable::SecretNotFoundError)
    end
  end

  describe "scope presentation" do
    it "renders a safe inspect while open and closed" do
      open_text = nil

      config.with_secrets(provider) { |secrets|
        open_text = secrets.inspect
        secrets.db.password
      }

      expect(open_text).to eql("#<Dry::Configurable::SecretScope open>")
      closed_scope = nil
      config.with_secrets(provider) { |secrets| closed_scope = secrets }
      expect(closed_scope.inspect).to eql("#<Dry::Configurable::SecretScope closed>")
    end
  end
end
