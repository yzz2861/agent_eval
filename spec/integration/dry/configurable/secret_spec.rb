# frozen_string_literal: true

RSpec.describe "secret settings" do
  let(:provider) { LocalSecretProvider.new(values) }
  let(:values) do
    {
      api_key: "first-value",
      password: "first-value",
      "vault/api-key" => "first-value",
      "database/password" => "first-value"
    }
  end

  let(:klass) do
    Class.new do
      extend Dry::Configurable

      setting :api_key, secret: true
    end
  end

  it "stores only a reference until a secret is explicitly read" do
    expect(klass.config.api_key).to eq(Dry::Configurable::SecretRef.new(:api_key))
    expect(klass.config.to_h).to eq(api_key: Dry::Configurable::SecretRef.new(:api_key))
    expect(klass.config.inspect).not_to include("first-value")
  end

  it "reads the current secret on every scoped access and releases its resource" do
    first_resource = nil

    klass.config.with_secret(:api_key, provider) do |secret|
      expect(secret.value).to eq("first-value")
      first_resource = secret
    end

    expect(first_resource).to be_closed

    values[:api_key] = "rotated-value"

    second_resource = nil

    klass.config.with_secret(:api_key, provider) do |secret|
      expect(secret.value).to eq("rotated-value")
      second_resource = secret
    end

    expect(second_resource).to be_closed
    expect(second_resource).not_to equal(first_resource)
    expect(provider.calls.map(&:key)).to eq(%i[api_key api_key])
    expect(klass.config.to_h).to eq(api_key: Dry::Configurable::SecretRef.new(:api_key))
  end

  it "passes the configured reference to the provider" do
    klass.config.api_key = Dry::Configurable::SecretRef.new("vault/api-key")

    klass.config.with_secret(:api_key, provider) do |secret|
      expect(secret.value).to eq("first-value")
    end

    expect(provider.calls.map(&:key)).to eq(["vault/api-key"])
  end

  it "uses an explicit default as the secret reference key" do
    configurable = Class.new do
      extend Dry::Configurable

      setting :api_key, secret: true, default: "vault/explicit-key"
    end

    expect(configurable.config.api_key).to eq(
      Dry::Configurable::SecretRef.new("vault/explicit-key")
    )
  end

  it "does not expand secrets when copied or finalized" do
    klass.config.with_secret(:api_key, provider) do |secret|
      expect(secret.value).to eq("first-value")
    end

    copied = klass.config.dup
    finalized = copied.finalize!

    expect(copied.api_key).to eq(Dry::Configurable::SecretRef.new(:api_key))
    expect(finalized.to_h).to eq(api_key: Dry::Configurable::SecretRef.new(:api_key))
    expect(finalized.to_data.api_key).to eq(Dry::Configurable::SecretRef.new(:api_key))
    expect([copied.inspect, finalized.inspect].join).not_to include("first-value")
  end

  it "releases the resource when the block raises" do
    resource = nil

    expect {
      klass.config.with_secret(:api_key, provider) do |secret|
        resource = secret
        raise "business failure"
      end
    }.to raise_error(RuntimeError, "business failure")

    expect(resource).to be_closed
    expect(klass.config.api_key).to eq(Dry::Configurable::SecretRef.new(:api_key))
  end

  it "distinguishes a missing secret from a failed read" do
    missing_provider = LocalSecretProvider.new({})
    failing_provider = proc { raise IOError, "provider unavailable" }

    expect {
      klass.config.with_secret(:api_key, missing_provider) { }
    }.to raise_error(
      Dry::Configurable::SecretNotFoundError,
      "secret +api_key+ was not found"
    )

    expect {
      klass.config.with_secret(:api_key, failing_provider) { }
    }.to raise_error(
      Dry::Configurable::SecretReadError,
      "failed to read secret +api_key+"
    ) do |error|
      expect(error.cause).to be_nil
      expect(error.full_message).not_to include("provider unavailable")
    end
  end

  it "supports secrets in nested configuration" do
    nested = Class.new do
      extend Dry::Configurable

      setting :database do
        setting :password, secret: "database/password"
      end
    end

    nested.config.database.with_secret(:password, provider) do |secret|
      expect(secret.value).to eq("first-value")
    end

    expect(nested.config.to_h).to eq(
      database: {password: Dry::Configurable::SecretRef.new("database/password")}
    )
  end

  it "uses a provider injected through the configurable extension" do
    secret_provider = provider

    configurable = Class.new do
      extend Dry::Configurable(secret_provider: secret_provider)

      setting :api_key, secret: true
    end

    configurable.config.with_secret(:api_key) do |secret|
      expect(secret.value).to eq("first-value")
    end
  end

  it "propagates an injected provider through nested configuration" do
    secret_provider = provider

    configurable = Class.new do
      extend Dry::Configurable(secret_provider: secret_provider)

      setting :database do
        setting :password, secret: true
      end
    end

    configurable.config.database.with_secret(:password) do |secret|
      expect(secret.value).to eq("first-value")
    end
  end

  it "supports a provider that manages the block itself" do
    scoped_provider = ScopedSecretProvider.new("database/password" => "scoped-value")
    secret_ref = Dry::Configurable::SecretRef.new("database/password")
    settings = Dry::Configurable::Settings.new([
      Dry::Configurable::Setting.new(:password, default: secret_ref, secret: true)
    ])
    config = Dry::Configurable::Config.new(settings)

    result = config.with_secret(:password, scoped_provider) do |secret|
      expect(scoped_provider.open?).to be(true)
      secret.upcase
    end

    expect(result).to eq("SCOPED-VALUE")
    expect(scoped_provider.open?).to be(false)
    expect(config.to_h).to eq(password: secret_ref)
  end

  it "does not turn block errors from a managed provider into read failures" do
    scoped_provider = ScopedSecretProvider.new(:api_key => "scoped-value")

    expect {
      klass.config.with_secret(:api_key, scoped_provider) do
        raise "business failure"
      end
    }.to raise_error(RuntimeError, "business failure")

    expect(scoped_provider.open?).to be(false)
  end

  it "keeps key errors from the business block intact" do
    expect {
      klass.config.with_secret(:api_key, provider) do
        raise KeyError, "unrelated key"
      end
    }.to raise_error(KeyError, "unrelated key")
  end

  it "rejects a value constructor on a secret setting" do
    expect {
      Class.new do
        extend Dry::Configurable

        setting :api_key, secret: true, constructor: ->(value) { value }
      end
    }.to raise_error(ArgumentError, "secret settings cannot use constructors")
  end

  class LocalSecretProvider
    attr_reader :calls

    def initialize(values)
      @values = values
      @calls = []
    end

    def call(reference)
      @calls << reference

      key = reference.is_a?(Dry::Configurable::SecretRef) ? reference.key : reference
      raise KeyError, key.inspect unless @values.key?(key)

      value = @values.fetch(key)
      raise ArgumentError, "nil is not a secret value" if value.nil?

      LeasedSecret.new(value)
    end

    def release(secret)
      secret.close
    end
  end

  class LeasedSecret
    attr_reader :value

    def initialize(value)
      @value = value
      @closed = false
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  class ScopedSecretProvider
    def initialize(values)
      @values = values
      @open = false
    end

    def call(reference, &block)
      @open = true
      block.call(@values.fetch(reference.key))
    ensure
      @open = false
    end

    def open?
      @open
    end
  end
end
