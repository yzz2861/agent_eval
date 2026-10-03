# frozen_string_literal: true

RSpec.describe Dry::Container::ReadOnlyView do
  subject(:view) do
    container.read_only_view(
      keys: :"shared.time",
      namespaces: "public.items"
    )
  end

  let(:container) do
    Dry::Container.new.tap do |registry|
      registry.register("public.items.one", "one")
      registry.register("public.items.two", "two")
      registry.register("public.items_secret", "prefix boundary")
      registry.register("secret.database", "postgres://admin@database")
      registry.register("secret.signing_key", "signing-key")
      registry.register("secret.lazy") { raise "secret factory was called" }
      registry.register("shared.time", "time")
      registry.register("public.items.nil", nil)
      registry.register("public.factory") { container.resolve("secret.signing_key") }
    end
  end

  it "resolves explicitly granted keys and namespace descendants" do
    expect(view[:"shared.time"]).to eq("time")
    expect(view.resolve("public.items.one")).to eq("one")
    expect(view.resolve("public.items.two")).to eq("two")
    expect(view.resolve("public.items.nil")).to be_nil
  end

  it "applies the same scope through the [] alias" do
    expect(view["public.items.one"]).to eq("one")
    expect { view["secret.database"] }
      .to raise_error(KeyError, %(key not found: "secret.database"))
  end

  it "applies the same scope to key?, keys, each_key, and each" do
    expect(view.key?("public.items.one")).to be(true)
    expect(view.key?("secret.database")).to be(false)
    expect(view.key?("public.items_secret")).to be(false)
    expect(view.key?("missing")).to be(false)

    expect(view.keys).to match_array(
      %w[public.items.nil public.items.one public.items.two shared.time]
    )
    expect(view.each_key.to_a).to match_array(view.keys)
    expect(view.each.to_a).to match_array(
      [
        ["public.items.nil", nil],
        ["public.items.one", "one"],
        ["public.items.two", "two"],
        ["shared.time", "time"]
      ]
    )
  end

  it "does not resolve namespace siblings through a prefix-only match" do
    expect(view.key?("public.items_secret")).to be(false)

    expect { view.resolve("public.items_secret") }
      .to raise_error(KeyError, %(key not found: "public.items_secret"))
  end

  it "reports unauthorized existing keys the same way as missing keys" do
    aggregate_failures do
      expect { view.resolve("secret.database") }
        .to raise_error(KeyError, %(key not found: "secret.database"))
      expect { view.resolve("missing") }
        .to raise_error(KeyError, %(key not found: "missing"))
    end
  end

  it "uses the view as the KeyError receiver" do
    expect { view.resolve("secret.database") }
      .to raise_error(Dry::Container::KeyError) do |error|
      expect(error.key).to eq("secret.database")
      expect(error.receiver).to be(view)
      expect(error.receiver.keys).not_to include("secret.database")
      expect(error.spell_checker).to be_instance_of(DidYouMean::KeyErrorChecker)
    end
  end

  it "limits KeyError spell corrections to visible keys" do
    expect { view.resolve("public.items.ond") }
      .to raise_error(Dry::Container::KeyError) do |error|
      quoted_visible_keys = view.keys.map { |key| %("#{key}") }
      expect(error.spell_checker.corrections - quoted_visible_keys).to be_empty
      expect(error.spell_checker.corrections).not_to include(%("secret.database"))
    end
  end

  it "does not call factories for keys outside the scope" do
    expect { view.resolve("secret.lazy") }.to raise_error(KeyError)
  end

  it "uses the fallback for both unauthorized and missing keys" do
    expect(view.resolve("secret.database") { |key| "fallback for #{key}" })
      .to eq("fallback for secret.database")
    expect(view.resolve(:missing) { |key| "fallback for #{key}" })
      .to eq("fallback for missing")
  end

  it "does not expose mutation methods or the underlying container" do
    expect(view).not_to respond_to(:register)
    expect(view).not_to respond_to(:merge)
    expect(view).not_to respond_to(:decorate)
    expect(view).not_to respond_to(:_container)
    expect(view.instance_variables).to be_empty
  end

  it "is frozen" do
    expect(view).to be_frozen
  end

  it "requires an explicit grant when created" do
    expect { container.read_only_view }.to raise_error(
      ArgumentError,
      "a read-only view requires at least one key or namespace"
    )
  end

  it "does not grant an empty key or namespace" do
    expect { container.read_only_view(keys: "") }.to raise_error(
      ArgumentError,
      "keys and namespaces must not be empty"
    )
  end

  it "does not isolate a permitted factory that captured the original container" do
    factory_view = container.read_only_view(keys: "public.factory")

    expect(factory_view.resolve("public.factory")).to eq("signing-key")
  end

  it "uses the container namespace separator for namespace grants" do
    scoped_container = Class.new {
      include Dry::Container::Mixin
    }.new
    scoped_container.config.namespace_separator = "-"
    scoped_container.register("public-factory", "factory")
    scoped_container.register("publicfactory", "prefix boundary")
    scoped_view = scoped_container.read_only_view(namespaces: "public")

    expect(scoped_view.keys).to eq(%w[public-factory])
    expect(scoped_view.key?("public-factory")).to be(true)
    expect(scoped_view.key?("publicfactory")).to be(false)
  end
end
